package core

import (
	"archive/zip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func Collect(ctx context.Context, o Options) (m Manifest, err error) {
	if o.EncryptionKey != "" {
		return m, errors.New("encryption during acquisition requires --work")
	}
	if o.Case == "" || o.Operator == "" || o.Scope == "" || o.Out == "" {
		return m, errors.New("case, operator, scope and out are required")
	}
	if o.Root == "" && !o.System && len(o.Paths) == 0 {
		return m, errors.New("root, paths or system collection required")
	}
	if o.MaxFile <= 0 || o.MaxTotal <= 0 || o.MaxFiles <= 0 || o.MaxFile > 64<<30 || o.MaxTotal > 1<<40 || o.MaxFiles > 100000 {
		return m, errors.New("limits must be positive")
	}
	if ctx.Err() != nil {
		return m, ctx.Err()
	}
	out, e := filepath.Abs(o.Out)
	if e != nil {
		return m, e
	}
	root := ""
	if o.Root != "" {
		root, e = filepath.Abs(o.Root)
		if e != nil {
			return m, e
		}
		root, e = filepath.EvalSymlinks(root)
		if e != nil {
			return m, e
		}
		st, e := os.Stat(root)
		if e != nil || !st.IsDir() {
			return m, errors.New("root must be directory")
		}
	}
	sources := []string{}
	if root != "" {
		sources = append(sources, root)
	}
	for _, p := range o.Paths {
		abs, e := filepath.Abs(p)
		if e != nil {
			return m, e
		}
		if abs, e = filepath.EvalSymlinks(abs); e != nil {
			return m, e
		}
		st, e := os.Stat(abs)
		if e != nil {
			return m, e
		}
		if !st.IsDir() && !st.Mode().IsRegular() {
			return m, fmt.Errorf("path must be a directory or regular file: %s", p)
		}
		sources = append(sources, abs)
	}
	if len(sources) > 0 {
		dest, e := canonicalDestination(out)
		if e != nil {
			return m, e
		}
		for _, s := range sources {
			if inside(s, dest) {
				return m, errors.New("output must be outside source tree")
			}
		}
	}
	var key ed25519.PrivateKey
	if o.SignKey != "" {
		if len(sources) > 0 {
			kp, ke := filepath.Abs(o.SignKey)
			if ke != nil {
				return m, ke
			}
			kp, ke = filepath.EvalSymlinks(kp)
			if ke != nil {
				return m, ke
			}
			for _, s := range sources {
				if inside(s, kp) {
					return m, errors.New("signing key must be outside evidence root")
				}
			}
		}
		b, e := ReadLimited(o.SignKey, 4096)
		if e != nil {
			return m, e
		}
		key, e = decodePrivate(b)
		if e != nil {
			return m, e
		}
	}
	f, e := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return m, e
	}
	success := false
	defer func() {
		f.Close()
		if !success {
			os.Remove(out)
		}
	}()
	z := zip.NewWriter(f)
	host, _ := os.Hostname()
	m = Manifest{Schema: Schema, Version: Version, ID: ID(), Case: o.Case, Operator: o.Operator, Scope: o.Scope, Host: host, OS: runtime.GOOS, Arch: runtime.GOARCH, Started: time.Now().UTC(), Status: "complete", Items: []Item{}, Issues: []Issue{}}
	m.Acquisition = o.Acquisition
	if m.Acquisition == nil {
		m.Acquisition = liveFileGuarantees()
	}
	var total int64
	var metadataAttributes int64
	issue := func(src, reason string) { m.Issues = append(m.Issues, Issue{src, reason}); m.Status = "partial" }
	recordSnapshotNote := func(text string) {
		if m.Acquisition == nil {
			m.Acquisition = liveFileGuarantees()
		}
		acq := *m.Acquisition
		acq.Notes = append(append([]string{}, m.Acquisition.Notes...), text)
		m.Acquisition = &acq
	}
	add := func(src, kind string, r io.Reader, st os.FileInfo) error {
		if len(m.Items) >= o.MaxFiles || total >= o.MaxTotal {
			issue(src, "collection budget reached")
			return nil
		}
		if st != nil && st.Size() > o.MaxFile {
			issue(src, "file size exceeds limit")
			return nil
		}
		if st != nil && st.Size() > o.MaxTotal-total {
			issue(src, "total byte limit")
			return nil
		}
		var metadata *FileMetadata
		if file, ok := r.(*os.File); ok && st != nil {
			metadata = sampledFileMetadata(file, st, "")
			boundMetadataAttributes(metadata, &metadataAttributes)
		}
		id := fmt.Sprintf("E%06d", len(m.Items)+1)
		obj := "objects/" + id
		w, e := z.Create(obj)
		if e != nil {
			return e
		}
		h := sha256.New()
		budget := min(o.MaxFile, o.MaxTotal-total)
		source := &readErrorReader{r: r}
		n, e := io.Copy(io.MultiWriter(w, h), io.LimitReader(contextReader{ctx, source}, budget))
		switch {
		case e != nil && source.err == nil:
			return e
		case source.err != nil:
			issue(src, fmt.Sprintf("read error after %d bytes; object holds the readable prefix: %v", n, source.err))
		default:
			extra := make([]byte, 1)
			nn, re := r.Read(extra)
			if nn > 0 || re != nil && re != io.EOF {
				issue(src, "source truncated or read error after budget")
			}
		}
		item := Item{ID: id, Source: src, Object: obj, Kind: kind, Size: n, SHA256: hex.EncodeToString(h.Sum(nil)), Collected: time.Now().UTC(), Metadata: metadata}
		if st != nil {
			item.Modified = st.ModTime().UTC()
			item.Mode = st.Mode().String()
			if after, e := os.Stat(src); e != nil || !os.SameFile(st, after) || after.Size() != st.Size() || !after.ModTime().Equal(st.ModTime()) {
				item.Changed = true
				issue(src, "source metadata changed during acquisition")
			}
		}
		m.Items = append(m.Items, item)
		total += n
		return nil
	}
	// Live commands are more volatile than the files below them. Collect them
	// first so a later file-size budget cannot drop the snapshots.
	if o.System && ctx.Err() == nil {
		sources := systemSources()
		for i, s := range sources {
			if ctx.Err() != nil {
				issue(s.Name, ctx.Err().Error())
				break
			}
			ReportProgress(ctx, Progress{Phase: "live-system", Detail: s.Name, Step: i + 1, Steps: len(sources)})
			b, note, e := snapshot(ctx, s)
			if e != nil {
				issue(s.Name, e.Error())
			}
			if len(b) > 0 {
				before := len(m.Items)
				if e = add(s.Name, "snapshot", strings.NewReader(string(b)), nil); e != nil {
					return m, e
				}
				if note != "" && len(m.Items) > before {
					recordSnapshotNote(s.Name + ": " + note)
				}
			}
		}
	}
	budgetReached := false
	visited := map[string]bool{}
	collectFile := func(path string, quiet bool) error {
		if visited[path] {
			return nil
		}
		visited[path] = true
		if len(m.Items) >= o.MaxFiles || total >= o.MaxTotal {
			issue(path, "collection budget reached; remaining tree not visited")
			budgetReached = true
			return nil
		}
		// SameFile requires stat information, including the volume identity on
		// Windows; directory enumeration metadata is not sufficient there.
		st, e := os.Lstat(path)
		if e != nil {
			issue(path, e.Error())
			return nil
		}
		if !st.Mode().IsRegular() {
			if quiet && o.OnSkip != nil {
				o.OnSkip(path, "symlink or non-regular file skipped")
			} else {
				issue(path, "symlink or non-regular file skipped")
			}
			return nil
		}
		rf, e := os.Open(path)
		if e != nil {
			issue(path, e.Error())
			return nil
		}
		defer rf.Close()
		opened, e := rf.Stat()
		if e != nil {
			return e
		}
		if !os.SameFile(st, opened) {
			issue(path, "source replaced before open")
			return nil
		}
		if err := add(path, "file", rf, st); err != nil {
			return err
		}
		ReportProgress(ctx, Progress{Phase: "files", Detail: path, Step: len(m.Items), Bytes: total})
		return nil
	}
	for i, source := range sources {
		quiet := root == "" || i > 0
		e = filepath.WalkDir(source, func(path string, d os.DirEntry, walkErr error) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if walkErr != nil {
				issue(path, walkErr.Error())
				return nil
			}
			if d.IsDir() {
				return nil
			}
			if e := collectFile(path, quiet); e != nil || budgetReached {
				if e == nil {
					e = filepath.SkipAll
				}
				return e
			}
			return nil
		})
		if e != nil {
			return m, e
		}
		if budgetReached {
			break
		}
	}
	if ctx.Err() != nil {
		return m, ctx.Err()
	}
	ReportProgress(ctx, Progress{Phase: "package", Detail: out, Step: len(m.Items), Bytes: total, Steps: len(m.Items)})
	m.Finished = time.Now().UTC()
	b, e := marshalManifest(m)
	if e != nil {
		return m, fmt.Errorf("manifest cannot be encoded: %w", e)
	}
	w, e := z.Create("manifest.json")
	if e != nil {
		return m, e
	}
	if _, e = w.Write(b); e != nil {
		return m, e
	}
	if key != nil {
		sig := ed25519.Sign(key, b)
		w, e = z.Create("manifest.sig")
		if e != nil {
			return m, e
		}
		if _, e = w.Write(sig); e != nil {
			return m, e
		}
	}
	if e = z.Close(); e != nil {
		return m, e
	}
	if e = f.Sync(); e != nil {
		return m, e
	}
	if e = f.Close(); e != nil {
		return m, e
	}
	success = true
	return m, nil
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if e := r.ctx.Err(); e != nil {
		return 0, e
	}
	return r.r.Read(p)
}

// readErrorReader separates source read failures from destination write and
// cancellation failures, so a damaged source keeps its acquired prefix.
type readErrorReader struct {
	r   io.Reader
	err error
}

func (r *readErrorReader) Read(p []byte) (int, error) {
	n, e := r.r.Read(p)
	if e != nil && e != io.EOF {
		r.err = e
	}
	return n, e
}
