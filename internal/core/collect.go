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
	if o.Root == "" && !o.System {
		return m, errors.New("root or system collection required")
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
		parent, e := filepath.EvalSymlinks(filepath.Dir(out))
		if e != nil {
			return m, e
		}
		rel, relErr := filepath.Rel(root, filepath.Join(parent, filepath.Base(out)))
		if relErr == nil && (rel == "." || rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))) {
			return m, errors.New("output must be outside source tree")
		}
	}
	var key ed25519.PrivateKey
	if o.SignKey != "" {
		if root != "" {
			kp, ke := filepath.Abs(o.SignKey)
			if ke != nil {
				return m, ke
			}
			kp, ke = filepath.EvalSymlinks(kp)
			if ke != nil {
				return m, ke
			}
			rel, ke := filepath.Rel(root, kp)
			if ke == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
				return m, errors.New("signing key must be outside evidence root")
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
	var total int64
	issue := func(src, reason string) { m.Issues = append(m.Issues, Issue{src, reason}); m.Status = "partial" }
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
		id := fmt.Sprintf("E%06d", len(m.Items)+1)
		obj := "objects/" + id
		w, e := z.Create(obj)
		if e != nil {
			return e
		}
		h := sha256.New()
		budget := min(o.MaxFile, o.MaxTotal-total)
		n, e := io.Copy(io.MultiWriter(w, h), io.LimitReader(contextReader{ctx, r}, budget))
		if e != nil {
			return e
		}
		extra := make([]byte, 1)
		nn, re := r.Read(extra)
		if nn > 0 || re != nil && re != io.EOF {
			issue(src, "source truncated or read error after budget")
		}
		item := Item{ID: id, Source: src, Object: obj, Kind: kind, Size: n, SHA256: hex.EncodeToString(h.Sum(nil)), Collected: time.Now().UTC()}
		if st != nil {
			item.Modified = st.ModTime().UTC()
			item.Mode = st.Mode().String()
			if after, e := os.Stat(src); e != nil || after.Size() != st.Size() || !after.ModTime().Equal(st.ModTime()) {
				item.Changed = true
				issue(src, "source metadata changed during acquisition")
			}
		}
		m.Items = append(m.Items, item)
		total += n
		return nil
	}
	if root != "" {
		e = filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
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
			if len(m.Items) >= o.MaxFiles || total >= o.MaxTotal {
				issue(path, "collection budget reached; remaining tree not visited")
				return filepath.SkipAll
			}
			// SameFile requires stat information, including the volume identity on
			// Windows; directory enumeration metadata is not sufficient there.
			st, e := os.Lstat(path)
			if e != nil {
				issue(path, e.Error())
				return nil
			}
			if !st.Mode().IsRegular() {
				issue(path, "symlink or non-regular file skipped")
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
			return add(path, "file", rf, st)
		})
		if e != nil {
			return m, e
		}
	}
	if o.System && ctx.Err() == nil {
		for _, s := range systemSources() {
			if ctx.Err() != nil {
				issue(s.Name, ctx.Err().Error())
				break
			}
			b, e := snapshot(ctx, s)
			if e != nil {
				issue(s.Name, e.Error())
			}
			if len(b) > 0 {
				if e = add(s.Name, "snapshot", strings.NewReader(string(b)), nil); e != nil {
					return m, e
				}
			}
		}
	}
	if ctx.Err() != nil {
		return m, ctx.Err()
	}
	m.Finished = time.Now().UTC()
	b := JSON(m)
	if len(b) > 16<<20 {
		return m, errors.New("manifest size limit exceeded")
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
