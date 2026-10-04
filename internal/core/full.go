package core

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

const CollectionSchema = "k957-collection/1"

var hostName = os.Hostname
var fullArtifactCandidates = artifactCandidates

// CollectionArtifact is one file bound into a full-mode acquisition.
type CollectionArtifact struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	SHA1   string `json:"sha1,omitempty"`
	MD5    string `json:"md5,omitempty"`
}

// CollectionRecord binds every product of one full-mode run. Its signature
// covers these exact bytes; SHA256SUMS covers the files themselves.
type CollectionRecord struct {
	Adaptive        *AdaptiveSummary     `json:"adaptive_executables,omitempty"`
	Schema          string               `json:"schema"`
	Version         string               `json:"version"`
	ID              string               `json:"id"`
	Case            string               `json:"case"`
	Operator        string               `json:"operator"`
	Scope           string               `json:"scope"`
	Host            string               `json:"host"`
	OS              string               `json:"os"`
	Arch            string               `json:"arch"`
	Started         time.Time            `json:"started"`
	Finished        time.Time            `json:"finished"`
	Status          string               `json:"status"`
	Privileged      bool                 `json:"privileged"`
	Full            bool                 `json:"full"`
	GeneratedKey    bool                 `json:"generated_key"`
	Directory       string               `json:"directory"`
	PublicKey       string               `json:"public_key"`
	Fingerprint     string               `json:"fingerprint"`
	CollectorSHA256 string               `json:"collector_sha256,omitempty"`
	Evidence        string               `json:"evidence,omitempty"`
	Memory          *MemoryRecord        `json:"memory,omitempty"`
	Artifacts       []CollectionArtifact `json:"artifacts"`
	Absent          []string             `json:"absent"`
	Issues          []Issue              `json:"issues"`
	Notes           []string             `json:"notes"`
}

// FullOptions selects the zero-argument collection. Zero limits use the
// full-mode defaults. A nil Profile means the built-in OS profile.
type FullOptions struct {
	OutputDir                            string
	Root, Case, Operator, Scope, SignKey string
	System, Artifacts, Memory            bool
	MemoryTool                           string
	MemoryArgs                           []string
	MemoryLimit, Reserve                 int64
	MaxFile, MaxTotal                    int64
	MaxFiles                             int
	Profile                              []string
	IOMem, Kcore                         string
}

// CollectFull acquires memory, live system state and the artifact profile
// into output/<hostname>/<UTC timestamp>/ and signs the collection record.
func CollectFull(ctx context.Context, o FullOptions) (rec CollectionRecord, err error) {
	if ctx.Err() != nil {
		return rec, ctx.Err()
	}
	if !o.System && !o.Artifacts && !o.Memory && o.Root == "" {
		return rec, errors.New("full collection has nothing selected")
	}
	if o.MaxFile == 0 {
		o.MaxFile = 256 << 20
	}
	if o.MaxTotal == 0 {
		o.MaxTotal = 8 << 30
	}
	if o.MaxFiles == 0 {
		o.MaxFiles = 100000
	}
	base := o.OutputDir
	if base == "" {
		base = "output"
	}
	base, err = filepath.Abs(base)
	if err != nil {
		return rec, err
	}
	host, _ := hostName()
	if host == "" {
		host = "unknown"
	}
	started := time.Now().UTC()
	dir, err := newCollectionDir(base, host, started)
	if err != nil {
		return rec, err
	}
	sealed := false
	defer func() {
		if !sealed {
			os.RemoveAll(dir)
		}
	}()
	pub, priv, generated, err := collectionKey(o.SignKey)
	if err != nil {
		return rec, err
	}
	defer func() {
		for i := range priv {
			priv[i] = 0
		}
	}()
	stamp := filepath.Base(dir)
	if o.Case == "" {
		o.Case = "AUTO-" + sanitizeHost(host) + "-" + stamp
	}
	if o.Operator == "" {
		o.Operator = currentOperator()
	}
	if o.Scope == "" {
		o.Scope = "Full automatic triage of " + host
	}
	fp := sha256.Sum256(pub)
	rec = CollectionRecord{
		Schema: CollectionSchema, Version: Version, ID: ID(), Case: o.Case, Operator: o.Operator, Scope: o.Scope,
		Host: host, OS: runtime.GOOS, Arch: runtime.GOARCH, Started: started, Status: "complete", Privileged: privileged(),
		Full: true, GeneratedKey: generated, Directory: dir, PublicKey: hex.EncodeToString(pub), Fingerprint: hex.EncodeToString(fp[:]),
		Artifacts: []CollectionArtifact{}, Absent: []string{}, Issues: []Issue{},
		Notes: []string{
			"Full mode follows RFC 3227 order of volatility: physical memory, then live system state, then filesystem artifacts.",
			"The Ed25519 signature in collection.sig covers the exact collection.json bytes. SHA256SUMS is a coreutils-compatible hash list and excludes itself and the derived reports/ directory.",
			"A generated signing key proves this record and the evidence package match each other. It is not an external trust anchor; record the fingerprint independently.",
		},
	}
	if !rec.Privileged {
		rec.Notes = append(rec.Notes, "The collector was not privileged. Physical memory and some system artifacts are expected to be missing or partial.")
	}
	ReportProgress(ctx, Progress{Phase: "prepare", Detail: dir, Step: 1, Steps: 1})
	if o.Memory && ctx.Err() == nil {
		mr, e := AcquireMemory(ctx, MemoryOptions{Dir: dir, Case: o.Case, Operator: o.Operator, Tool: o.MemoryTool, ToolArgs: o.MemoryArgs, Limit: o.MemoryLimit, Reserve: o.Reserve, iomem: o.IOMem, kcore: o.Kcore})
		if e != nil {
			rec.Issues = append(rec.Issues, Issue{Source: "memory", Reason: e.Error()})
		} else {
			rec.Memory = &mr
			if mr.Status != "complete" {
				rec.Issues = append(rec.Issues, Issue{Source: "memory", Reason: "partial memory image; see memory.json"})
			}
		}
	}
	if ctx.Err() != nil {
		rec.Issues = append(rec.Issues, Issue{Source: "collection", Reason: ctx.Err().Error()})
	} else if o.System || o.Artifacts || o.Root != "" {
		var adaptive *AdaptiveExecutables
		var acquired Manifest
		opt := Options{Out: filepath.Join(dir, "evidence.k957"), Case: o.Case, Operator: o.Operator, Scope: o.Scope, System: o.System, MaxFile: o.MaxFile, MaxTotal: o.MaxTotal, MaxFiles: o.MaxFiles}
		keyFile := filepath.Join(dir, "signing.key")
		if e := WriteNew(keyFile, []byte(hex.EncodeToString(priv)+"\n")); e != nil {
			return rec, e
		}
		defer os.Remove(keyFile)
		opt.SignKey = keyFile
		var notes []string
		opt.OnSkip = func(path, reason string) {
			if len(notes) < 100 {
				notes = append(notes, path+": "+reason)
			}
		}
		if o.Root != "" {
			opt.Root = o.Root
		}
		if o.Artifacts {
			cands := o.Profile
			if cands == nil {
				cands = fullArtifactCandidates()
				discovered, paths, e := selectAdaptiveExecutables(ctx, dir)
				adaptive = &discovered
				if e != nil {
					rec.Issues = append(rec.Issues, Issue{Source: "adaptive-executables", Reason: e.Error()})
				} else {
					cands = append(cands, paths...)
				}
			}
			present, absent, skipped := filterCandidates(cands, dir)
			rec.Absent = absent
			notes = append(notes, skipped...)
			opt.Paths = present
		}
		if opt.Root != "" || opt.System || len(opt.Paths) > 0 {
			m, e := Collect(ctx, opt)
			acquired = m
			if e != nil {
				if ctx.Err() != nil {
					rec.Issues = append(rec.Issues, Issue{Source: "evidence", Reason: ctx.Err().Error()})
				} else {
					rec.Issues = append(rec.Issues, Issue{Source: "evidence", Reason: e.Error()})
				}
			} else {
				rec.Evidence = "evidence.k957"
				if m.Status != "complete" {
					rec.Issues = append(rec.Issues, Issue{Source: "evidence.k957", Reason: fmt.Sprintf("package status %s with %d issues; see the manifest", m.Status, len(m.Issues))})
				}
			}
		}
		if adaptive != nil {
			summary := bindAdaptiveExecutables(adaptive, acquired)
			rec.Adaptive = &summary
			if e := WriteJSONNew(filepath.Join(dir, summary.Record), adaptive); e != nil {
				return rec, e
			}
			rec.Notes = append(rec.Notes, "Default artifact collection additionally selects currently observed process executables, Linux executable file mappings and Windows loaded modules, including shared libraries and DLLs. Inspect the signed adaptive-executables.json artifact for process/mapping references, acquisition hashes and unavailable paths.")
		}
		if len(notes) > 0 {
			rec.Notes = append(rec.Notes, "Profile entries not collected: "+strings.Join(notes, "; "))
		}
		if e := os.Remove(keyFile); e != nil && !os.IsNotExist(e) {
			return rec, e
		}
	}
	if e := writeSigningPub(dir, pub); e != nil {
		return rec, e
	}
	arts, e := collectionArtifacts(dir, rec.Evidence, rec.Memory)
	if e != nil {
		return rec, e
	}
	rec.Artifacts = arts
	if sum, e := collectorFingerprint(); e != nil {
		rec.Issues = append(rec.Issues, Issue{Source: "collector", Reason: "collector binary hash: " + e.Error()})
	} else {
		rec.CollectorSHA256 = sum
		rec.Notes = append(rec.Notes, "collector_sha256 is the SHA-256 of the k957 executable that wrote this record. Compare it with a copy of the tool obtained independently.")
	}
	if len(rec.Issues) > 0 {
		rec.Status = "partial"
	}
	rec.Finished = time.Now().UTC()
	ReportProgress(ctx, Progress{Phase: "seal", Detail: "collection record", Step: 0, Steps: 1})
	if e = sealCollection(dir, &rec, priv); e != nil {
		return CollectionRecord{}, e
	}
	sealed = true
	ReportProgress(ctx, Progress{Phase: "seal", Detail: dir, Step: 1, Steps: 1})
	if ctx.Err() != nil {
		return rec, ctx.Err()
	}
	return rec, nil
}

func collectionKey(path string) (ed25519.PublicKey, ed25519.PrivateKey, bool, error) {
	if path == "" {
		pub, priv, e := ed25519.GenerateKey(rand.Reader)
		return pub, priv, true, e
	}
	b, e := ReadLimited(path, 4096)
	if e != nil {
		return nil, nil, false, e
	}
	priv, e := decodePrivate(b)
	if e != nil {
		return nil, nil, false, e
	}
	return priv.Public().(ed25519.PublicKey), priv, false, nil
}

func collectorFingerprint() (string, error) {
	path, e := executablePath()
	if e != nil {
		return "", e
	}
	f, e := os.Open(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	h := sha256.New()
	if _, e = io.Copy(h, f); e != nil {
		return "", e
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func writeSigningPub(dir string, pub ed25519.PublicKey) error {
	return WriteNew(filepath.Join(dir, "signing.pub"), []byte(hex.EncodeToString(pub)+"\n"))
}

func collectionArtifacts(dir, evidence string, mem *MemoryRecord) ([]CollectionArtifact, error) {
	names := []struct{ name, kind string }{{"signing.pub", "signing-key"}}
	if _, e := os.Lstat(filepath.Join(dir, "adaptive-executables.json")); e == nil {
		names = append(names, struct{ name, kind string }{"adaptive-executables.json", "adaptive-record"})
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	if evidence != "" {
		names = append(names, struct{ name, kind string }{evidence, "evidence"})
	}
	if mem != nil && mem.Image != "" {
		names = append(names, struct{ name, kind string }{mem.Image, "memory"}, struct{ name, kind string }{"memory.json", "memory-record"})
	}
	var out []CollectionArtifact
	for _, n := range names {
		a, e := hashArtifact(dir, n.name, n.kind)
		if e != nil {
			return nil, e
		}
		out = append(out, a)
	}
	return out, nil
}

func hashArtifact(dir, name, kind string) (CollectionArtifact, error) {
	path := filepath.Join(dir, name)
	sha256sum, sha1sum, md5sum, size, e := hashFile(path)
	if e != nil {
		return CollectionArtifact{}, e
	}
	return CollectionArtifact{Name: name, Kind: kind, Size: size, SHA256: sha256sum, SHA1: sha1sum, MD5: md5sum}, nil
}

func sealCollection(dir string, rec *CollectionRecord, priv ed25519.PrivateKey) error {
	body, err := MarshalJSON(rec)
	if err != nil {
		return err
	}
	if e := WriteNew(filepath.Join(dir, "collection.json"), body); e != nil {
		return e
	}
	if e := WriteNew(filepath.Join(dir, "collection.sig"), ed25519.Sign(priv, body)); e != nil {
		return e
	}
	return writeSHA256SUMS(dir)
}

func writeSHA256SUMS(dir string) error {
	files, e := collectionFiles(dir)
	if e != nil {
		return e
	}
	var b strings.Builder
	for _, rel := range files {
		sum, e := fileSHA256(filepath.Join(dir, filepath.FromSlash(rel)))
		if e != nil {
			return e
		}
		fmt.Fprintf(&b, "%s  %s\n", sum, rel)
	}
	return WriteNew(filepath.Join(dir, "SHA256SUMS"), []byte(b.String()))
}

// collectionFiles lists slash-separated paths covered by SHA256SUMS.
// The sums file and the derived reports directory are excluded.
func collectionFiles(dir string) ([]string, error) {
	var files []string
	e := filepath.WalkDir(dir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, e := filepath.Rel(dir, path)
		if e != nil {
			return e
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		if d.IsDir() {
			if rel == "reports" {
				return filepath.SkipDir
			}
			return nil
		}
		if rel == "SHA256SUMS" {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink in collection: %s", rel)
		}
		files = append(files, rel)
		return nil
	})
	sort.Strings(files)
	return files, e
}

func newCollectionDir(base, host string, when time.Time) (string, error) {
	parent := filepath.Join(base, sanitizeHost(host))
	if e := os.MkdirAll(parent, 0700); e != nil {
		return "", e
	}
	stamp := when.UTC().Format("20060102T150405Z")
	for i := 0; i < 100; i++ {
		name := stamp
		if i > 0 {
			name = fmt.Sprintf("%s-%d", stamp, i+1)
		}
		dir := filepath.Join(parent, name)
		if e := os.Mkdir(dir, 0700); e == nil {
			return dir, nil
		} else if !os.IsExist(e) {
			return "", e
		}
	}
	return "", errors.New("collection directory collision")
}

func sanitizeHost(host string) string {
	if host == "" {
		return "unknown"
	}
	var b strings.Builder
	for _, r := range host {
		switch {
		case r <= 127 && (r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-'):
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	s := strings.Trim(b.String(), ".")
	if s == "" || s == ".." {
		return "unknown"
	}
	if len(s) > 64 {
		s = s[:64]
	}
	return s
}

var currentUser = user.Current

func currentOperator() string {
	if u, e := currentUser(); e == nil && u.Username != "" {
		return u.Username
	}
	for _, key := range []string{"USER", "USERNAME"} {
		if v := os.Getenv(key); v != "" {
			return v
		}
	}
	return "unknown"
}

func filterCandidates(cands []string, dest string) (present, absent, notes []string) {
	seen := map[string]bool{}
	dest, _ = filepath.Abs(dest)
	for _, c := range cands {
		abs, e := filepath.Abs(c)
		if e != nil {
			absent = append(absent, c)
			continue
		}
		resolved, e := filepath.EvalSymlinks(abs)
		if e != nil {
			if os.IsNotExist(e) {
				absent = append(absent, abs)
			} else {
				notes = append(notes, abs+": "+e.Error())
			}
			continue
		}
		if seen[resolved] {
			continue
		}
		seen[resolved] = true
		if inside(resolved, dest) {
			notes = append(notes, resolved+": contains the output directory and was not collected")
			continue
		}
		st, e := os.Stat(resolved)
		if e != nil {
			absent = append(absent, resolved)
			continue
		}
		if !st.IsDir() && !st.Mode().IsRegular() {
			notes = append(notes, resolved+": not a file or directory")
			continue
		}
		present = append(present, resolved)
	}
	sort.Strings(present)
	sort.Strings(absent)
	return present, absent, notes
}
