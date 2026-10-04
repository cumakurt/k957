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

const resumeChunk = 8 << 20
const workSchema = "k957-work/1"

type WorkFile struct {
	Item         Item  `json:"item"`
	ExpectedSize int64 `json:"expected_size"`
	Complete     bool  `json:"complete"`
}
type WorkState struct {
	metadataAttributes  int64
	metadataInitialized bool
	Encryption          string     `json:"encryption,omitempty"`
	Schema              string     `json:"schema"`
	Root                string     `json:"root"`
	MaxFile             int64      `json:"max_file"`
	MaxTotal            int64      `json:"max_total"`
	MaxFiles            int        `json:"max_files"`
	Manifest            Manifest   `json:"manifest"`
	Files               []WorkFile `json:"files"`
}

// CollectResumable preserves acquired chunks in a trusted staging directory.
// It intentionally excludes live commands: replaying them is a new acquisition.
func CollectResumable(ctx context.Context, o Options, work string, resume bool) (Manifest, error) {
	return collectResumable(ctx, o, work, resume, nil)
}
func collectResumable(ctx context.Context, o Options, work string, resume bool, afterCommit func()) (m Manifest, err error) {
	if o.Root == "" || o.Case == "" || o.Operator == "" || o.Scope == "" || o.Out == "" || work == "" || o.System || len(o.Paths) > 0 {
		return m, errors.New("resumable collection requires root, work, out, case, operator, scope; system and additional paths are not supported")
	}
	if o.MaxFile <= 0 || o.MaxFile > 64<<30 || o.MaxTotal <= 0 || o.MaxTotal > 1<<40 || o.MaxFiles <= 0 || o.MaxFiles > 100000 {
		return m, errors.New("invalid limits")
	}
	root, e := filepath.Abs(o.Root)
	if e != nil {
		return m, e
	}
	root, e = filepath.EvalSymlinks(root)
	if e != nil {
		return m, e
	}
	stRoot, se := os.Stat(root)
	if se != nil {
		return m, se
	}
	if !stRoot.IsDir() {
		return m, errors.New("root must be directory")
	}
	work, e = canonicalDestination(work)
	if e != nil {
		return m, e
	}
	out, e := canonicalDestination(o.Out)
	if e != nil {
		return m, e
	}
	if inside(root, work) || inside(root, out) || inside(work, out) || inside(work, root) {
		return m, errors.New("source, work and output must be separated; output cannot be inside work")
	}
	if _, e = os.Lstat(out); e == nil {
		return m, errors.New("output already exists")
	} else if !os.IsNotExist(e) {
		return m, e
	}
	var c *workCrypto
	if o.EncryptionKey != "" {
		kp, ke := filepath.Abs(o.EncryptionKey)
		if ke != nil {
			return m, ke
		}
		kp, ke = filepath.EvalSymlinks(kp)
		if ke != nil {
			return m, ke
		}
		if inside(root, kp) || inside(work, kp) {
			return m, errors.New("encryption key must be outside source and work")
		}
		c, e = newWorkCrypto(kp)
		if e != nil {
			return m, e
		}
	}
	var key ed25519.PrivateKey
	if o.SignKey != "" {
		kp, e := filepath.Abs(o.SignKey)
		if e != nil {
			return m, e
		}
		kp, e = filepath.EvalSymlinks(kp)
		if e != nil {
			return m, e
		}
		if inside(root, kp) || inside(work, kp) {
			return m, errors.New("signing key must be outside source and work")
		}
		b, e := ReadLimited(kp, 4096)
		if e != nil {
			return m, e
		}
		key, e = decodePrivate(b)
		if e != nil {
			return m, e
		}
	}
	if ctx.Err() != nil {
		return m, ctx.Err()
	}
	var state WorkState
	if !resume {
		if e = os.Mkdir(work, 0700); e != nil {
			return m, e
		}
		if e = os.Mkdir(filepath.Join(work, "chunks"), 0700); e != nil {
			return m, e
		}
	} else {
		if e = regularDirectory(work); e != nil {
			return m, e
		}
		if e = regularDirectory(filepath.Join(work, "chunks")); e != nil {
			return m, e
		}
	}
	lock := filepath.Join(work, "active.lock")
	if e = WriteNew(lock, []byte(fmt.Sprintf("pid=%d\nstarted=%s\n", os.Getpid(), time.Now().UTC().Format(time.RFC3339Nano)))); e != nil {
		return m, fmt.Errorf("work directory locked; confirm no process is using it before removing stale active.lock: %w", e)
	}
	defer os.Remove(lock)
	if resume {
		if e = readWork(work, &state, c); e != nil {
			return m, e
		}
		if state.Root != root || state.Manifest.Case != o.Case || state.Manifest.Operator != o.Operator || state.Manifest.Scope != o.Scope || state.MaxFile != o.MaxFile || state.MaxTotal != o.MaxTotal || state.MaxFiles != o.MaxFiles {
			return m, errors.New("resume options do not match original acquisition")
		}
	} else {
		state, e = planWork(ctx, root, o)
		if c != nil {
			state.Encryption = stageMode
		}
		if e != nil {
			return m, e
		}
		if e = saveWork(work, state, c); e != nil {
			return m, e
		}
	}
	// A prior process may have died before closing its epoch.
	for i := range state.Manifest.Epochs {
		if state.Manifest.Epochs[i].Outcome == "running" {
			state.Manifest.Epochs[i].Outcome = "interrupted; end time unknown"
		}
	}
	if len(state.Manifest.Epochs) >= 1000 {
		return m, errors.New("epoch limit reached")
	}
	epochHost, _ := os.Hostname()
	epoch := Epoch{Host: epochHost, OS: runtime.GOOS, Arch: runtime.GOARCH, ID: ID(), Started: time.Now().UTC(), Outcome: "running"}
	state.Manifest.Epochs = append(state.Manifest.Epochs, epoch)
	if e = saveWork(work, state, c); e != nil {
		return m, e
	}
	defer func() {
		i := len(state.Manifest.Epochs) - 1
		if err != nil || state.Manifest.Epochs[i].Outcome != "completed" {
			state.Manifest.Epochs[i].Finished = time.Now().UTC()
		}
		if err != nil {
			state.Manifest.Epochs[i].Outcome = "failed: " + err.Error()
		} else {
			state.Manifest.Epochs[i].Outcome = "completed"
		}
		if e := saveWork(work, state, c); e != nil && err == nil {
			err = fmt.Errorf("checkpoint finalization: %w", e)
		}
	}()
	for i := range state.Files {
		if e = ctx.Err(); e != nil {
			return m, e
		}
		ReportProgress(ctx, Progress{Phase: "files", Detail: state.Files[i].Item.Source, Step: i + 1, Steps: len(state.Files)})
		wf := &state.Files[i]
		if e = validateParts(ctx, work, wf.Item, c); e != nil {
			return m, e
		}
		if wf.Complete {
			continue
		}
		if e = acquireFile(ctx, work, &state, i, epoch.ID, afterCommit, c); e != nil {
			return m, e
		}
	}
	state.Manifest.Items = make([]Item, 0, len(state.Files))
	for _, wf := range state.Files {
		state.Manifest.Items = append(state.Manifest.Items, wf.Item)
	}
	state.Manifest.Finished = time.Now().UTC()
	last := len(state.Manifest.Epochs) - 1
	state.Manifest.Epochs[last].Finished = state.Manifest.Finished
	state.Manifest.Epochs[last].Outcome = "completed"
	m = state.Manifest
	ReportProgress(ctx, Progress{Phase: "package", Detail: out, Step: len(m.Items), Steps: len(m.Items)})
	if e = exportWork(ctx, work, out, m, key, c); e != nil {
		return m, e
	}
	return m, nil
}
func canonicalDestination(path string) (string, error) {
	abs, e := filepath.Abs(path)
	if e != nil {
		return "", e
	}
	parent, e := filepath.EvalSymlinks(filepath.Dir(abs))
	if e != nil {
		return "", e
	}
	return filepath.Join(parent, filepath.Base(abs)), nil
}
func inside(root, path string) bool {
	rel, e := filepath.Rel(root, path)
	return e == nil && (rel == "." || rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)))
}
func regularDirectory(path string) error {
	st, e := os.Lstat(path)
	if e != nil {
		return e
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return errors.New("work path must be a real directory")
	}
	return nil
}
func planWork(ctx context.Context, root string, o Options) (s WorkState, err error) {
	host, _ := os.Hostname()
	s = WorkState{Schema: workSchema, Root: root, MaxFile: o.MaxFile, MaxTotal: o.MaxTotal, MaxFiles: o.MaxFiles, Manifest: Manifest{Schema: ResumeSchema, Version: Version, ID: ID(), Case: o.Case, Operator: o.Operator, Scope: o.Scope, Host: host, OS: runtime.GOOS, Arch: runtime.GOARCH, Started: time.Now().UTC(), Status: "complete", InventoryFrozen: true, Issues: []Issue{}, Items: []Item{}}, Files: []WorkFile{}}
	s.Manifest.Acquisition = liveFileGuarantees()
	s.Manifest.Acquisition.Method = "logical-resumable-files"
	s.Manifest.Acquisition.Notes = append(s.Manifest.Acquisition.Notes, "Parts can originate from multiple invocation epochs. Metadata is sampled when that file is first opened for acquisition; its epoch is recorded separately from part epochs.")
	var total int64
	issue := func(path, msg string) {
		s.Manifest.Status = "partial"
		s.Manifest.Issues = append(s.Manifest.Issues, Issue{path, msg})
	}
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if e := ctx.Err(); e != nil {
			return e
		}
		if walkErr != nil {
			issue(path, walkErr.Error())
			return nil
		}
		if d.IsDir() {
			return nil
		}
		st, e := d.Info()
		if e != nil {
			issue(path, e.Error())
			return nil
		}
		if !st.Mode().IsRegular() {
			issue(path, "symlink/non-regular source skipped")
			return nil
		}
		if len(s.Files) >= o.MaxFiles {
			issue(path, "file limit reached; rest of inventory not visited")
			return filepath.SkipAll
		}
		if st.Size() > o.MaxFile || st.Size() > o.MaxTotal-total {
			issue(path, "size budget exceeded")
			return nil
		}
		id := fmt.Sprintf("E%06d", len(s.Files)+1)
		s.Files = append(s.Files, WorkFile{ExpectedSize: st.Size(), Item: Item{ID: id, Source: path, Object: "objects/" + id, Kind: "file", Modified: st.ModTime().UTC(), Mode: st.Mode().String()}})
		total += st.Size()
		ReportProgress(ctx, Progress{Phase: "inventory", Detail: path, Step: len(s.Files), Bytes: total})
		return nil
	})
	return
}
func saveWork(work string, s WorkState, cs ...*workCrypto) error {
	c := chooseCrypto(cs)
	b, e := MarshalJSON(s)
	if e != nil {
		return fmt.Errorf("checkpoint cannot be encoded: %w", e)
	}
	if len(b) > checkpointLimit {
		return errors.New("checkpoint exceeds 256 MiB limit")
	}
	b, e = c.seal("state", b)
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(work, ".checkpoint-*")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if _, e = f.Write(b); e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	if e = replaceCheckpoint(name, filepath.Join(work, c.stateName())); e != nil {
		return e
	}
	syncDirectory(work)
	return nil
}

// Directory sync improves crash durability where supported. Removable media
// and non-Unix filesystems may not implement it; no hardware durability promise.
func syncDirectory(path string) {
	f, e := os.Open(path)
	if e == nil {
		_ = f.Sync()
		_ = f.Close()
	}
}
func readWork(work string, s *WorkState, cs ...*workCrypto) error {
	c := chooseCrypto(cs)
	other := "state.enc"
	if c != nil {
		other = "state.json"
	}
	if _, e := os.Lstat(filepath.Join(work, other)); e == nil {
		return errors.New("staging encryption mode mismatch; use original key/mode, no in-place conversion")
	} else if !os.IsNotExist(e) {
		return e
	}
	path := filepath.Join(work, c.stateName())
	st, e := os.Lstat(path)
	if e != nil {
		return e
	}
	if !st.Mode().IsRegular() {
		return errors.New("checkpoint must be regular file")
	}
	b, e := ReadLimited(path, checkpointLimit+stageOverhead)
	if e != nil {
		return e
	}
	b, e = c.open("state", b)
	if e != nil {
		return e
	}
	if len(b) > checkpointLimit {
		return errors.New("checkpoint exceeds size limit")
	}
	if e = custodyJSON(b, s); e != nil {
		return e
	}
	if (c == nil && s.Encryption != "") || (c != nil && s.Encryption != stageMode) {
		return errors.New("invalid checkpoint encryption metadata")
	}
	if s.Schema != workSchema || s.Manifest.Version != Version || s.Manifest.Schema != ResumeSchema || !s.Manifest.InventoryFrozen || len(s.Files) > 100000 || len(s.Manifest.Epochs) > 1000 || len(s.Files) > s.MaxFiles {
		return errors.New("unsupported checkpoint")
	}
	if e := validateEpochs(s.Manifest.Epochs); e != nil {
		return e
	}
	var total int64
	paths := map[string]bool{}
	for i, wf := range s.Files {
		it := wf.Item
		id := fmt.Sprintf("E%06d", i+1)
		if it.ID != id || it.Object != "objects/"+id || it.Kind != "file" || !filepath.IsAbs(it.Source) || !inside(s.Root, it.Source) || filepath.Clean(it.Source) != it.Source || paths[it.Source] {
			return errors.New("invalid checkpoint source")
		}
		paths[it.Source] = true
		if wf.ExpectedSize < 0 || wf.ExpectedSize > s.MaxFile || wf.ExpectedSize > 64<<30 {
			return errors.New("invalid checkpoint size")
		}
		total += wf.ExpectedSize
		if total > s.MaxTotal || total > 1<<40 {
			return errors.New("checkpoint budget exceeded")
		}
		if e := validatePartMetadata(it, s.Manifest.Epochs, wf.ExpectedSize, wf.Complete); e != nil {
			return e
		}
	}
	return nil
}
func validatePartMetadata(it Item, epochs []Epoch, expected int64, complete bool) error {
	ep := map[string]bool{}
	for _, v := range epochs {
		if v.ID == "" || ep[v.ID] {
			return errors.New("duplicate/empty epoch")
		}
		ep[v.ID] = true
	}
	var offset int64
	for _, p := range it.Parts {
		if p.Offset != offset || p.Size <= 0 || p.Size > resumeChunk || !validHash(p.SHA256) || !ep[p.Epoch] || p.Acquired.IsZero() {
			return errors.New("invalid part metadata")
		}
		offset += p.Size
		if offset > expected {
			return errors.New("part exceeds source size")
		}
	}
	if complete && (offset != expected || it.Size != expected || !validHash(it.SHA256) || it.Collected.IsZero()) {
		return errors.New("invalid complete file metadata")
	}
	return nil
}
func validHash(s string) bool { return len(s) == 64 && strings.Trim(s, "0123456789abcdef") == "" }
func chunkData(work string, p Part, cs ...*workCrypto) ([]byte, error) {
	c := chooseCrypto(cs)
	path := filepath.Join(work, "chunks", c.name(p.SHA256))
	st, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !st.Mode().IsRegular() || st.Size() != p.Size+func() int64 {
		if c != nil {
			return stageOverhead
		}
		return 0
	}() {
		return nil, errors.New("chunk type/size mismatch")
	}
	b, e := ReadLimited(path, resumeChunk+stageOverhead)
	if e != nil {
		return nil, e
	}
	b, e = c.open("chunk:"+p.SHA256, b)
	if e != nil {
		return nil, e
	}
	sum := sha256.Sum256(b)
	if hex.EncodeToString(sum[:]) != p.SHA256 {
		return nil, errors.New("checkpoint chunk hash mismatch")
	}
	return b, nil
}
func validateParts(ctx context.Context, work string, it Item, cs ...*workCrypto) error {
	c := chooseCrypto(cs)
	h := sha256.New()
	var size int64
	for _, p := range it.Parts {
		if e := ctx.Err(); e != nil {
			return e
		}
		b, e := chunkData(work, p, c)
		if e != nil {
			return fmt.Errorf("%s: %w", it.ID, e)
		}
		h.Write(b)
		size += int64(len(b))
	}
	if it.SHA256 != "" && (hex.EncodeToString(h.Sum(nil)) != it.SHA256 || size != it.Size) {
		return errors.New("completed staged file hash mismatch")
	}
	return nil
}

func storeChunk(work string, b []byte, cs ...*workCrypto) (string, error) {
	c := chooseCrypto(cs)
	h := sha256.Sum256(b)
	sum := hex.EncodeToString(h[:])
	path := filepath.Join(work, "chunks", c.name(sum))
	if _, e := os.Lstat(path); e == nil {
		_, e = chunkData(work, Part{Size: int64(len(b)), SHA256: sum}, c)
		return sum, e
	} else if !os.IsNotExist(e) {
		return "", e
	}
	b, e := c.seal("chunk:"+sum, b)
	if e != nil {
		return "", e
	}
	f, e := os.CreateTemp(filepath.Join(work, "chunks"), ".chunk-*")
	if e != nil {
		return "", e
	}
	name := f.Name()
	defer os.Remove(name)
	if _, e = f.Write(b); e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return "", e
	}
	if ce != nil {
		return "", ce
	}
	if e = os.Rename(name, path); e != nil {
		return "", e
	}
	syncDirectory(filepath.Dir(path))
	return sum, nil
}
func acquireFile(ctx context.Context, work string, s *WorkState, index int, epoch string, afterCommit func(), cs ...*workCrypto) error {
	c := chooseCrypto(cs)
	wf := &s.Files[index]
	it := &wf.Item
	resolved, e := filepath.EvalSymlinks(it.Source)
	if e != nil {
		return e
	}
	if resolved != it.Source {
		return errors.New("source path now contains symlink; start a new acquisition")
	}
	st, e := os.Lstat(it.Source)
	if e != nil {
		return e
	}
	if !st.Mode().IsRegular() || st.Size() != wf.ExpectedSize || !st.ModTime().Equal(it.Modified) {
		return fmt.Errorf("source changed since inventory: %s; start a new acquisition", it.Source)
	}
	f, e := os.Open(it.Source)
	if e != nil {
		return e
	}
	defer f.Close()
	opened, e := f.Stat()
	if e != nil {
		return e
	}
	if !os.SameFile(st, opened) {
		return errors.New("source identity changed")
	}
	if !s.metadataInitialized {
		for _, entry := range s.Files {
			if entry.Item.Metadata != nil && len(entry.Item.Metadata.Attributes) > 0 {
				s.metadataAttributes += int64(len(JSON(entry.Item.Metadata.Attributes)))
			}
		}
		s.metadataInitialized = true
	}
	if it.Metadata == nil {
		it.Metadata = sampledFileMetadata(f, opened, epoch)
		boundMetadataAttributes(it.Metadata, &s.metadataAttributes)
	}
	h := sha256.New()
	var offset int64
	// Re-read the saved prefix from source; matching metadata alone is insufficient.
	for _, part := range it.Parts {
		buf := make([]byte, part.Size)
		if _, e = io.ReadFull(contextReader{ctx, f}, buf); e != nil {
			return e
		}
		hash := sha256.Sum256(buf)
		if hex.EncodeToString(hash[:]) != part.SHA256 {
			return errors.New("source prefix differs from checkpoint; start a new acquisition")
		}
		h.Write(buf)
		offset += part.Size
	}
	for offset < wf.ExpectedSize {
		n := min(int64(resumeChunk), wf.ExpectedSize-offset)
		buf := make([]byte, n)
		if _, e = io.ReadFull(contextReader{ctx, f}, buf); e != nil {
			return e
		}
		sum, e := storeChunk(work, buf, c)
		if e != nil {
			return e
		}
		h.Write(buf)
		it.Parts = append(it.Parts, Part{Offset: offset, Size: n, SHA256: sum, Epoch: epoch, Acquired: time.Now().UTC()})
		offset += n
		if e = saveWork(work, *s, c); e != nil {
			return e
		}
		if afterCommit != nil {
			afterCommit()
		}
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	var extra [1]byte
	n, re := f.Read(extra[:])
	if n != 0 || re != io.EOF {
		return errors.New("source grew or read failed")
	}
	after, e := f.Stat()
	if e != nil {
		return e
	}
	pathAfter, e := os.Stat(it.Source)
	if e != nil {
		return e
	}
	if after.Size() != st.Size() || !after.ModTime().Equal(st.ModTime()) || !os.SameFile(st, pathAfter) {
		return errors.New("source changed during acquisition; start a new acquisition")
	}
	it.Size = offset
	it.SHA256 = hex.EncodeToString(h.Sum(nil))
	it.Collected = time.Now().UTC()
	wf.Complete = true
	return saveWork(work, *s, c)
}
func exportWork(ctx context.Context, work, out string, m Manifest, key ed25519.PrivateKey, cs ...*workCrypto) (err error) {
	c := chooseCrypto(cs)
	f, e := os.OpenFile(out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	success := false
	defer func() {
		f.Close()
		if !success {
			os.Remove(out)
		}
	}()
	if c == nil {
		e = writeWorkZIP(ctx, work, f, m, key, c)
	} else {
		e = writeEncryptedWork(ctx, work, f, m, key, c)
	}
	if e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	success = true
	return nil
}
func writeEncryptedWork(ctx context.Context, work string, output io.Writer, m Manifest, key ed25519.PrivateKey, c *workCrypto) error {
	reader, writer := io.Pipe()
	done := make(chan error, 1)
	go func() { err := encryptStream(reader, output, c.transport); reader.CloseWithError(err); done <- err }()
	zipErr := writeWorkZIP(ctx, work, writer, m, key, c)
	writer.CloseWithError(zipErr)
	encErr := <-done
	if zipErr != nil {
		return zipErr
	}
	return encErr
}

func writeWorkZIP(ctx context.Context, work string, output io.Writer, m Manifest, key ed25519.PrivateKey, c *workCrypto) error {
	z := zip.NewWriter(output)
	if e := ctx.Err(); e != nil {
		return e
	}
	for _, it := range m.Items {
		w, e := z.Create(it.Object)
		if e != nil {
			return e
		}
		h := sha256.New()
		var size int64
		for _, p := range it.Parts {
			if e = ctx.Err(); e != nil {
				return e
			}
			b, e := chunkData(work, p, c)
			if e != nil {
				return e
			}
			if _, e = io.MultiWriter(w, h).Write(b); e != nil {
				return e
			}
			size += int64(len(b))
		}
		if size != it.Size || hex.EncodeToString(h.Sum(nil)) != it.SHA256 {
			return errors.New("staged file hash mismatch")
		}
	}
	b, e := marshalManifest(m)
	if e != nil {
		return fmt.Errorf("manifest cannot be encoded: %w", e)
	}
	w, e := z.Create("manifest.json")
	if e != nil {
		return e
	}
	if _, e = w.Write(b); e != nil {
		return e
	}
	if key != nil {
		w, e = z.Create("manifest.sig")
		if e != nil {
			return e
		}
		if _, e = w.Write(ed25519.Sign(key, b)); e != nil {
			return e
		}
	}
	if e = z.Close(); e != nil {
		return e
	}
	return nil
}

func validateEpochs(epochs []Epoch) error {
	seen := map[string]bool{}
	for _, ep := range epochs {
		if ep.ID == "" || seen[ep.ID] || ep.Started.IsZero() || ep.Outcome == "" {
			return errors.New("invalid acquisition epoch")
		}
		seen[ep.ID] = true
	}
	return nil
}
