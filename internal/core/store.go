package core

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CollectionVerification is the result of checking one full-mode directory.
type CollectionVerification struct {
	verifiedRecord      *CollectionRecord
	verifiedRecordBytes []byte
	Directory           string   `json:"directory"`
	Status              string   `json:"status"`
	Signature           string   `json:"signature"`
	CollectionStatus    string   `json:"collection_status,omitempty"`
	Evidence            string   `json:"evidence,omitempty"`
	Memory              string   `json:"memory,omitempty"`
	Errors              []string `json:"errors,omitempty"`
}

// StoreVerification is the batch result for every host under a collection root.
type StoreVerification struct {
	Root        string                   `json:"root"`
	Collections []CollectionVerification `json:"collections"`
	Verified    int                      `json:"verified"`
	Failed      int                      `json:"failed"`
}

// CollectionAnalysis is one stored collection after verification and reporting.
type CollectionAnalysis struct {
	Directory  string   `json:"directory"`
	Status     string   `json:"status"`
	Report     string   `json:"report,omitempty"`
	Findings   int      `json:"findings,omitempty"`
	MemoryHits int      `json:"memory_hits,omitempty"`
	Errors     []string `json:"errors,omitempty"`
}

// StoreAnalysis is the batch analysis result.
type StoreAnalysis struct {
	Root        string               `json:"root"`
	Collections []CollectionAnalysis `json:"collections"`
	Analyzed    int                  `json:"analyzed"`
	Failed      int                  `json:"failed"`
}

// DiscoverCollections lists output/<hostname>/<timestamp> directories.
func DiscoverCollections(root string) ([]string, error) {
	root, e := filepath.Abs(root)
	if e != nil {
		return nil, e
	}
	hosts, e := os.ReadDir(root)
	if e != nil {
		return nil, e
	}
	var dirs []string
	for _, host := range hosts {
		if !host.IsDir() {
			continue
		}
		stamps, e := os.ReadDir(filepath.Join(root, host.Name()))
		if e != nil {
			return nil, e
		}
		for _, stamp := range stamps {
			if stamp.IsDir() {
				dirs = append(dirs, filepath.Join(root, host.Name(), stamp.Name()))
			}
		}
	}
	return dirs, nil
}

// VerifyStore checks every collection under root. An empty root is an error.
// A cancelled ctx stops before the next collection. Progress hints are not stored.
func VerifyStore(ctx context.Context, root, trustedKey string) (StoreVerification, error) {
	dirs, e := DiscoverCollections(root)
	if e != nil {
		return StoreVerification{}, e
	}
	out := StoreVerification{Root: root, Collections: []CollectionVerification{}}
	if len(dirs) == 0 {
		return out, fmt.Errorf("no collections in %s", root)
	}
	plans := make([]int64, len(dirs))
	var total int64
	for i, dir := range dirs {
		if e = ctx.Err(); e != nil {
			return out, e
		}
		plans[i] = verifyReadBytes(dir)
		total += plans[i]
	}
	meter := &verifyMeter{ctx: ctx, total: total}
	var done int64
	for i, dir := range dirs {
		if e = ctx.Err(); e != nil {
			return out, e
		}
		if total > 0 {
			ReportProgress(ctx, Progress{Phase: "verify", Detail: dir, Bytes: done, TotalBytes: total})
		} else {
			ReportProgress(ctx, Progress{Phase: "verify", Detail: dir, Step: i, Steps: len(dirs)})
		}
		meter.done = done
		v := verifyCollectionProgress(ctx, dir, trustedKey, meter)
		done += plans[i]
		out.Collections = append(out.Collections, v)
		if v.Status == "verified" {
			out.Verified++
		} else {
			out.Failed++
		}
	}
	if e = ctx.Err(); e != nil {
		return out, e
	}
	if out.Failed > 0 {
		return out, fmt.Errorf("%d of %d collections failed verification", out.Failed, len(dirs))
	}
	return out, nil
}

func verifyCollection(dir, trustedKey string) CollectionVerification {
	return verifyCollectionProgress(context.Background(), dir, trustedKey, nil)
}

func verifyCollectionProgress(ctx context.Context, dir, trustedKey string, meter *verifyMeter) (v CollectionVerification) {
	if ctx == nil {
		ctx = context.Background()
	}
	if meter == nil {
		meter = &verifyMeter{ctx: ctx}
	}
	v = CollectionVerification{Directory: dir, Status: "verified", Signature: "not authenticated"}
	if e := ctx.Err(); e != nil {
		v.Status = "failed"
		v.Errors = []string{e.Error()}
		return v
	}
	fail := func(msg string) {
		v.Status = "failed"
		v.Errors = append(v.Errors, msg)
	}
	body, e := ReadLimited(filepath.Join(dir, "collection.json"), 32<<20)
	if e != nil {
		fail("collection record: " + e.Error())
		v.Signature = "absent"
		return v
	}
	var rec CollectionRecord
	if e = custodyJSON(body, &rec); e != nil {
		fail("collection record: " + e.Error())
		return v
	}
	v.CollectionStatus = rec.Status
	if rec.Schema != CollectionSchema || !acceptedCollectionVersion(rec.Version) || rec.ID == "" || rec.Case == "" || (rec.Status != "complete" && rec.Status != "partial") {
		fail("unsupported or invalid collection record")
	}
	sig, e := ReadLimited(filepath.Join(dir, "collection.sig"), ed25519.SignatureSize)
	if e != nil || len(sig) != ed25519.SignatureSize {
		fail("invalid collection signature")
		v.Signature = "invalid"
	} else {
		pub, e := hex.DecodeString(strings.TrimSpace(rec.PublicKey))
		if e != nil || len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, body, sig) {
			fail("collection signature does not match the embedded key")
			v.Signature = "failed"
		}
		stored, e := loadPublic(filepath.Join(dir, "signing.pub"))
		if e != nil || !bytes.Equal(stored, pub) {
			fail("signing.pub does not match the embedded key")
		}
		if trustedKey != "" {
			trusted, e := loadPublic(trustedKey)
			if e != nil {
				fail(e.Error())
			} else if !bytes.Equal(trusted, pub) || !ed25519.Verify(trusted, body, sig) {
				fail("collection was not signed by the trusted key")
				v.Signature = "failed"
			} else if v.Signature != "failed" {
				v.Signature = "verified against supplied trusted key"
			}
		} else if v.Signature != "failed" {
			v.Signature = "verified against embedded key; not an external trust anchor"
		}
	}
	if rec.Evidence != "" {
		if !collectionFileName(rec.Evidence) || !regularFile(filepath.Join(dir, rec.Evidence)) {
			fail("invalid evidence path: a regular file inside the collection is required")
			return v
		}
		v.Evidence = rec.Evidence
		p, e := OpenContext(ctx, filepath.Join(dir, rec.Evidence), filepath.Join(dir, "signing.pub"))
		if e != nil {
			fail("evidence: " + e.Error())
		} else {
			if p.Signature != "verified against supplied trusted key" {
				fail("evidence signature was not verified")
			}
			p.Zip.Close()
		}
	}
	for _, a := range rec.Artifacts {
		if e := checkArtifactProgress(dir, a, meter); e != nil {
			fail(e.Error())
		}
	}
	if e := checkSumsProgress(dir, meter); e != nil {
		fail(e.Error())
	}
	if rec.Memory != nil {
		v.Memory = rec.Memory.Image
		if e := checkMemoryProgress(dir, rec.Memory, meter); e != nil {
			fail("memory: " + e.Error())
		}
	}
	if v.Status == "verified" && ctx.Value(collectionSnapshotKey{}) == true {
		v.verifiedRecord = &rec
		v.verifiedRecordBytes = append([]byte(nil), body...)
	}
	return v
}

const verifyReportEvery = 4 << 20

// verifyMeter counts bytes read while checking or examining collections.
// total is the planned read size; done is the planned size already finished.
// An empty phase is reported as verify.
type verifyMeter struct {
	ctx   context.Context
	phase string
	done  int64
	total int64
}

func (m *verifyMeter) reader(r io.Reader, detail string, planned int64) io.Reader {
	if m == nil {
		return r
	}
	return &verifyReader{meter: m, r: r, detail: detail, planned: planned}
}

func (m *verifyMeter) finish(planned int64) {
	if m == nil || planned <= 0 {
		return
	}
	m.done += planned
	if m.done > m.total {
		m.done = m.total
	}
}

func (m *verifyMeter) emit(detail string, fileRead, planned int64) {
	if m == nil || m.total <= 0 {
		return
	}
	shown := fileRead
	if planned > 0 && shown > planned {
		shown = planned
	}
	pos := m.done + shown
	if pos > m.total {
		pos = m.total
	}
	phase := m.phase
	if phase == "" {
		phase = "verify"
	}
	ReportProgress(m.ctx, Progress{Phase: phase, Detail: detail, Bytes: pos, TotalBytes: m.total})
}

type verifyReader struct {
	meter   *verifyMeter
	r       io.Reader
	detail  string
	planned int64
	read    int64
	since   int64
}

func (r *verifyReader) Read(p []byte) (int, error) {
	if r.meter != nil && r.meter.ctx != nil {
		if e := r.meter.ctx.Err(); e != nil {
			return 0, e
		}
	}
	n, err := r.r.Read(p)
	if n > 0 {
		r.read += int64(n)
		r.since += int64(n)
	}
	if r.since >= verifyReportEvery || (err != nil && r.since > 0) {
		r.meter.emit(r.detail, r.read, r.planned)
		r.since = 0
	}
	return n, err
}

func verifyReadBytes(dir string) int64 {
	body, e := ReadLimited(filepath.Join(dir, "collection.json"), 32<<20)
	if e != nil {
		return 0
	}
	var rec CollectionRecord
	if json.Unmarshal(body, &rec) != nil {
		return 0
	}
	var n int64
	for _, a := range rec.Artifacts {
		if !collectionFileName(a.Name) {
			continue
		}
		n += fileSize(filepath.Join(dir, a.Name))
	}
	if regularFile(filepath.Join(dir, "SHA256SUMS")) {
		files, e := collectionFiles(dir)
		if e == nil {
			for _, rel := range files {
				n += fileSize(filepath.Join(dir, filepath.FromSlash(rel)))
			}
		}
	}
	if rec.Memory != nil && rec.Memory.Schema == MemorySchema && rec.Memory.Image != "" && !strings.ContainsAny(rec.Memory.Image, `/\`) {
		sz := fileSize(filepath.Join(dir, rec.Memory.Image))
		n += sz
		if rec.Memory.Format == "lime" {
			n += sz
		}
	}
	return n
}

func collectionFileName(name string) bool {
	return name != "" && !strings.ContainsAny(name, `/\:`) && name != "." && name != ".."
}

func regularFile(path string) bool {
	st, e := os.Lstat(path)
	return e == nil && st.Mode().IsRegular()
}

func fileSize(path string) int64 {
	st, e := os.Stat(path)
	if e != nil || !st.Mode().IsRegular() || st.Size() < 0 {
		return 0
	}
	return st.Size()
}

func checkArtifact(dir string, a CollectionArtifact) error {
	return checkArtifactProgress(dir, a, nil)
}

func checkArtifactProgress(dir string, a CollectionArtifact, meter *verifyMeter) error {
	if !collectionFileName(a.Name) {
		return fmt.Errorf("invalid artifact name %q", a.Name)
	}
	path := filepath.Join(dir, a.Name)
	if !regularFile(path) {
		return fmt.Errorf("%s: regular file required", filepath.Base(path))
	}
	planned := fileSize(path)
	sha256sum, sha1sum, md5sum, size, e := hashFileProgress(path, a.Name, planned, meter)
	if e != nil {
		return fmt.Errorf("%s: %w", a.Name, e)
	}
	if sha256sum != a.SHA256 || size != a.Size || (a.SHA1 != "" && sha1sum != a.SHA1) || (a.MD5 != "" && md5sum != a.MD5) {
		return fmt.Errorf("%s: hash or size mismatch", a.Name)
	}
	return nil
}

func hashFileProgress(path, detail string, planned int64, meter *verifyMeter) (string, string, string, int64, error) {
	if meter == nil {
		return hashFile(path)
	}
	f, e := os.Open(path)
	if e != nil {
		return "", "", "", 0, e
	}
	defer f.Close()
	sha256sum, sha1sum, md5sum, n, e := hashReader(meter.reader(f, detail, planned))
	if e != nil {
		return "", "", "", n, e
	}
	meter.finish(planned)
	return sha256sum, sha1sum, md5sum, n, nil
}

func fileSHA256Progress(path, detail string, planned int64, meter *verifyMeter) (string, error) {
	if meter == nil {
		return fileSHA256(path)
	}
	f, e := os.Open(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	sum, e := sha256Reader(meter.reader(f, detail, planned))
	if e != nil {
		return "", e
	}
	meter.finish(planned)
	return sum, nil
}

func checkSums(dir string) error {
	return checkSumsProgress(dir, nil)
}

func checkSumsProgress(dir string, meter *verifyMeter) error {
	b, e := ReadLimited(filepath.Join(dir, "SHA256SUMS"), 32<<20)
	if e != nil {
		return fmt.Errorf("SHA256SUMS: %w", e)
	}
	listed := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if len(line) < 66 {
			return errors.New("malformed SHA256SUMS line")
		}
		sum := strings.ToLower(line[:64])
		rest := line[64:]
		var name string
		switch {
		case strings.HasPrefix(rest, " *"), strings.HasPrefix(rest, "  "):
			name = rest[2:]
		default:
			return errors.New("malformed SHA256SUMS line")
		}
		if e := safeSumName(name); e != nil {
			return e
		}
		if _, ok := listed[name]; ok {
			return fmt.Errorf("duplicate SHA256SUMS entry %s", name)
		}
		listed[name] = sum
	}
	if e := sc.Err(); e != nil {
		return e
	}
	files, e := collectionFiles(dir)
	if e != nil {
		return e
	}
	if len(files) != len(listed) {
		return fmt.Errorf("SHA256SUMS lists %d files, directory has %d", len(listed), len(files))
	}
	for _, rel := range files {
		want, ok := listed[rel]
		if !ok {
			return fmt.Errorf("file missing from SHA256SUMS: %s", rel)
		}
		path := filepath.Join(dir, filepath.FromSlash(rel))
		sum, e := fileSHA256Progress(path, rel, fileSize(path), meter)
		if e != nil {
			return e
		}
		if !strings.EqualFold(sum, want) {
			return fmt.Errorf("SHA256SUMS mismatch: %s", rel)
		}
	}
	return nil
}

func safeSumName(name string) error {
	if name == "" || strings.Contains(name, `\`) || filepath.IsAbs(name) {
		return fmt.Errorf("invalid SHA256SUMS path %q", name)
	}
	for _, p := range strings.Split(name, "/") {
		if p == "" || p == "." || p == ".." {
			return fmt.Errorf("invalid SHA256SUMS path %q", name)
		}
	}
	return nil
}

func checkMemory(dir string, rec *MemoryRecord) error {
	return checkMemoryProgress(dir, rec, nil)
}

func checkMemoryProgress(dir string, rec *MemoryRecord, meter *verifyMeter) error {
	if rec.Schema != MemorySchema || !collectionFileName(rec.Image) {
		return errors.New("invalid memory record")
	}
	path := filepath.Join(dir, rec.Image)
	if !regularFile(path) {
		return fmt.Errorf("%s: regular file required", filepath.Base(path))
	}
	planned := fileSize(path)
	sha256sum, sha1sum, md5sum, size, e := hashFileProgress(path, rec.Image, planned, meter)
	if e != nil {
		return e
	}
	if sha256sum != rec.SHA256 || sha1sum != rec.SHA1 || md5sum != rec.MD5 || size != rec.ImageSize {
		return errors.New("image hash or size does not match memory.json")
	}
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	var reader io.Reader = f
	if meter != nil {
		reader = meter.reader(f, rec.Image, planned)
	}
	switch rec.Format {
	case "lime":
		ranges, e := ParseLime(reader)
		if e != nil {
			return e
		}
		if meter != nil {
			meter.finish(planned)
		}
		if len(ranges) != len(rec.Ranges) {
			return errors.New("lime range count does not match memory.json")
		}
		var payload uint64
		for i, rg := range ranges {
			if rg.Start != rec.Ranges[i].Start || rg.Size != rec.Ranges[i].Size {
				return fmt.Errorf("lime range %d does not match memory.json", i)
			}
			payload += rg.Size
		}
		if int64(payload)+int64(len(ranges))*limeHeaderSize != size {
			return errors.New("lime image size does not match its ranges")
		}
	case "raw":
		if len(rec.Ranges) != 1 || rec.Ranges[0].Start != 0 || rec.Ranges[0].Size != uint64(size) || rec.Bytes != uint64(size) {
			return errors.New("raw image does not match memory.json")
		}
	default:
		return errors.New("unknown memory format")
	}
	return nil
}

// AnalyzeStore verifies every collection, then writes a full report and a
// masked shared report under reports/<timestamp>/.
func acceptedCollectionVersion(v string) bool {
	return v == Version || v == "0.13.0"
}

func AnalyzeStore(ctx context.Context, root, rulesPath, trustedKey, hashSetPath string) (StoreAnalysis, error) {
	dirs, e := DiscoverCollections(root)
	if e != nil {
		return StoreAnalysis{}, e
	}
	out := StoreAnalysis{Root: root, Collections: []CollectionAnalysis{}}
	if len(dirs) == 0 {
		return out, fmt.Errorf("no collections in %s", root)
	}
	rules, e := LoadRules(rulesPath)
	if e != nil {
		return out, e
	}
	if rulesPath == "" {
		rules = BuiltinRules()
	}
	set, e := LoadHashSet(hashSetPath)
	if e != nil {
		return out, e
	}
	plans := make([]int64, len(dirs))
	var total int64
	for i, dir := range dirs {
		if e = ctx.Err(); e != nil {
			return out, e
		}
		plans[i] = analyzeReadBytes(dir)
		total += plans[i]
	}
	meter := &verifyMeter{ctx: ctx, phase: "analyze", total: total}
	var done int64
	for i, dir := range dirs {
		if e = ctx.Err(); e != nil {
			return out, e
		}
		if total > 0 {
			ReportProgress(ctx, Progress{Phase: "analyze", Detail: dir, Bytes: done, TotalBytes: total})
		} else {
			ReportProgress(ctx, Progress{Phase: "analyze", Detail: dir, Step: i, Steps: len(dirs)})
		}
		meter.done = done
		item := analyzeCollection(ctx, dir, rules, trustedKey, set, meter)
		done += plans[i]
		out.Collections = append(out.Collections, item)
		if item.Status == "analyzed" {
			out.Analyzed++
		} else {
			out.Failed++
		}
	}
	if e = ctx.Err(); e != nil {
		return out, e
	}
	if out.Failed > 0 {
		return out, fmt.Errorf("%d of %d collections failed analysis", out.Failed, len(dirs))
	}
	return out, nil
}

// analyzeReadBytes is the verification read plus one pass over the memory image.
// Report export is not included; it does not reread the image.
func analyzeReadBytes(dir string) int64 {
	n := verifyReadBytes(dir)
	body, e := ReadLimited(filepath.Join(dir, "collection.json"), 32<<20)
	if e != nil {
		return n
	}
	var rec CollectionRecord
	if json.Unmarshal(body, &rec) != nil || rec.Memory == nil {
		return n
	}
	if rec.Memory.Image == "" || strings.ContainsAny(rec.Memory.Image, `/\`) {
		return n
	}
	return n + fileSize(filepath.Join(dir, rec.Memory.Image))
}

func analyzeCollection(ctx context.Context, dir string, rules []Rule, trustedKey string, set *HashSet, meter *verifyMeter) CollectionAnalysis {
	if meter == nil {
		meter = &verifyMeter{ctx: ctx}
	}
	item := CollectionAnalysis{Directory: dir, Status: "analyzed"}
	if e := ctx.Err(); e != nil {
		item.Status = "failed"
		item.Errors = []string{e.Error()}
		return item
	}
	v := verifyCollectionForExamination(ctx, dir, trustedKey, meter)
	if v.Status != "verified" {
		item.Status = "failed"
		item.Errors = v.Errors
		return item
	}
	body, rec, e := verifiedCollectionSnapshot(v)
	if e != nil {
		item.Status = "failed"
		item.Errors = []string{e.Error()}
		return item
	}
	report, e := nextReportDir(filepath.Join(dir, "reports"))
	if e != nil {
		item.Status = "failed"
		item.Errors = []string{e.Error()}
		return item
	}
	if e = os.MkdirAll(filepath.Dir(report), 0700); e != nil {
		item.Status = "failed"
		item.Errors = []string{e.Error()}
		return item
	}
	workspace, e := os.MkdirTemp(filepath.Dir(report), ".memory-analysis-")
	if e != nil {
		item.Status = "failed"
		item.Errors = []string{e.Error()}
		return item
	}
	defer os.RemoveAll(workspace)
	ctx = WithMemoryWorkspace(ctx, workspace)
	var a Analysis
	if rec.Evidence != "" {
		p, e := openVerifiedCollectionPackage(ctx, dir, rec)
		if e != nil {
			item.Status = "failed"
			item.Errors = []string{e.Error()}
			return item
		}
		a = AnalyzeContext(ctx, p, rules)
		p.Close()
	} else {
		a = Analysis{Version: Version, Run: ID(), Created: time.Now().UTC(), Signature: v.Signature, Manifest: Manifest{Schema: Schema, Version: Version, ID: rec.ID, Case: rec.Case, Operator: rec.Operator, Scope: rec.Scope, Host: rec.Host, OS: rec.OS, Arch: rec.Arch, Started: rec.Started, Finished: rec.Finished, Status: rec.Status, Items: []Item{}, Issues: []Issue{}}, Rules: rules, Findings: []Finding{}, Timeline: []Event{}, Notes: []string{"No evidence package was in this collection. The report covers the memory image and collection record only."}}
	}
	// Full-mode identity must bind all signed artifacts, including external RAM.
	// Keep the package manifest digest available without treating an embedded
	// public key as a caller-supplied trust anchor.
	a.PackageDigest = a.EvidenceDigest
	digest := sha256.Sum256(body)
	a.EvidenceDigest = hex.EncodeToString(digest[:])
	a.Signature = v.Signature
	a.CollectionStatus = rec.Status
	a.CollectionIssues = append([]Issue(nil), rec.Issues...)
	a.Adaptive = rec.Adaptive
	a.Notes = append(a.Notes, "Full-mode evidence_digest is SHA-256 of the signed collection.json bytes, binding all recorded artifacts. package_digest is the evidence package manifest SHA-256 when present. Collection status and issues cover the complete acquisition; manifest metadata describes the logical package.")
	for i := range a.Findings {
		a.Findings[i].ID = findingID(a.EvidenceDigest, a.Findings[i])
	}
	if rec.Memory != nil && rec.Memory.Image != "" {
		image := filepath.Join(dir, rec.Memory.Image)
		m, e := scanVerifiedMemoryFile(ctx, image, rec.Memory.SHA256, rules, meter)
		if e != nil {
			item.Status = "failed"
			item.Errors = []string{"memory analysis: " + e.Error()}
			return item
		}
		m.Evidence = "MEMORY"
		m.Source = rec.Memory.Image
		annotateMemory(&m, rec.Memory)
		if e = examineConfiguredMemory(ctx, image, rec.Memory.OS, &m); e != nil {
			item.Status = "failed"
			item.Errors = []string{e.Error()}
			return item
		}
		rememberMemory(&a, m)
		item.MemoryHits = len(m.Hits)
		if m.Results != nil {
			item.MemoryHits = int(m.Results.Hits)
		}
	}
	if e := ctx.Err(); e != nil {
		item.Status = "failed"
		item.Errors = []string{e.Error()}
		return item
	}
	applyConfiguredIndicators(ctx, &a)
	ApplyHashSet(&a, set)
	if e = ExportContext(ctx, a, report); e != nil {
		item.Status = "failed"
		item.Errors = []string{e.Error()}
		return item
	}
	policy, e := LoadSharePolicy("")
	if e != nil {
		item.Status = "failed"
		item.Errors = []string{e.Error()}
		return item
	}
	shared, e := BuildSharedReport(a, policy)
	if e != nil {
		item.Status = "failed"
		item.Errors = []string{e.Error()}
		return item
	}
	if e = ExportShared(shared, filepath.Join(report, "shared")); e != nil {
		item.Status = "failed"
		item.Errors = []string{e.Error()}
		return item
	}
	if e = WriteJSONNew(filepath.Join(report, "rules.json"), rules); e != nil {
		item.Status = "failed"
		item.Errors = []string{e.Error()}
		return item
	}
	if e = WriteJSONNew(filepath.Join(report, "verification.json"), v); e != nil {
		item.Status = "failed"
		item.Errors = []string{e.Error()}
		return item
	}
	item.Report = report
	item.Findings = len(a.Findings)
	return item
}

func nextReportDir(parent string) (string, error) {
	if e := os.MkdirAll(parent, 0700); e != nil {
		return "", e
	}
	stamp := time.Now().UTC().Format("20060102T150405Z")
	for i := 0; i < 100; i++ {
		name := stamp
		if i > 0 {
			name = fmt.Sprintf("%s-%d", stamp, i+1)
		}
		p := filepath.Join(parent, name)
		if _, e := os.Lstat(p); os.IsNotExist(e) {
			return p, nil
		}
	}
	return "", errors.New("report directory collision")
}

// BuiltinRules is the literal triage set used when analyze is given no rule file.
func BuiltinRules() []Rule {
	return []Rule{
		{ID: "failed-password", Description: "Failed password authentication", Contains: "failed password"},
		{ID: "authentication-failure", Description: "Authentication failure", Contains: "authentication failure"},
		{ID: "invalid-user", Description: "Invalid user login attempt", Contains: "invalid user"},
		{ID: "accepted-password", Description: "Accepted password authentication", Contains: "accepted password"},
		{ID: "accepted-publickey", Description: "Accepted public key authentication", Contains: "accepted publickey"},
		{ID: "sudo", Description: "sudo invocation", Contains: "sudo:"},
		{ID: "session-opened", Description: "Session opened", Contains: "session opened"},
		{ID: "user-add", Description: "User account creation", Contains: "useradd"},
		{ID: "authorized-keys", Description: "SSH authorized keys file", Contains: "authorized_keys"},
		{ID: "powershell-encoded", Description: "Encoded PowerShell command", Contains: "powershell -enc"},
		{ID: "powershell-hidden", Description: "Hidden PowerShell execution", Contains: "-windowstyle hidden"},
		{ID: "cmd-exec", Description: "Windows command shell execution", Contains: "cmd.exe /c"},
		{ID: "dev-shm", Description: "Shared-memory execution path", Contains: "/dev/shm"},
		{ID: "base64-decode", Description: "Base64 decode command", Contains: "base64 -d"},
		{ID: "netcat-listen", Description: "Netcat listener", Contains: "nc -l"},
		{ID: "dev-tcp", Description: "Bash reverse-shell device", Contains: "/dev/tcp/"},
		{ID: "mimikatz", Description: "Mimikatz string", Contains: "mimikatz"},
		{ID: "meterpreter", Description: "Meterpreter string", Contains: "meterpreter"},
		{ID: "shadow-path", Description: "Password database path", Contains: "/etc/shadow"},
		{ID: "certutil", Description: "certutil execution", Contains: "certutil"},
		{ID: "rundll32", Description: "rundll32 execution", Contains: "rundll32"},
		{ID: "regsvr32", Description: "regsvr32 execution", Contains: "regsvr32"},
		{ID: "bitsadmin", Description: "bitsadmin execution", Contains: "bitsadmin"},
		{ID: "osascript", Description: "osascript execution", Contains: "osascript"},
		{ID: "launchctl-load", Description: "launchctl load", Contains: "launchctl load"},
		{ID: "schtasks-create", Description: "Scheduled task creation", Contains: "schtasks /create"},
		{ID: "wmic-process", Description: "WMI process creation", Contains: "wmic process call create"},
	}
}
