package core

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadErrorReaderKeepsPrefix(t *testing.T) {
	r := &readErrorReader{r: io.MultiReader(bytes.NewReader([]byte("abcdef")), errReader{})}
	b, e := io.ReadAll(r)
	if string(b) != "abcdef" || r.err == nil || e == nil {
		t.Fatalf("prefix %q err %v read %v", b, r.err, e)
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("disk fault") }

func TestSnapshotFileKeepsPrefix(t *testing.T) {
	p := filepath.Join(t.TempDir(), "big")
	if e := os.WriteFile(p, bytes.Repeat([]byte("a"), snapshotLimit+8), 0600); e != nil {
		t.Fatal(e)
	}
	b, _, e := snapshot(context.Background(), source{Name: "big", File: p})
	if e == nil || len(b) != snapshotLimit || !bytes.Equal(b, bytes.Repeat([]byte("a"), snapshotLimit)) {
		t.Fatalf("len %d err %v", len(b), e)
	}
}

func TestAdditionalPathsAndSkip(t *testing.T) {
	d := t.TempDir()
	root := filepath.Join(d, "root")
	extra := filepath.Join(d, "extra")
	os.Mkdir(root, 0700)
	os.Mkdir(extra, 0700)
	os.WriteFile(filepath.Join(root, "a.txt"), []byte("a"), 0600)
	os.WriteFile(filepath.Join(extra, "b.txt"), []byte("b"), 0600)
	os.Symlink("b.txt", filepath.Join(extra, "link"))
	var skipped []string
	m, e := Collect(context.Background(), Options{Root: root, Paths: []string{extra, filepath.Join(root, "a.txt")}, Out: filepath.Join(d, "out.k957"), Case: "T", Operator: "T", Scope: "T", MaxFile: 1 << 20, MaxTotal: 1 << 20, MaxFiles: 10, OnSkip: func(path, reason string) {
		skipped = append(skipped, path+": "+reason)
	}})
	if e != nil {
		t.Fatal(e)
	}
	if m.Status != "complete" || len(m.Items) != 2 {
		t.Fatalf("status %s items %d issues %#v", m.Status, len(m.Items), m.Issues)
	}
	if len(skipped) != 1 || !strings.Contains(skipped[0], "link") {
		t.Fatalf("skips %#v", skipped)
	}
}

func TestIOMemAndPlan(t *testing.T) {
	ranges, e := parseIOMem(strings.NewReader("00000000-00000fff : Reserved\n00100000-00100fff : System RAM\n00100000-001007ff : System RAM\n"))
	if e != nil || len(ranges) != 1 || ranges[0].start != 0x100000 || ranges[0].end != 0x101000 {
		t.Fatalf("%#v %v", ranges, e)
	}
	if _, e = parseIOMem(strings.NewReader("00000000-00000000 : System RAM\n")); e == nil || !errors.Is(e, errMemoryPrivilege) {
		t.Fatal(e)
	}
	if _, e = parseIOMem(strings.NewReader("zz : System RAM\n")); e == nil {
		t.Fatal("expected malformed iomem")
	}
	planned, gaps := planPhysical([]physRange{{0x1000, 0x3000}}, []kcoreSegment{{paddr: 0x1800, size: 0x800, offset: 100}})
	if len(planned) != 1 || planned[0].phys != 0x1800 || planned[0].size != 0x800 || planned[0].offset != 100 {
		t.Fatalf("planned %#v", planned)
	}
	if len(gaps) != 2 || gaps[0].Start != 0x1000 || gaps[0].Size != 0x800 || gaps[1].Start != 0x2000 {
		t.Fatalf("gaps %#v", gaps)
	}
}

func TestSyntheticLimeAcquisition(t *testing.T) {
	d := t.TempDir()
	payload := make([]byte, 8192)
	copy(payload, "Linux version 1.2.3-test (builder)\n")
	copy(payload[64:], "failed password for root")
	copy(payload[128:], utf16LE([]byte("FAILED PASSWORD")))
	copy(payload[256:], "http://example.test/memory")
	kcore := filepath.Join(d, "kcore")
	iomem := filepath.Join(d, "iomem")
	writeKcore(t, kcore, 0x100000, len(payload), payload)
	os.WriteFile(iomem, []byte("00100000-00101fff : System RAM\n"), 0600)
	out := filepath.Join(d, "mem")
	os.Mkdir(out, 0700)
	rec, e := AcquireMemory(context.Background(), MemoryOptions{Dir: out, Case: "T", Operator: "T", iomem: iomem, kcore: kcore})
	if e != nil {
		t.Fatal(e)
	}
	if rec.Format != "lime" || rec.Status != "complete" || rec.Bytes != 8192 || len(rec.Ranges) != 1 || rec.Ranges[0].Start != 0x100000 {
		t.Fatalf("%+v", rec)
	}
	f, e := os.Open(filepath.Join(out, "memory.lime"))
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	ranges, e := ParseLime(f)
	if e != nil || len(ranges) != 1 || ranges[0].Size != 8192 {
		t.Fatalf("%v %#v", e, ranges)
	}
	m, e := scanMemoryFile(filepath.Join(out, "memory.lime"), BuiltinRules())
	if e != nil {
		t.Fatal(e)
	}
	if m.KernelBanner != "Linux version 1.2.3-test (builder)" || m.ZeroPages != 1 {
		t.Fatalf("banner %q zeros %d", m.KernelBanner, m.ZeroPages)
	}
	ascii, utf16 := false, false
	for _, h := range m.Hits {
		if h.Rule == "failed-password" && h.Encoding == "ascii" && h.Physical == 0x100000+64 {
			ascii = true
		}
		if h.Rule == "failed-password" && h.Encoding == "utf-16le" && h.Physical == 0x100000+128 {
			utf16 = true
		}
	}
	if !ascii || !utf16 {
		t.Fatalf("hits %#v", m.Hits)
	}
	if len(m.URLs) != 1 || m.URLs[0] != "http://example.test/memory" {
		t.Fatalf("urls %#v", m.URLs)
	}
	if len(m.Volatility) == 0 || !strings.Contains(strings.Join(m.Volatility, "\n"), "LimeLayer") {
		t.Fatalf("volatility %#v", m.Volatility)
	}
	src := filepath.Join(d, "src")
	os.Mkdir(src, 0700)
	lime, e := os.ReadFile(filepath.Join(out, "memory.lime"))
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(src, "memory.lime"), lime, 0600); e != nil {
		t.Fatal(e)
	}
	pkg := filepath.Join(d, "pkg.k957")
	if _, e = Collect(context.Background(), Options{Root: src, Out: pkg, Case: "T", Operator: "T", Scope: "T", MaxFile: 1 << 20, MaxTotal: 8 << 20, MaxFiles: 10}); e != nil {
		t.Fatal(e)
	}
	p, e := Open(pkg, "")
	if e != nil {
		t.Fatal(e)
	}
	defer p.Zip.Close()
	a := Analyze(p, BuiltinRules())
	if len(a.Memories) != 1 || a.Memories[0].KernelBanner == "" || len(a.Findings) == 0 {
		t.Fatalf("memories %d findings %d", len(a.Memories), len(a.Findings))
	}
	report := filepath.Join(d, "report")
	if e = Export(a, report); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Join(report, "memory-hits.csv")); e != nil {
		t.Fatal(e)
	}
}

func TestUnreadableMemoryPage(t *testing.T) {
	d := t.TempDir()
	kcore := filepath.Join(d, "kcore")
	iomem := filepath.Join(d, "iomem")
	writeKcore(t, kcore, 0x200000, 8192, bytes.Repeat([]byte{1}, 4096))
	os.WriteFile(iomem, []byte("00200000-00201fff : System RAM\n"), 0600)
	out := filepath.Join(d, "mem")
	os.Mkdir(out, 0700)
	rec, e := AcquireMemory(context.Background(), MemoryOptions{Dir: out, Case: "T", Operator: "T", iomem: iomem, kcore: kcore})
	if e != nil {
		t.Fatal(e)
	}
	if rec.Status != "partial" || len(rec.Ranges) != 1 || rec.Ranges[0].UnreadablePages != 1 {
		t.Fatalf("%+v", rec)
	}
}

func TestExternalMemoryTool(t *testing.T) {
	if _, e := exec.LookPath("sh"); e != nil {
		t.Skip("sh is required")
	}
	d := t.TempDir()
	script := filepath.Join(d, "tool.sh")
	if e := os.WriteFile(script, []byte("#!/bin/sh\nprintf 'raw-image' > \"$1\"\n"), 0700); e != nil {
		t.Fatal(e)
	}
	out := filepath.Join(d, "mem")
	os.Mkdir(out, 0700)
	rec, e := AcquireMemory(context.Background(), MemoryOptions{Dir: out, Case: "T", Operator: "T", Tool: script, ToolArgs: []string{"{output}"}})
	if e != nil {
		t.Fatal(e)
	}
	if rec.Format != "raw" || rec.Method != "external-tool" || rec.Bytes != 9 || rec.ToolSHA256 == "" {
		t.Fatalf("%+v", rec)
	}
	if _, e := os.Stat(filepath.Join(out, "memory.raw")); e != nil {
		t.Fatal(e)
	}
	if _, e = AcquireMemory(context.Background(), MemoryOptions{Dir: filepath.Join(d, "other"), Tool: script, ToolArgs: []string{"missing-placeholder"}}); e == nil {
		t.Fatal("expected missing output placeholder")
	}
}

func TestFullCollectionVerifyAnalyzeAndTamper(t *testing.T) {
	d := t.TempDir()
	payload := make([]byte, 4096)
	copy(payload, "Linux version 9.9.9-test\nfailed password for analyst\n")
	kcore := filepath.Join(d, "kcore")
	iomem := filepath.Join(d, "iomem")
	writeKcore(t, kcore, 0x300000, len(payload), payload)
	os.WriteFile(iomem, []byte("00300000-00300fff : System RAM\n"), 0600)
	profile := filepath.Join(d, "profile")
	os.Mkdir(profile, 0700)
	os.WriteFile(filepath.Join(profile, "auth.log"), []byte("2026-09-29T00:00:00Z failed password for analyst\n"), 0600)
	os.Symlink("auth.log", filepath.Join(profile, "link"))
	root := filepath.Join(d, "root")
	os.Mkdir(root, 0700)
	os.WriteFile(filepath.Join(root, "note.txt"), []byte("note"), 0600)
	base := filepath.Join(d, "output")
	rec, e := CollectFull(context.Background(), FullOptions{OutputDir: base, Root: root, System: false, Artifacts: true, Memory: true, Profile: []string{profile, filepath.Join(d, "missing")}, Reserve: 0, IOMem: iomem, Kcore: kcore, MaxFile: 1 << 20, MaxTotal: 8 << 20, MaxFiles: 100})
	if e != nil {
		t.Fatal(e)
	}
	if rec.Status != "complete" || rec.Evidence != "evidence.k957" || rec.Memory == nil || !rec.GeneratedKey || !rec.Full || len(rec.CollectorSHA256) != 64 {
		t.Fatalf("%+v", rec)
	}
	if _, e := os.Stat(filepath.Join(rec.Directory, "signing.key")); !os.IsNotExist(e) {
		t.Fatal("private key remained in the collection")
	}
	if len(rec.Absent) != 1 {
		t.Fatalf("absent %#v", rec.Absent)
	}
	if _, e = VerifyStore(context.Background(), base, ""); e != nil {
		t.Fatal(e)
	}
	pub := filepath.Join(rec.Directory, "signing.pub")
	if _, e = VerifyStore(context.Background(), base, pub); e != nil {
		t.Fatal(e)
	}
	analyzed, e := AnalyzeStore(context.Background(), base, "", "", "")
	if e != nil {
		t.Fatal(e)
	}
	if analyzed.Analyzed != 1 || analyzed.Collections[0].Findings == 0 || analyzed.Collections[0].MemoryHits == 0 {
		t.Fatalf("%+v", analyzed)
	}
	report := analyzed.Collections[0].Report
	if _, e = LoadAnalysis(filepath.Join(report, "analysis.json")); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"report.html", "analysis.json", "findings.csv", "timeline.csv", "correlations.csv", "memory.csv", "memory-hits.csv", "memory-observations.csv", "rules.json", "verification.json", "filetypes.csv", "hash-matches.csv", "bodyfile.txt", "persistence.csv", "activity.csv", filepath.Join("shared", "report.html"), filepath.Join("shared", "shared.json")} {
		if _, e := os.Stat(filepath.Join(report, name)); e != nil {
			t.Fatal(name, e)
		}
	}
	sig := filepath.Join(rec.Directory, "collection.sig")
	if e = os.WriteFile(sig, make([]byte, 64), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = VerifyStore(context.Background(), base, ""); e == nil {
		t.Fatal("tampered signature was accepted")
	}
}

func TestSanitizeHost(t *testing.T) {
	if sanitizeHost("web.example.com") != "web.example.com" || sanitizeHost("a/b") != "a_b" || sanitizeHost("..") != "unknown" || sanitizeHost("") != "unknown" {
		t.Fatal(sanitizeHost("a/b"), sanitizeHost(".."))
	}
}

func writeKcore(t *testing.T, path string, paddr uint64, filesz int, payload []byte) {
	t.Helper()
	const dataOff = 64 + 56
	hdr := make([]byte, dataOff)
	copy(hdr, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(hdr[16:], 4)
	binary.LittleEndian.PutUint16(hdr[18:], 62)
	binary.LittleEndian.PutUint32(hdr[20:], 1)
	binary.LittleEndian.PutUint64(hdr[32:], 64)
	binary.LittleEndian.PutUint16(hdr[52:], 64)
	binary.LittleEndian.PutUint16(hdr[54:], 56)
	binary.LittleEndian.PutUint16(hdr[56:], 1)
	binary.LittleEndian.PutUint32(hdr[64:], 1)
	binary.LittleEndian.PutUint32(hdr[68:], 4)
	binary.LittleEndian.PutUint64(hdr[72:], dataOff)
	binary.LittleEndian.PutUint64(hdr[88:], paddr)
	binary.LittleEndian.PutUint64(hdr[96:], uint64(filesz))
	binary.LittleEndian.PutUint64(hdr[104:], uint64(filesz))
	binary.LittleEndian.PutUint64(hdr[112:], 4096)
	if e := os.WriteFile(path, append(hdr, payload...), 0600); e != nil {
		t.Fatal(e)
	}
}
