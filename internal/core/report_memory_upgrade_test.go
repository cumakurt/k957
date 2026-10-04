package core

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCompleteMemoryResultsBeyondOldCaps(t *testing.T) {
	old := memoryWindow
	memoryWindow = 23
	t.Cleanup(func() { memoryWindow = old })
	image := bytes.Repeat([]byte("password\x00"), 1500)
	image = append(image, bytes.Repeat([]byte("prefix\x00-----BEGIN CERTIFICATE-----\x00"), 650)...)
	image = append(image, []byte("LATE_PASSWORD\x00")...)
	workspace := t.TempDir()
	ctx := WithMemoryWorkspace(context.Background(), workspace)
	m, e := scanMemoryContext(ctx, bytes.NewReader(image), []Rule{{ID: "pw", Contains: "password"}})
	if e != nil {
		t.Fatal(e)
	}
	if m.Limited || m.ObservationsLimited || m.Results == nil || m.Results.Hits != 1501 || m.Results.Observations < 650 || m.Results.Strings < 1500 {
		t.Fatalf("incomplete scan: %+v", m.Results)
	}
	if len(m.Hits) != memoryHitTotal || len(m.Observations) != memoryObsTotal {
		t.Fatal("preview policy changed", len(m.Hits), len(m.Observations))
	}
	raw, e := os.ReadFile(m.Results.path)
	if e != nil {
		t.Fatal(e)
	}
	if digestBytes(raw) != m.Results.SHA256 {
		t.Fatal("sidecar hash")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	hits := 0
	late := false
	for {
		var r MemoryResult
		e = d.Decode(&r)
		if e == io.EOF {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
		if r.Kind == "literal" {
			hits++
			if r.Physical >= uint64(len(image)-20) {
				late = true
			}
		}
	}
	if hits != 1501 || !late {
		t.Fatal("late hit lost", hits, late)
	}
}
func TestMemoryStringsReconstructLongASCIIAndUTF16(t *testing.T) {
	old := memoryWindow
	memoryWindow = 101
	t.Cleanup(func() { memoryWindow = old })
	ascii := strings.Repeat("a", memoryStringSegment+31)
	wide := utf16LE([]byte(strings.Repeat("b", memoryStringSegment+17)))
	image := append([]byte(ascii+"\x00\x00"), wide...)
	image = append(image, 0, 0)
	m, e := scanMemoryContext(WithMemoryWorkspace(context.Background(), t.TempDir()), bytes.NewReader(image), nil)
	if e != nil {
		t.Fatal(e)
	}
	f, e := os.Open(m.Results.path)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	d := json.NewDecoder(f)
	var gotASCII, gotWide strings.Builder
	for {
		var row MemoryResult
		e = d.Decode(&row)
		if e == io.EOF {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
		if row.Kind != "string" {
			continue
		}
		if row.Encoding == "ascii" && strings.HasPrefix(row.Detail, "aaa") {
			gotASCII.WriteString(row.Detail)
		}
		if row.Encoding == "utf-16le" && strings.HasPrefix(row.Detail, "bbb") {
			gotWide.WriteString(row.Detail)
		}
	}
	if gotASCII.String() != ascii || gotWide.String() != strings.Repeat("b", memoryStringSegment+17) {
		t.Fatal("string segments lost bytes", gotASCII.Len(), gotWide.Len())
	}
}
func TestMemoryWorkspaceFailuresAndCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := scanMemoryContext(WithMemoryWorkspace(ctx, t.TempDir()), contextReader{ctx: ctx, r: strings.NewReader("image")}, nil); e == nil {
		t.Fatal("cancelled scan accepted")
	}
	if _, e := scanMemoryContext(WithMemoryWorkspace(context.Background(), filepath.Join(t.TempDir(), "missing")), strings.NewReader("image"), nil); e == nil {
		t.Fatal("missing workspace accepted")
	}
}
func TestNativeDefaultPDFAndPortableReferences(t *testing.T) {
	a := Analysis{Version: Version, Run: "R1", Created: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), EvidenceDigest: strings.Repeat("a", 64), Manifest: Manifest{Case: "Café <case> 漢", Host: "host", Items: []Item{{ID: "E1", Source: "source", SHA256: strings.Repeat("b", 64)}}}, Findings: []Finding{{ID: "F1", Rule: "rule", Evidence: "E1", Source: "source", Review: "confirmed"}}, Timeline: []Event{{Time: time.Date(2026, 1, 1, 0, 0, 1, 0, time.UTC), Type: "test", Evidence: "E1", Source: "source", Detail: "quoted <text>", SourceIP: "198.51.100.10"}}}
	out := filepath.Join(t.TempDir(), "report")
	if e := Export(a, out); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"report.pdf", "documents.json", "review-queue.json", "timeline.jsonl", "portable-exports.json", "file-sha256.txt", "ip-addresses.txt"} {
		if _, e := os.Stat(filepath.Join(out, name)); e != nil {
			t.Fatal(name, e)
		}
	}
	var receipt DocumentReceipt
	if e := strictJSON(filepath.Join(out, "documents.json"), 1<<20, &receipt); e != nil {
		t.Fatal(e)
	}
	if receipt.PDFPages < 2 || len(receipt.GlyphEscapes) == 0 || receipt.SourceAnalysisDigest == "" {
		t.Fatal("rendering disclosure", receipt)
	}
	body, _ := os.ReadFile(filepath.Join(out, "timeline.jsonl"))
	if !bytes.Contains(body, []byte(`"evidence_id":"E1"`)) || !bytes.Contains(body, []byte(`"timestamp_desc":"test"`)) {
		t.Fatal("portable provenance")
	}
	html, _ := os.ReadFile(filepath.Join(out, "report.html"))
	for _, value := range []string{"report.pdf", "beforeprint", "Finding review states", "memory"} {
		if !bytes.Contains(html, []byte(value)) {
			t.Fatal(value)
		}
	}
	if bytes.Contains(html, []byte("linear-gradient")) {
		t.Fatal("decorative gradient")
	}
}
func TestMemoryJSONCountsBeyondOldRowLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "objects.json")
	f, e := os.Create(path)
	if e != nil {
		t.Fatal(e)
	}
	f.WriteString("[")
	for i := 0; i < 100001; i++ {
		if i > 0 {
			f.WriteString(",")
		}
		f.WriteString(`{"PID":7}`)
	}
	f.WriteString("]")
	f.Close()
	count, e := countMemoryJSON(context.Background(), path)
	if e != nil || count != 100001 {
		t.Fatal(count, e)
	}
	for _, bad := range []string{`[] []`, `[null]`, `{"PID":1}`} {
		if e = os.WriteFile(path, []byte(bad), 0600); e != nil {
			t.Fatal(e)
		}
		if _, e = countMemoryJSON(context.Background(), path); e == nil {
			t.Fatal("invalid renderer", bad)
		}
	}
}

func TestMemoryURLSegmentsAcrossTinyWindows(t *testing.T) {
	old := memoryWindow
	memoryWindow = 5
	defer func() { memoryWindow = old }()
	ascii := "HTTPS://example.test/" + strings.Repeat("a", memoryStringSegment+17)
	wide := "http://wide.test/" + strings.Repeat("b", memoryStringSegment+29)
	image := append([]byte("prefix"+ascii+"\x00"), utf16LE([]byte(wide))...)
	m, e := scanMemoryContext(WithMemoryWorkspace(context.Background(), t.TempDir()), bytes.NewReader(image), nil)
	if e != nil {
		t.Fatal(e)
	}
	if m.Results.URLs != 2 {
		t.Fatalf("URL tokens %d", m.Results.URLs)
	}
	recovered := map[string]string{}
	starts := map[string]uint64{}
	if e := visitMemoryResults(context.Background(), m.Results, func(row MemoryResult) error {
		if row.Kind == "url" {
			if !row.Continuation {
				starts[row.Encoding] = row.Physical
			}
			recovered[row.Encoding] += row.Detail
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	if recovered["ascii"] != ascii || recovered["utf-16le"] != wide || starts["ascii"] != 6 || starts["utf-16le"] != uint64(7+len(ascii)) {
		t.Fatalf("URL reconstruction mismatch: %v", starts)
	}
}

func TestMemoryPluginOptionsAndPlatformDiscovery(t *testing.T) {
	d := t.TempDir()
	path := filepath.Join(d, "help")
	os.WriteFile(path, []byte("  --dump           Extract listed processes\n  --threads        Include threads\n  --pid [PID ...]  Filter processes\n"), 0600)
	flags, e := memoryBooleanOptions(path)
	if e != nil || strings.Join(flags, " ") != "--dump --threads" {
		t.Fatalf("%v %v", flags, e)
	}
	os.WriteFile(path, []byte("  banners.Banners  Global banners\n  linux.pslist.PsList  Processes\n  windows.pslist.PsList  Other platform\n"), 0600)
	plugins, e := memoryPluginsFromHelp(path, "linux")
	if e != nil || strings.Join(plugins, " ") != "banners.Banners linux.pslist.PsList" {
		t.Fatalf("%v %v", plugins, e)
	}
}

func TestMemoryKernelExportRejectsChangedOrUnrecordedReceipts(t *testing.T) {
	source := t.TempDir()
	record := filepath.Join(source, "memory-suite.json")
	os.WriteFile(record, []byte("{}\n"), 0600)
	sum, e := fileSHA256(record)
	if e != nil {
		t.Fatal(e)
	}
	suite := MemorySuite{Directory: "kernel", path: source, RecordSHA256: sum}
	a := Analysis{Memories: []MemoryAnalysis{{Kernel: &suite}}}
	if e := exportMemoryKernel(context.Background(), a, t.TempDir()); e != nil {
		t.Fatal(e)
	}
	os.WriteFile(record, []byte("changed"), 0600)
	if e := exportMemoryKernel(context.Background(), a, t.TempDir()); e == nil {
		t.Fatal("changed suite record accepted")
	}
	os.WriteFile(record, []byte("{}\n"), 0600)
	os.Mkdir(filepath.Join(source, "unrecorded"), 0700)
	os.WriteFile(filepath.Join(source, "unrecorded", "memory-suite.json"), []byte("{}\n"), 0600)
	if e := exportMemoryKernel(context.Background(), a, t.TempDir()); e == nil {
		t.Fatal("unrecorded nested receipt accepted")
	}
}

func TestMemoryUnavailableModulesRemainExplicit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "help")
	os.WriteFile(path, []byte("volatility3.plugins.linux.vmayarascan, volatility3.plugins.windows.hashdump,\nvolatility3.plugins.yarascan\n"), 0600)
	names, e := memoryUnavailablePlugins(path, "linux")
	if e != nil || strings.Join(names, " ") != "linux.vmayarascan yarascan" {
		t.Fatalf("%v %v", names, e)
	}
	a := Analysis{Memories: []MemoryAnalysis{{Kernel: &MemorySuite{Examinations: []MemoryExamination{{Status: "interpreted"}}, Unavailable: names}}}}
	found := false
	for _, c := range analysisCoverage(a) {
		if c.Stage == "memory_kernel" {
			found = true
			if c.Status != "partial" || c.Omitted != 2 {
				t.Fatal(c)
			}
		}
	}
	if !found {
		t.Fatal("missing kernel coverage")
	}
}
