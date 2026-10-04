package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFindingCapPreservesRemainingEvidence(t *testing.T) {
	d, o := fixture(t, false)
	if err := os.WriteFile(filepath.Join(o.Root, "auth.log"), []byte(strings.Repeat("marker\n", findingLimit+1)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(o.Root, "z-last.log"), []byte("2026-09-30T10:00:00Z last event\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Collect(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	p, err := Open(o.Out, "")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Zip.Close()
	a := Analyze(p, []Rule{{ID: "marker", Contains: "marker"}})
	if len(a.Findings) != findingLimit || !a.FindingsTruncated || len(a.FileTypes) != 2 {
		t.Fatalf("findings=%d truncated=%v classified=%d", len(a.Findings), a.FindingsTruncated, len(a.FileTypes))
	}
	found := false
	for _, ev := range a.Timeline {
		if ev.Type == "log_timestamp" && strings.HasSuffix(ev.Source, "z-last.log") {
			found = true
		}
	}
	if !found {
		t.Fatal("finding cap stopped later log parsing")
	}
	if err := Export(a, filepath.Join(d, "report")); err != nil {
		t.Fatal(err)
	}
	page, err := os.ReadFile(filepath.Join(d, "report", "report.html"))
	if err != nil || !bytes.Contains(page, []byte("Counts are lower bounds")) {
		t.Fatalf("missing coverage warning: %v", err)
	}
	policy, err := LoadSharePolicy("")
	if err != nil {
		t.Fatal(err)
	}
	shared, err := BuildSharedReport(a, policy)
	if err != nil || !shared.FindingsTruncated {
		t.Fatalf("sharing lost truncation: %v", err)
	}
}

func TestAnalysisCancellationCannotPublish(t *testing.T) {
	d, o := fixture(t, false)
	if _, err := Collect(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	p, err := Open(o.Out, "")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Zip.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	a := AnalyzeContext(ctx, p, nil)
	if !a.Canceled || len(a.FileTypes) != 0 {
		t.Fatal("canceled analysis examined evidence")
	}
	out := filepath.Join(d, "canceled-report")
	if err := Export(a, out); err == nil {
		t.Fatal("canceled report exported")
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("canceled export created a directory")
	}
	policy, err := LoadSharePolicy("")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildSharedReport(a, policy); err == nil {
		t.Fatal("canceled analysis shared")
	}
	if _, err := OpenContext(ctx, o.Out, ""); !errors.Is(err, context.Canceled) {
		t.Fatalf("verification ignored cancellation: %v", err)
	}
}

func TestStrictEvidenceAndRuleJSON(t *testing.T) {
	d, o := fixture(t, false)
	if _, err := Collect(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(d, "duplicate.k957")
	rewrite(t, o.Out, bad, func(name string, b []byte) []byte {
		if name == "manifest.json" {
			return bytes.Replace(b, []byte(`"status": "complete"`), []byte(`"status": "partial", "status": "complete"`), 1)
		}
		return b
	}, false)
	if p, err := Open(bad, ""); err == nil {
		p.Zip.Close()
		t.Fatal("duplicate manifest key accepted")
	}
	for _, content := range []string{
		`[{"id":"a","id":"b","contains":"marker"}]`,
		`[{"id":"a","contains":"marker","unexpected":true}]`,
	} {
		path := filepath.Join(d, ID()+".json")
		if err := WriteNew(path, []byte(content)); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadRules(path); err == nil {
			t.Fatalf("ambiguous rules accepted: %s", content)
		}
	}
}

func TestSystemdDeclarativeUserAndCommandReset(t *testing.T) {
	it := Item{ID: "E1", Source: "demo.service"}
	text := "[Unit]\nExecStart=/wrong-section\n[Service]\nExecStart=/obsolete\nExecStart=\nExecStart=/actual\nUser=first\nUser=final\n[Install]\nUser=wrong-section\n"
	events, summary, _ := parseSystemdUnit([]byte(text), it, 10)
	if len(events) != 1 || events[0].Detail != "/actual" || events[0].User != "final" || events[0].Line != 6 || summary.Parsed != 1 {
		t.Fatalf("events=%+v summary=%+v", events, summary)
	}
}

func TestHashSetNoMatchAndFindingCoverage(t *testing.T) {
	_, o := fixture(t, false)
	if _, err := Collect(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	p, err := Open(o.Out, "")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Zip.Close()
	a := Analyze(p, nil)
	set := &HashSet{byHash: map[string]hashEntry{strings.Repeat("a", 64): {Verdict: "known-bad"}}}
	ApplyHashSet(&a, set)
	page, err := renderReportHTML(a)
	if err != nil || !bytes.Contains(page, []byte("Examiner hash set applied: 1 entries; no matching evidence objects")) {
		t.Fatalf("no-match set not reported: %v", err)
	}
	set = &HashSet{byHash: map[string]hashEntry{a.Manifest.Items[0].SHA256: {Verdict: "known-bad"}}}
	a.Findings = make([]Finding, findingLimit)
	ApplyHashSet(&a, set)
	if !a.FindingsTruncated || a.HashSet.Matched != 1 {
		t.Fatal("omitted hash finding was silent")
	}
}

func TestCollectionRejectsExternalEvidenceAndSymlinkArtifact(t *testing.T) {
	d := t.TempDir()
	rec := CollectionRecord{Schema: CollectionSchema, Version: Version, ID: "id", Case: "case", Status: "complete", Evidence: "../external.k957"}
	if err := WriteNew(filepath.Join(d, "collection.json"), JSON(rec)); err != nil {
		t.Fatal(err)
	}
	v := verifyCollection(d, "")
	if v.Status != "failed" || !strings.Contains(strings.Join(v.Errors, " "), "invalid evidence path") {
		t.Fatalf("%+v", v)
	}
	path := filepath.Join(t.TempDir(), "external")
	if err := WriteNew(path, []byte("external")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path, filepath.Join(d, "link")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	sum := sha256.Sum256([]byte("external"))
	if err := checkArtifact(d, CollectionArtifact{Name: "link", Size: 8, SHA256: hex.EncodeToString(sum[:])}); err == nil {
		t.Fatal("artifact outside collection accepted through symlink")
	}
}

func TestUnparsedObjectCoverageIsVisible(t *testing.T) {
	d, o := fixture(t, false)
	if err := os.WriteFile(filepath.Join(o.Root, "binary.bin"), []byte{0, 1, 2}, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Collect(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	p, err := Open(o.Out, "")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Zip.Close()
	a := Analyze(p, nil)
	if len(a.ParseSummaries) != 2 {
		t.Fatal("missing per-object coverage")
	}
	if err := Export(a, filepath.Join(d, "report")); err != nil {
		t.Fatal(err)
	}
	page, err := os.ReadFile(filepath.Join(d, "report", "report.html"))
	if err != nil || !bytes.Contains(page, []byte("unsupported_text_encoding_or_binary")) {
		t.Fatalf("missing skip reason: %v", err)
	}
}

func TestPersistenceXMLPreservesFragmentedValues(t *testing.T) {
	it := Item{ID: "E1", Source: "task.xml"}
	task := `<Task xmlns="` + taskNamespace + `"><Principals><Principal><UserId>DOMAIN\<![CDATA[Analyst]]></UserId></Principal></Principals><Actions><Exec><Command>/usr/<![CDATA[bin/]]>tool</Command><Arguments>--name a&amp;b</Arguments></Exec></Actions></Task>`
	events, summary, _ := parseScheduledTask([]byte(task), it, 10)
	if summary.Error != "" || len(events) != 1 || events[0].Detail != "/usr/bin/tool --name a&b" || events[0].User != `DOMAIN\Analyst` {
		t.Fatalf("fragmented task: %+v %+v", events, summary)
	}
	spoof := `<!-- ` + taskNamespace + ` --><Other><Exec><Command>spoof</Command></Exec></Other>`
	events, summary, _ = parseScheduledTask([]byte(spoof), it, 10)
	if len(events) != 0 || summary.Error == "" {
		t.Fatal("unrelated XML interpreted as a scheduled task")
	}
	plist := `<plist><dict><key>Label</key><string>com.<![CDATA[example]]>.agent</string><key>ProgramArguments</key><array><string>/usr/<![CDATA[bin/]]>tool</string><string>a&amp;b</string></array></dict></plist>`
	events, summary, _ = parseLaunchdPlist([]byte(plist), it, 10)
	if summary.Error != "" || len(events) != 1 || events[0].Detail != "com.example.agent: /usr/bin/tool a&b" {
		t.Fatalf("fragmented plist: %+v %+v", events, summary)
	}
}

func TestCaseTimelineOrdersFractionalSeconds(t *testing.T) {
	d, o := fixture(t, false)
	whole := time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC)
	for name, when := range map[string]time.Time{"auth.log": whole, "fraction.log": whole.Add(500 * time.Millisecond)} {
		path := filepath.Join(o.Root, name)
		if err := os.WriteFile(path, []byte("synthetic"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, when, when); err != nil {
			t.Fatal(err)
		}
	}
	base := filepath.Join(d, "output")
	if _, err := CollectFull(context.Background(), FullOptions{OutputDir: base, Root: o.Root, MaxFile: 1024, MaxTotal: 2048, MaxFiles: 10}); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(d, "dossier")
	if _, err := BuildCase(context.Background(), base, out, "", nil); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(filepath.Join(out, "timeline.csv"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	var previous time.Time
	for _, row := range rows[1:] {
		stamp, err := time.Parse(time.RFC3339Nano, row[0])
		if err != nil {
			t.Fatal(err)
		}
		if stamp.Before(previous) {
			t.Fatalf("timeline reversed: %s before %s", stamp, previous)
		}
		previous = stamp
	}
}

func TestFailedCollectionSignatureIsNeverReportedVerified(t *testing.T) {
	d, o := fixture(t, false)
	rec, err := CollectFull(context.Background(), FullOptions{OutputDir: filepath.Join(d, "output"), Root: o.Root, MaxFile: 1024, MaxTotal: 2048, MaxFiles: 10})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(rec.Directory, "collection.sig")
	sig, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sig[0] ^= 1
	if err := os.WriteFile(path, sig, 0600); err != nil {
		t.Fatal(err)
	}
	v := verifyCollection(rec.Directory, "")
	if v.Status != "failed" || v.Signature != "failed" {
		t.Fatalf("invalid signature described as verified: %+v", v)
	}
}

func TestReportRetainsPCAPNGContextAndErrors(t *testing.T) {
	a := Analysis{CaptureSummaries: []CaptureSummary{{Evidence: "E1", Format: "PCAPNG", Sections: 2, Interfaces: make([]CaptureInterface, 4), Limited: true, Error: "truncated block"}}, NetworkFlows: []NetworkFlow{{Evidence: "E1", CaptureContext: CaptureContext{Section: 2, InterfaceID: 0}}}}
	page, err := renderReportHTML(a)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Section 2 / Interface 0", "Sections: 2 / Interfaces: 4", "truncated block", "Limited"} {
		if !bytes.Contains(page, []byte(want)) {
			t.Fatalf("missing capture context %q", want)
		}
	}
}
