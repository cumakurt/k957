package core

import (
	"bytes"
	"encoding/json"
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReportDocumentGroupsEscapesAndLimits(t *testing.T) {
	findings := make([]Finding, 4)
	for i := range findings {
		findings[i] = Finding{Rule: "marker", Description: "literal marker", Evidence: "E1", Source: "/var/log/auth.log", Line: i + 1, Excerpt: "ordinary line", Review: "unreviewed"}
	}
	findings[0].Excerpt = "<script>alert(1)</script>"
	findings[3].Excerpt = "UNIQUE-FOURTH-EXCERPT"
	findings = append(findings, Finding{Rule: "memory-rule", Description: "seen in an image", Evidence: "MEMORY", Source: "memory.lime", Excerpt: "image text", Review: "unreviewed"})
	a := Analysis{
		Version: Version, Run: "run", Created: time.Date(2026, 9, 29, 17, 55, 0, 0, time.UTC),
		Signature: "verified against supplied trusted key", EvidenceDigest: strings.Repeat("ab", 32),
		Manifest: Manifest{
			Case: "CASE", Host: "host", OS: "linux", Arch: "amd64", Operator: "operator",
			Scope: "selected files", Status: "complete",
			Started:  time.Date(2026, 9, 29, 17, 46, 8, 0, time.UTC),
			Finished: time.Date(2026, 9, 29, 17, 46, 10, 0, time.UTC),
			Items:    []Item{{ID: "E1", Source: "/var/log/auth.log", Kind: "file", Size: 12, SHA256: strings.Repeat("cd", 32)}},
		},
		Findings: findings,
		Notes:    []string{"Rules are literal matches.", "E000001: non UTF-8/binary text scan skipped"},
		Memories: []MemoryAnalysis{{
			Source: "memory.lime", Format: "lime", Bytes: 2048, KernelBanner: "linux version Literal notes",
			SHA256: strings.Repeat("ef", 32), Hits: []MemoryHit{{Rule: "memory-rule", Excerpt: "image text"}},
		}},
	}
	page, e := renderReportHTML(a)
	if e != nil {
		t.Fatal(e)
	}
	html := string(page)
	for _, want := range []string{
		"What was examined",
		"Literal matches",
		"does not match a Linux version line",
		"&lt;script&gt;alert(1)&lt;/script&gt;",
		"Rules are literal matches.",
		"1 file was skipped",
		"No examiner hash set was applied",
		"#fffef9",
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("missing %q", want)
		}
	}
	if strings.Contains(html, "<script>alert(1)</script>") {
		t.Fatal("unescaped excerpt")
	}
	if !strings.Contains(html, "window.k957Report") || strings.Contains(html, `"[{\"ID\"`) {
		t.Fatal("findings JSON was encoded twice")
	}
	if strings.Count(html, "UNIQUE-FOURTH-EXCERPT") != 1 {
		t.Fatalf("fourth sample leaked into the static document: %d", strings.Count(html, "UNIQUE-FOURTH-EXCERPT"))
	}
	if strings.Index(html, "memory-rule") > strings.Index(html, "marker") {
		t.Fatal("memory-backed group was not listed first")
	}
	empty := a
	empty.Timeline = nil
	empty.Findings = nil
	empty.Memories = nil
	page, e = renderReportHTML(empty)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Contains(page, []byte("No timeline rows were recorded.")) || !bytes.Contains(page, []byte("No literal matches were recorded.")) {
		t.Fatal(string(page))
	}
}

func TestRewriteExaminationReport(t *testing.T) {
	dir := os.Getenv("K957_REPORT_DIR")
	if dir == "" {
		t.Skip()
	}
	a, e := LoadAnalysis(filepath.Join(dir, "analysis.json"))
	if e != nil {
		t.Fatal(e)
	}
	page, e := renderReportHTML(a)
	if e != nil {
		t.Fatal(e)
	}
	if len(page) > 4<<20 {
		t.Fatalf("report is %d bytes", len(page))
	}
	for _, want := range []string{"What was examined", "Literal matches", a.Manifest.Case, "does not match a Linux version line"} {
		if !bytes.Contains(page, []byte(want)) {
			t.Fatalf("missing %q", want)
		}
	}
	if e = os.WriteFile(filepath.Join(dir, "report.html"), page, 0600); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(filepath.Join(dir, "shared", "shared.json"))
	if e != nil {
		t.Fatal(e)
	}
	var shared SharedReport
	if e = json.Unmarshal(raw, &shared); e != nil {
		t.Fatal(e)
	}
	tpl, e := template.New("shared").Funcs(template.FuncMap{"stamp": sharedTime, "endpoint": networkEndpoint}).Parse(sharedTemplate)
	if e != nil {
		t.Fatal(e)
	}
	var b bytes.Buffer
	if e = tpl.Execute(&b, shared); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(dir, "shared", "report.html"), b.Bytes(), 0600); e != nil {
		t.Fatal(e)
	}
}
