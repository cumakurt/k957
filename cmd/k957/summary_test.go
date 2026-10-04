package main

import (
	"bytes"
	"encoding/json"
	"k957/internal/core"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCasePipedOutputIsSingleJSONValue(t *testing.T) {
	dir := t.TempDir()
	stdout, err := os.Create(filepath.Join(dir, "stdout"))
	if err != nil {
		t.Fatal(err)
	}
	defer stdout.Close()
	stderr, err := os.Create(filepath.Join(dir, "stderr"))
	if err != nil {
		t.Fatal(err)
	}
	defer stderr.Close()
	restore := withOutput(t, stdout, stderr)
	defer restore()
	if err = emitCase(core.CaseDossier{Directory: dir, Items: 12, Verified: 1}); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(stdout.Name())
	if err != nil {
		t.Fatal(err)
	}
	var summary map[string]any
	if err = json.Unmarshal(body, &summary); err != nil || summary["items"] != float64(12) {
		t.Fatalf("piped case output is not JSON: %q: %v", body, err)
	}
	message, err := os.ReadFile(stderr.Name())
	if err != nil || !strings.Contains(string(message), filepath.Join(dir, "report.html")) {
		t.Fatal("case navigation hint missing from stderr", err)
	}
}

func TestCollectionSummaryIsGrouped(t *testing.T) {
	var buf bytes.Buffer
	rec := core.CollectionRecord{
		Status: "complete", Host: "MacBookPro", OS: "linux", Arch: "amd64", Privileged: true,
		Case: "AUTO-MacBookPro-20260929T165932Z", Operator: "root", GeneratedKey: true,
		Directory: "/case/out", Fingerprint: "e45e5603b13741fc9fc055de513d4a7a1e61ed4b2e6273fdac74bb5723d49a12",
		Evidence: "evidence.k957",
		Started:  time.Date(2026, 9, 29, 16, 59, 32, 0, time.UTC),
		Finished: time.Date(2026, 9, 29, 17, 2, 15, 0, time.UTC),
		Memory: &core.MemoryRecord{
			Status: "complete", Bytes: 33679503360, Format: "lime",
			SHA256: "7b7b085126c1513433a3e548635fa6557e1fe8c7b8ce8d79be8b4204a0db0dbc",
		},
		Artifacts: []core.CollectionArtifact{{Name: "evidence.k957", Size: 36119883}},
		Absent:    []string{"/root/.bash_history", "/home/eggs/.zsh_history"},
		Notes:     []string{"Skipped non-regular profile entries: /etc/cron.daily/brave-browser: symlink or non-regular file skipped"},
	}
	writeCollectionSummary(&buf, rec)
	text := buf.String()
	for _, want := range []string{"Collection", "Output", "Acquired", "Review", "complete", "MacBookPro", "privileged", rec.Fingerprint, "31.4 GiB", "lime", "7b7b085126c15134...", "34.4 MiB", "2 paths were not present", "none", "collection.json", "private key discarded"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q\n%s", want, text)
		}
	}
	for _, hidden := range []string{"Skipped non-regular", "/root/.bash_history", "unmapped", rec.Memory.SHA256} {
		if strings.Contains(text, hidden) {
			t.Fatalf("summary dumped %q\n%s", hidden, text)
		}
	}
	if strings.Contains(text, "\x1b") {
		t.Fatal("a non-terminal summary must stay plain")
	}
}

func TestStoreSummariesAreGrouped(t *testing.T) {
	okDir := "/store/MacBookPro/20260929T165932Z"
	badDir := "/store/MacBookPro/20260929T163918Z"
	var verify bytes.Buffer
	writeStoreVerificationSummary(&verify, core.StoreVerification{
		Root: "output", Verified: 1, Failed: 1,
		Collections: []core.CollectionVerification{
			{Directory: badDir, Status: "failed", Signature: "absent", Errors: []string{
				"collection record: open " + badDir + "/collection.json: no such file or directory",
				"second problem",
				"third problem",
			}},
			{Directory: okDir, Status: "verified", Signature: "verified against embedded key; not an external trust anchor", CollectionStatus: "complete", Evidence: "evidence.k957", Memory: "memory.lime"},
		},
	})
	text := verify.String()
	for _, want := range []string{"Verification", "Collections", "1 verified", "1 failed", badDir, okDir, "signature absent", "embedded key; not an external trust anchor", "complete  evidence.k957  memory.lime", "./collection.json", "1 more errors"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q\n%s", want, text)
		}
	}
	if strings.Count(text, badDir) != 1 {
		t.Fatalf("failed path repeated\n%s", text)
	}
	if strings.Contains(text, "\x1b") {
		t.Fatal("a non-terminal summary must stay plain")
	}

	var analysis bytes.Buffer
	writeStoreAnalysisSummary(&analysis, core.StoreAnalysis{
		Root: "output", Analyzed: 1, Failed: 1,
		Collections: []core.CollectionAnalysis{
			{Directory: badDir, Status: "failed", Errors: []string{"open " + badDir + "/collection.json: no such file or directory"}},
			{Directory: okDir, Status: "analyzed", Report: okDir + "/reports/stamp", Findings: 4, MemoryHits: 2},
		},
	})
	atext := analysis.String()
	for _, want := range []string{"Analysis", "1 analyzed", "1 failed", "findings 4  memory hits 2", "report.html", "./collection.json"} {
		if !strings.Contains(atext, want) {
			t.Fatalf("missing %q\n%s", want, atext)
		}
	}

	var dossier bytes.Buffer
	writeCaseSummary(&dossier, core.CaseDossier{
		Directory: "/exam/stamp", Verified: 1, Failed: 1, Items: 12,
		Duplicates:  []core.CaseDuplicate{{SHA256: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}},
		HashMatches: []core.HashMatch{{SHA256: "hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh"}},
		Mismatches:  []core.FileIdentity{{Source: "hidden-mismatch-path"}},
		Failures:    []core.CollectionVerification{{Directory: badDir, Status: "failed", Signature: "absent", Errors: []string{"collection record missing"}}},
	})
	ctext := dossier.String()
	for _, want := range []string{"Case", filepath.Join("/exam/stamp", "report.html"), "1 verified", "1 failed", "Failures", badDir, "collection record missing"} {
		if !strings.Contains(ctext, want) {
			t.Fatalf("missing %q\n%s", want, ctext)
		}
	}
	for _, hidden := range []string{"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", "hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh", "hidden-mismatch-path"} {
		if strings.Contains(ctext, hidden) {
			t.Fatalf("case summary dumped %q\n%s", hidden, ctext)
		}
	}

	var pkg bytes.Buffer
	writePackageVerificationSummary(&pkg, "/tmp/evidence.k957", "verified against supplied trusted key", "complete", 3, 0)
	ptext := pkg.String()
	for _, want := range []string{"Package", "/tmp/evidence.k957", "verified", "supplied trusted key", "complete", "none"} {
		if !strings.Contains(ptext, want) {
			t.Fatalf("missing %q\n%s", want, ptext)
		}
	}
}
