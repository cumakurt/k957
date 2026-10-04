package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"k957/internal/core"
	"os"
	"path/filepath"
	"testing"
)

func TestHashSetFindingCanBeReviewedOnReanalysis(t *testing.T) {
	d := t.TempDir()
	src := filepath.Join(d, "src")
	if err := os.Mkdir(src, 0700); err != nil {
		t.Fatal(err)
	}
	payload := []byte("synthetic hash-set evidence")
	if err := os.WriteFile(filepath.Join(src, "file"), payload, 0600); err != nil {
		t.Fatal(err)
	}
	pkg := filepath.Join(d, "evidence.k957")
	if _, err := core.Collect(context.Background(), core.Options{Root: src, Out: pkg, Case: "T", Operator: "T", Scope: "synthetic", MaxFile: 1024, MaxTotal: 1024, MaxFiles: 10}); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	set := filepath.Join(d, "hashset.txt")
	if err := core.WriteNew(set, []byte(hex.EncodeToString(sum[:])+" fixture\n")); err != nil {
		t.Fatal(err)
	}
	report := filepath.Join(d, "report")
	if err := run([]string{"analyze", "--in", pkg, "--hash-set", set, "--out", report}); err != nil {
		t.Fatal(err)
	}
	a, err := core.LoadAnalysis(filepath.Join(report, "analysis.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Findings) != 1 {
		t.Fatalf("findings: %+v", a.Findings)
	}
	ledger := filepath.Join(d, "ledger.json")
	if err = run([]string{"review", "--analysis", filepath.Join(report, "analysis.json"), "--finding", a.Findings[0].ID, "--decision", "rejected", "--analyst", "Tester", "--note", "Synthetic fixture", "--out", ledger}); err != nil {
		t.Fatal(err)
	}
	reviewed := filepath.Join(d, "reviewed")
	if err = run([]string{"analyze", "--in", pkg, "--hash-set", set, "--reviews", ledger, "--out", reviewed}); err != nil {
		t.Fatal(err)
	}
	result, err := core.LoadAnalysis(filepath.Join(reviewed, "analysis.json"))
	if err != nil {
		t.Fatal(err)
	}
	if result.Findings[0].Review != "rejected" {
		t.Fatal("hash-set review was not retained")
	}
}
