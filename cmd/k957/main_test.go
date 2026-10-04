package main

import (
	"k957/internal/core"
	"os"
	"path/filepath"
	"testing"
)

func TestCLIWorkflow(t *testing.T) {
	d := t.TempDir()
	src := filepath.Join(d, "src")
	os.Mkdir(src, 0700)
	os.WriteFile(filepath.Join(src, "log.txt"), []byte("2026-09-27T00:00:00Z hello"), 0600)
	pkg := filepath.Join(d, "evidence.k957")
	prefix := filepath.Join(d, "sign")
	key := filepath.Join(d, "aes.key")
	for _, args := range [][]string{{"version"}, {"help"}, {"keygen", "--out", prefix}, {"encryption-key", "--out", key}, {"collect", "--root", src, "--out", pkg, "--case", "T", "--operator", "T", "--scope", "Test", "--sign-key", prefix + ".key"}, {"verify", "--in", pkg, "--trusted-key", prefix + ".pub"}, {"analyze", "--in", pkg, "--out", filepath.Join(d, "report")}, {"seal", "--in", pkg, "--out", pkg + ".enc", "--key", key}, {"unseal", "--in", pkg + ".enc", "--out", pkg + ".restored", "--key", key}, {"verify", "--in", pkg + ".restored"}} {
		if e := run(args); e != nil {
			t.Fatalf("%v: %v", args, e)
		}
	}
}
func TestCLIErrors(t *testing.T) {
	// No-argument collect deliberately starts live full acquisition. Exercise
	// invalid explicit options here so error tests never collect the test host.
	for _, args := range [][]string{{"unknown"}, {"keygen"}, {"encryption-key"}, {"collect", "--out", filepath.Join(t.TempDir(), "invalid.k957")}, {"verify", "--in", "missing"}, {"analyze", "--in", "missing"}, {"collect", "--bad-flag"}} {
		if e := run(args); e == nil {
			t.Fatalf("expected error: %v", args)
		}
	}
}
func TestCLIResumable(t *testing.T) {
	d := t.TempDir()
	root := filepath.Join(d, "source")
	os.Mkdir(root, 0700)
	os.WriteFile(filepath.Join(root, "log"), []byte("2026-09-27T00:00:00Z test"), 0600)
	work := filepath.Join(d, "work")
	base := []string{"collect", "--root", root, "--work", work, "--case", "T", "--operator", "T", "--scope", "T"}
	args := append(append([]string{}, base...), "--out", filepath.Join(d, "one"))
	if e := run(args); e != nil {
		t.Fatal(e)
	}
	if e := run([]string{"work-status", "--work", work, "--verify-parts"}); e != nil {
		t.Fatal(e)
	}
	args = append(append([]string{}, base...), "--out", filepath.Join(d, "two"), "--resume")
	if e := run(args); e != nil {
		t.Fatal(e)
	}
}
func TestCLIReview(t *testing.T) {
	d := t.TempDir()
	src := filepath.Join(d, "src")
	os.Mkdir(src, 0700)
	os.WriteFile(filepath.Join(src, "log"), []byte("suspicious test"), 0600)
	rules := filepath.Join(d, "rules.json")
	os.WriteFile(rules, []byte(`[{"id":"R","contains":"test"}]`), 0600)
	pkg := filepath.Join(d, "case")
	if e := run([]string{"collect", "--root", src, "--out", pkg, "--case", "T", "--operator", "T", "--scope", "T"}); e != nil {
		t.Fatal(e)
	}
	report := filepath.Join(d, "report")
	if e := run([]string{"analyze", "--in", pkg, "--rules", rules, "--out", report}); e != nil {
		t.Fatal(e)
	}
	a, e := core.LoadAnalysis(filepath.Join(report, "analysis.json"))
	if e != nil {
		t.Fatal(e)
	}
	ledger := filepath.Join(d, "reviews.json")
	if e = run([]string{"review", "--analysis", filepath.Join(report, "analysis.json"), "--finding", a.Findings[0].ID, "--decision", "rejected", "--analyst", "Tester", "--note", "Synthetic", "--out", ledger}); e != nil {
		t.Fatal(e)
	}
	if e = run([]string{"analyze", "--in", pkg, "--rules", rules, "--reviews", ledger, "--out", filepath.Join(d, "reviewed")}); e != nil {
		t.Fatal(e)
	}
}
func TestCLIEncryptedCollection(t *testing.T) {
	d := t.TempDir()
	src := filepath.Join(d, "src")
	os.Mkdir(src, 0700)
	os.WriteFile(filepath.Join(src, "file"), []byte("private fixture"), 0600)
	key := filepath.Join(d, "key")
	if e := run([]string{"encryption-key", "--out", key}); e != nil {
		t.Fatal(e)
	}
	out := filepath.Join(d, "encrypted")
	work := filepath.Join(d, "work")
	if e := run([]string{"collect", "--root", src, "--work", work, "--out", out, "--case", "T", "--operator", "T", "--scope", "T", "--encryption-key", key}); e != nil {
		t.Fatal(e)
	}
	if e := run([]string{"work-status", "--work", work, "--verify-parts", "--encryption-key", key}); e != nil {
		t.Fatal(e)
	}
	plain := filepath.Join(d, "plain")
	if e := run([]string{"unseal", "--in", out, "--out", plain, "--key", key}); e != nil {
		t.Fatal(e)
	}
	if e := run([]string{"verify", "--in", plain}); e != nil {
		t.Fatal(e)
	}
}

func TestCLIFullMode(t *testing.T) {
	d := t.TempDir()
	t.Chdir(d)
	src := filepath.Join(d, "src")
	if e := os.Mkdir(src, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(src, "auth.log"), []byte("2026-09-29T00:00:00Z failed password for root\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := run([]string{"collect", "-h"}); e != nil {
		t.Fatal(e)
	}
	if e := run([]string{"verify"}); e == nil {
		t.Fatal("expected missing store")
	}
	if e := run([]string{"analyze"}); e == nil {
		t.Fatal("expected missing store")
	}
	if e := run([]string{"collect", "--full", "--root", src, "--output-dir", "output", "--system=false", "--artifacts=false", "--memory=false", "--case", "T", "--operator", "T", "--scope", "T"}); e != nil {
		t.Fatal(e)
	}
	if e := run([]string{"verify"}); e != nil {
		t.Fatal(e)
	}
	if e := run([]string{"analyze"}); e != nil {
		t.Fatal(e)
	}
	if e := run([]string{"verify", "--in", "missing", "--store", "output"}); e == nil {
		t.Fatal("expected mutual exclusion")
	}
}

func TestCLIPreflight(t *testing.T) {
	d := t.TempDir()
	src := filepath.Join(d, "src")
	if e := os.Mkdir(src, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(src, "file"), []byte("fixture"), 0600); e != nil {
		t.Fatal(e)
	}
	out := filepath.Join(src, "must-not-exist")
	work := filepath.Join(d, "work")
	// Overlap always blocks, independently of available disk capacity.
	for _, args := range [][]string{
		{"preflight", "--root", src, "--out", out, "--work", work},
		{"collect", "--root", src, "--out", out, "--work", work, "--case", "T", "--operator", "T", "--scope", "T", "--check-space"},
		{"collect", "--root", src, "--out", out, "--check-space", "--resume"},
		{"preflight", "--bad-flag"}, {"preflight"},
		{"preflight", "--root", src, "--out", out, "--encryption-key", "unused"},
		{"preflight", "--resume", "--encrypted", "--root", src, "--out", out, "--work", work},
		{"collect", "--check-space", "--system"},
	} {
		if e := run(args); e == nil {
			t.Fatalf("expected error: %v", args)
		}
	}
	for _, p := range []string{out, work} {
		if _, e := os.Lstat(p); !os.IsNotExist(e) {
			t.Fatalf("unexpected destination %s: %v", p, e)
		}
	}
}
