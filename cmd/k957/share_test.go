package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestCLIShareWorkflow(t *testing.T) {
	d := t.TempDir()
	src := filepath.Join(d, "source")
	os.Mkdir(src, 0700)
	os.WriteFile(filepath.Join(src, "secret.jsonl"), []byte(`{"timestamp":"2001-02-03T04:05:06Z","user":"PrivateUserX","host":"PrivateHostX","src_ip":"192.0.2.19","message":"PrivateNoteX"}`), 0600)
	pkg := filepath.Join(d, "evidence.k957")
	if e := run([]string{"collect", "--root", src, "--out", pkg, "--case", "PrivateCaseX", "--operator", "PrivateActorX", "--scope", "PrivateScopeX"}); e != nil {
		t.Fatal(e)
	}
	before, _ := os.ReadFile(pkg)
	out := filepath.Join(d, "shared")
	if e := run([]string{"share", "--in", pkg, "--out", out}); e != nil {
		t.Fatal(e)
	}
	entries, _ := os.ReadDir(out)
	for _, f := range entries {
		b, _ := os.ReadFile(filepath.Join(out, f.Name()))
		for _, s := range []string{"Private", "192.0.2.19", "2001-02-03", "secret.jsonl"} {
			if bytes.Contains(b, []byte(s)) {
				t.Fatalf("leak in %s: %s", f.Name(), s)
			}
		}
	}
	after, _ := os.ReadFile(pkg)
	if !bytes.Equal(before, after) {
		t.Fatal("source changed")
	}
	policy := filepath.Join(d, "policy.json")
	os.WriteFile(policy, []byte(`{"schema":"k957-share-policy/1","keep":["users"]}`), 0600)
	kept := filepath.Join(d, "kept")
	if e := run([]string{"share", "--in", pkg, "--out", kept, "--policy", policy}); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(filepath.Join(kept, "shared.json"))
	if !bytes.Contains(b, []byte("PrivateUserX")) {
		t.Fatal("keep ignored")
	}
	for _, args := range [][]string{
		{"share", "--in", pkg, "--out", out},
		{"share", "--in", pkg, "--out", filepath.Join(d, "bad"), "--policy", "missing"},
		{"analyze", "--in", pkg, "--policy", policy},
		{"verify", "--in", pkg, "--policy", policy},
		{"review", "--analysis", filepath.Join(out, "shared.json"), "--finding", "F000001", "--decision", "confirmed", "--analyst", "A", "--note", "X", "--out", filepath.Join(d, "review")},
	} {
		if e := run(args); e == nil {
			t.Fatalf("accepted invalid workflow %v", args)
		}
	}
}
