package main

import (
	"os"
	"path/filepath"
	"testing"
)

func withOutput(t *testing.T, stdout, stderr *os.File) func() {
	t.Helper()
	oldOut, oldErr := os.Stdout, os.Stderr
	if stdout != nil {
		os.Stdout = stdout
	}
	if stderr != nil {
		os.Stderr = stderr
	}
	return func() { os.Stdout, os.Stderr = oldOut, oldErr }
}

func discard(t *testing.T) *os.File {
	t.Helper()
	f, e := os.Create(filepath.Join(t.TempDir(), "discard"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func closedFile(t *testing.T) *os.File {
	t.Helper()
	f, e := os.Create(filepath.Join(t.TempDir(), "closed"))
	if e != nil {
		t.Fatal(e)
	}
	f.Close()
	return f
}

func stdinFrom(t *testing.T, text string) {
	t.Helper()
	r, w, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = w.Write([]byte(text)); e != nil {
		t.Fatal(e)
	}
	w.Close()
	old := os.Stdin
	os.Stdin = r
	t.Cleanup(func() {
		os.Stdin = old
		r.Close()
	})
}

func TestMainAndWizard(t *testing.T) {
	sink := discard(t)
	t.Cleanup(withOutput(t, sink, sink))
	oldArgs, oldExit := os.Args, exitProcess
	t.Cleanup(func() { os.Args, exitProcess = oldArgs, oldExit })
	code := 0
	exitProcess = func(c int) { code = c }
	os.Args = []string{"k957", "version"}
	main()
	if code != 0 {
		t.Fatal(code)
	}
	os.Args = []string{"k957", "not-a-command"}
	main()
	if code != 1 {
		t.Fatal(code)
	}
	if e := run(nil); e != nil {
		t.Fatal(e)
	}
	stdinFrom(t, "")
	if e := wizard(); e == nil {
		t.Fatal("expected wizard eof")
	}
	stdinFrom(t, "9\n")
	if e := wizard(); e == nil {
		t.Fatal("expected invalid wizard choice")
	}
	stdinFrom(t, "1\n")
	if e := wizard(); e == nil {
		t.Fatal("expected wizard prompt eof")
	}
	d := t.TempDir()
	src := filepath.Join(d, "src")
	os.Mkdir(src, 0700)
	os.WriteFile(filepath.Join(src, "a.txt"), []byte("2026-09-29T00:00:00Z note\n"), 0600)
	out := filepath.Join(d, "case.k957")
	stdinFrom(t, "1\n"+src+"\n"+out+"\nCASE\nOp\nScope\n")
	if e := wizard(); e != nil {
		t.Fatal(e)
	}
	stdinFrom(t, "2\n"+filepath.Join(d, "missing.k957")+"\n"+filepath.Join(d, "report")+"\n")
	if e := wizard(); e == nil {
		t.Fatal("expected analyze failure")
	}
	stdinFrom(t, "2\n"+out+"\n")
	if e := wizard(); e == nil {
		t.Fatal("expected analyze output prompt eof")
	}
}

func TestCLIFlagAndStoreEdges(t *testing.T) {
	sink := discard(t)
	restore := withOutput(t, sink, sink)
	defer restore()
	d := t.TempDir()
	src := filepath.Join(d, "src")
	os.Mkdir(src, 0700)
	os.WriteFile(filepath.Join(src, "a.txt"), []byte("2026-09-29T00:00:00Z note\n"), 0600)
	os.Symlink("a.txt", filepath.Join(src, "link"))
	for _, args := range [][]string{
		{"keygen", "-h"},
		{"encryption-key", "-h"},
		{"seal", "-h"},
		{"preflight", "-h"},
		{"work-status", "-h"},
		{"review", "-h"},
		{"verify", "-h"},
		{"collect", "--resume", "--root", src, "--out", filepath.Join(d, "x"), "--case", "C", "--operator", "O", "--scope", "S"},
		{"preflight", "--resume", "--encrypted", "--root", src, "--out", filepath.Join(d, "p"), "--work", filepath.Join(d, "w")},
		{"preflight", "--encryption-key", filepath.Join(d, "k"), "--root", src, "--out", filepath.Join(d, "p")},
		{"work-status", "--work", filepath.Join(d, "missing")},
		{"share"},
		{"verify", "--reviews", filepath.Join(d, "r")},
		{"analyze", "--review-key", filepath.Join(d, "k"), "--in", filepath.Join(d, "missing")},
		{"analyze", "--rules", filepath.Join(d, "missing-rules"), "--in", filepath.Join(src, "a.txt"), "--out", filepath.Join(d, "rep")},
		{"review", "--analysis", filepath.Join(d, "missing"), "--finding", "x", "--decision", "confirmed", "--analyst", "A", "--note", "n", "--out", filepath.Join(d, "rev")},
		{"custody", "extra"},
		{"custody", "--in", filepath.Join(d, "missing"), "--trust", filepath.Join(d, "missing-trust")},
		{"custody", "--at", "not-a-time"},
		{"custody-verify", "--ledger", filepath.Join(d, "missing-ledger")},
	} {
		e := run(args)
		if args[len(args)-1] == "-h" {
			if e != nil {
				t.Fatalf("%v: %v", args, e)
			}
			continue
		}
		if e == nil {
			t.Fatalf("expected error: %v", args)
		}
	}
	if e := run([]string{"preflight", "--root", src, "--out", filepath.Join(d, "planned.k957")}); e != nil {
		t.Fatal(e)
	}
	restoreOut := withOutput(t, closedFile(t), nil)
	if e := run([]string{"preflight", "--root", src, "--out", filepath.Join(d, "planned2.k957")}); e == nil {
		t.Fatal("expected encode error")
	}
	restoreOut()
	out := filepath.Join(d, "partial.k957")
	if e := run([]string{"collect", "--root", src, "--out", out, "--case", "C", "--operator", "O", "--scope", "S"}); e == nil {
		t.Fatal("expected partial collection")
	}
	if e := run([]string{"collect", "--root", src, "--out", filepath.Join(d, "checked.k957"), "--case", "C", "--operator", "O", "--scope", "S", "--check-space", "--max-files", "1"}); e == nil {
		t.Fatal("expected checked partial or budget")
	}
	key := filepath.Join(d, "aes")
	if e := run([]string{"encryption-key", "--out", key}); e != nil {
		t.Fatal(e)
	}
	restoreOut = withOutput(t, closedFile(t), nil)
	if e := run([]string{"collect", "--root", src, "--work", filepath.Join(d, "work"), "--out", filepath.Join(d, "enc"), "--case", "C", "--operator", "O", "--scope", "S", "--encryption-key", key, "--max-files", "100"}); e == nil {
		t.Fatal("expected encrypted encode error")
	}
	restoreOut()
	store := filepath.Join(d, "store")
	os.MkdirAll(filepath.Join(store, "host", "stamp"), 0700)
	if e := run([]string{"verify", "--store", store}); e == nil {
		t.Fatal("expected store verify failure")
	}
	if e := run([]string{"analyze", "--store", store}); e == nil {
		t.Fatal("expected store analyze failure")
	}
	var tool stringList
	if e := tool.Set("{output}"); e != nil || tool.String() != "{output}" {
		t.Fatal(e, tool.String())
	}
	if e := runFullCollect([]string{"-h"}); e != nil {
		t.Fatal(e)
	}
	if e := runFullCollect([]string{"--system=false", "--artifacts=false", "--memory=false"}); e == nil {
		t.Fatal("expected empty full collection")
	}
	restoreOut = withOutput(t, closedFile(t), nil)
	if e := runFullCollect([]string{"--system=false", "--artifacts=false", "--memory=false", "--root", src, "--output-dir", filepath.Join(d, "full")}); e == nil {
		t.Fatal("expected full encode error")
	}
	restoreOut()
}
