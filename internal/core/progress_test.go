package core

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestProgressReporter(t *testing.T) {
	if progressEnabled(nil) || progressEnabled(context.Background()) {
		t.Fatal("expected no reporter")
	}
	ReportProgress(nil, Progress{Phase: "files"})
	var got []Progress
	ctx := WithProgress(context.Background(), func(p Progress) { got = append(got, p) })
	if !progressEnabled(ctx) {
		t.Fatal("expected reporter")
	}
	if WithProgress(nil, func(Progress) {}) != nil {
		t.Fatal("nil context")
	}
	d := t.TempDir()
	src := filepath.Join(d, "src")
	if e := os.Mkdir(src, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(src, "note.txt"), []byte("note"), 0600); e != nil {
		t.Fatal(e)
	}
	out := filepath.Join(d, "evidence.k957")
	if _, e := Collect(ctx, Options{Root: src, Out: out, Case: "T", Operator: "T", Scope: "T", MaxFile: 1 << 20, MaxTotal: 1 << 20, MaxFiles: 10}); e != nil {
		t.Fatal(e)
	}
	sawFile := false
	sawPackage := false
	for _, p := range got {
		if p.Phase == "files" && p.Detail != "" && p.Bytes >= 0 {
			sawFile = true
		}
		if p.Phase == "package" {
			sawPackage = true
		}
	}
	if !sawFile || !sawPackage {
		t.Fatalf("progress %#v", got)
	}
}
