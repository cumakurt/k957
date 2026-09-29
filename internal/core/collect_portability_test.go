package core

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

// Exercise collection through WalkDir on real files. In particular, Windows
// directory-entry metadata must not cause unchanged files to be rejected by
// the source identity check.
func TestCollectNestedUnicodePaths(t *testing.T) {
	d := t.TempDir()
	root := filepath.Join(d, "Source with spaces", "İnceleme")
	if err := os.MkdirAll(filepath.Join(root, "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		"olay günlüğü.jsonl":                     []byte("2026-09-28T12:00:00Z synthetic event\n"),
		filepath.Join("nested", "MixedCase.bin"): {0, 1, 2, 3, 255},
		"empty":                                  {},
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(root, name), content, 0600); err != nil {
			t.Fatal(err)
		}
	}
	o := Options{Root: root, Out: filepath.Join(d, "collected.k957"), Case: "PORTABLE", Operator: "Tester", Scope: "Synthetic", MaxFile: 1 << 20, MaxTotal: 8 << 20, MaxFiles: 10}
	m, err := Collect(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if m.Status != "complete" || len(m.Items) != len(files) || len(m.Issues) != 0 {
		t.Fatalf("unchanged files were not collected: %+v", m)
	}
	p, err := Open(o.Out, "")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Zip.Close()
	canonicalRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range p.Manifest.Items {
		rel, err := filepath.Rel(canonicalRoot, item.Source)
		if err != nil {
			t.Fatal(err)
		}
		want, ok := files[rel]
		if !ok {
			t.Fatalf("unexpected evidence path: %s", item.Source)
		}
		got, err := readEntry(p.Files[item.Object], 1<<20)
		if err != nil || !bytes.Equal(got, want) || item.Changed {
			t.Fatalf("incorrect acquisition of %s: %v", rel, err)
		}
	}
}
