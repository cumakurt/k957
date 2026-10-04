package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCaseDossier(t *testing.T) {
	d := t.TempDir()
	root := filepath.Join(d, "src")
	if e := os.Mkdir(root, 0700); e != nil {
		t.Fatal(e)
	}
	png := append([]byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}, []byte("pixel")...)
	if e := os.WriteFile(filepath.Join(root, "photo.txt"), png, 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(root, "copy.bin"), png, 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(root, "plain.txt"), []byte("hello\n"), 0600); e != nil {
		t.Fatal(e)
	}
	base := filepath.Join(d, "output")
	rec, e := CollectFull(context.Background(), FullOptions{OutputDir: base, Root: root, System: false, Artifacts: false, Memory: false, MaxFile: 1 << 20, MaxTotal: 1 << 20, MaxFiles: 20})
	if e != nil {
		t.Fatal(e)
	}
	if len(rec.CollectorSHA256) != 64 {
		t.Fatalf("collector hash %q", rec.CollectorSHA256)
	}
	sum := sha256.Sum256(png)
	setPath := filepath.Join(d, "set.txt")
	if e = os.WriteFile(setPath, []byte("known-bad "+hex.EncodeToString(sum[:])+" demo-image\n"), 0600); e != nil {
		t.Fatal(e)
	}
	set, e := LoadHashSet(setPath)
	if e != nil {
		t.Fatal(e)
	}
	out := filepath.Join(d, "dossier")
	dossier, e := BuildCase(context.Background(), base, out, "", set)
	if e != nil {
		t.Fatal(e)
	}
	if dossier.Schema != CaseSchema || dossier.Verified != 1 || dossier.Failed != 0 || dossier.Items != 3 || len(dossier.Duplicates) != 1 || dossier.Duplicates[0].Count != 2 {
		t.Fatalf("%+v", dossier)
	}
	if len(dossier.Mismatches) != 1 || !strings.HasSuffix(dossier.Mismatches[0].Source, "photo.txt") || len(dossier.HashMatches) != 2 {
		t.Fatalf("mismatch %#v matches %#v", dossier.Mismatches, dossier.HashMatches)
	}
	body, e := os.ReadFile(filepath.Join(out, "bodyfile.txt"))
	if e != nil || !strings.Contains(string(body), "photo.txt") || !strings.Contains(string(body), "|0|r/r--------|") {
		t.Fatalf("bodyfile %s %v", body, e)
	}
	for _, name := range []string{"case.json", "inventory.csv", "timeline.csv", "duplicates.csv", "hash-matches.csv", "report.html"} {
		if _, e = os.Stat(filepath.Join(out, name)); e != nil {
			t.Fatal(name, e)
		}
	}
	empty := filepath.Join(d, "empty")
	if e = os.Mkdir(empty, 0700); e != nil {
		t.Fatal(e)
	}
	if _, e = BuildCase(context.Background(), empty, filepath.Join(d, "unused"), "", nil); e == nil {
		t.Fatal("expected empty store")
	}
	if e = os.MkdirAll(filepath.Join(base, "other", "20060102T000000Z"), 0700); e != nil {
		t.Fatal(e)
	}
	failed, e := BuildCase(context.Background(), base, filepath.Join(d, "dossier-failed"), "", nil)
	if e == nil || failed.Failed != 1 || failed.Verified != 1 {
		t.Fatalf("err %v failed %+v", e, failed)
	}
	if _, e = os.Stat(filepath.Join(failed.Directory, "report.html")); e != nil {
		t.Fatal(e)
	}
}
