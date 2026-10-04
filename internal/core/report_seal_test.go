package core

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReportSealTrustChangesAndUnexpectedFiles(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	prefix := filepath.Join(t.TempDir(), "report-key")
	if e := Keygen(prefix); e != nil {
		t.Fatal(e)
	}
	file := filepath.Join(dir, "report.html")
	if e := WriteNew(file, []byte("<h1>Derived document</h1>")); e != nil {
		t.Fatal(e)
	}
	seal, e := SealReport(ctx, dir, prefix+".key")
	if e != nil || len(seal.Files) != 1 {
		t.Fatalf("%+v %v", seal, e)
	}
	status, e := VerifyReport(ctx, dir, "")
	if e != nil || !strings.Contains(status.Signature, "not independently trusted") {
		t.Fatalf("%+v %v", status, e)
	}
	status, e = VerifyReport(ctx, dir, prefix+".pub")
	if e != nil || !strings.Contains(status.Signature, "supplied trusted") {
		t.Fatalf("%+v %v", status, e)
	}
	if _, e = SealReport(ctx, dir, prefix+".key"); e == nil {
		t.Fatal("seal was overwritten")
	}
	extra := filepath.Join(dir, "unexpected.txt")
	if e = WriteNew(extra, []byte("extra")); e != nil {
		t.Fatal(e)
	}
	if _, e = VerifyReport(ctx, dir, prefix+".pub"); e == nil {
		t.Fatal("unlisted file accepted")
	}
	os.Remove(extra)
	if e = os.WriteFile(file, []byte("modified"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = VerifyReport(ctx, dir, prefix+".pub"); e == nil {
		t.Fatal("modified report accepted")
	}
}

func TestReportSealRejectsUnsafePathsAndCancelledHashing(t *testing.T) {
	for _, name := range []string{"../escape", "/absolute", "nested/../escape", "back\\slash", "a\nname"} {
		if validReportName(name) {
			t.Fatal("unsafe name", name)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := reportFiles(ctx, t.TempDir()); e == nil {
		t.Fatal("cancelled hashing proceeded")
	}
}
