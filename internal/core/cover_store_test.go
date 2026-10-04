package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestStoreVerificationEdges(t *testing.T) {
	if _, e := DiscoverCollections(filepath.Join(t.TempDir(), "missing")); e == nil {
		t.Fatal("expected missing store")
	}
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "note"), []byte("x"), 0600)
	host := filepath.Join(root, "host")
	os.Mkdir(host, 0700)
	os.WriteFile(filepath.Join(host, "file"), []byte("x"), 0600)
	os.Mkdir(filepath.Join(host, "stamp"), 0700)
	if dirs, e := DiscoverCollections(root); e != nil || len(dirs) != 1 {
		t.Fatal(e, dirs)
	}
	if runtime.GOOS != "windows" && os.Geteuid() != 0 {
		locked := filepath.Join(root, "locked")
		os.Mkdir(locked, 0000)
		t.Cleanup(func() { os.Chmod(locked, 0700) })
		if _, e := DiscoverCollections(root); e == nil {
			t.Fatal("expected unreadable host")
		}
		os.Chmod(locked, 0700)
	}

	if _, e := VerifyStore(context.Background(), t.TempDir(), ""); e == nil {
		t.Fatal("expected empty store")
	}

	dir := t.TempDir()
	if v := verifyCollection(dir, ""); v.Status != "failed" {
		t.Fatal(v)
	}
	os.WriteFile(filepath.Join(dir, "collection.json"), []byte("{"), 0600)
	if v := verifyCollection(dir, ""); len(v.Errors) == 0 {
		t.Fatal("expected bad json")
	}
	os.WriteFile(filepath.Join(dir, "collection.json"), []byte(`{"schema":"no"}{}`), 0600)
	if v := verifyCollection(dir, ""); len(v.Errors) == 0 {
		t.Fatal("expected trailing record")
	}
	os.WriteFile(filepath.Join(dir, "collection.json"), []byte(`{"schema":"no","version":"0","id":"","case":"","status":"no"}`), 0600)
	if v := verifyCollection(dir, ""); v.Status != "failed" {
		t.Fatal("expected invalid record")
	}
	if e := checkArtifact(dir, CollectionArtifact{Name: "../x"}); e == nil {
		t.Fatal("expected bad artifact name")
	}
	if e := checkArtifact(dir, CollectionArtifact{Name: "missing"}); e == nil {
		t.Fatal("expected missing artifact")
	}
	os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello"), 0600)
	if e := checkArtifact(dir, CollectionArtifact{Name: "a.txt", SHA256: "00", Size: 1}); e == nil {
		t.Fatal("expected hash mismatch")
	}
	for _, name := range []string{"", `a\b`, "/abs", "a/../b", "a//b", "."} {
		if e := safeSumName(name); e == nil {
			t.Fatal(name)
		}
	}
	if e := checkSums(dir); e == nil {
		t.Fatal("expected missing sums")
	}
	sum := sha256.Sum256([]byte("hello"))
	good := hex.EncodeToString(sum[:]) + "  a.txt\n"
	os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte("short\n"), 0600)
	if e := checkSums(dir); e == nil {
		t.Fatal("expected short line")
	}
	os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(strings.Repeat("a", 64)+" xname\n"), 0600)
	if e := checkSums(dir); e == nil {
		t.Fatal("expected bad separator")
	}
	os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(strings.Repeat("ab", 32)+"  ../a.txt\n"), 0600)
	if e := checkSums(dir); e == nil {
		t.Fatal("expected unsafe name")
	}
	os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(good+good), 0600)
	if e := checkSums(dir); e == nil {
		t.Fatal("expected duplicate")
	}
	sumsDir := t.TempDir()
	os.WriteFile(filepath.Join(sumsDir, "a.txt"), []byte("hello"), 0600)
	os.WriteFile(filepath.Join(sumsDir, "SHA256SUMS"), []byte("# comment\n\n"+strings.Repeat("ab", 32)+"  a.txt\n"), 0600)
	if e := checkSums(sumsDir); e == nil {
		t.Fatal("expected hash mismatch")
	}
	raw := []byte("raw-image")
	os.WriteFile(filepath.Join(dir, "memory.raw"), raw, 0600)
	h256, h1, hmd5, size, e := hashFile(filepath.Join(dir, "memory.raw"))
	if e != nil {
		t.Fatal(e)
	}
	rec := &MemoryRecord{Schema: "no", Image: "memory.raw", Format: "raw", SHA256: h256, SHA1: h1, MD5: hmd5, ImageSize: size, Ranges: []MemoryRange{{Size: uint64(size)}}, Bytes: uint64(size)}
	if e := checkMemory(dir, rec); e == nil {
		t.Fatal("expected invalid memory record")
	}
	rec.Schema = MemorySchema
	rec.SHA256 = "00"
	if e := checkMemory(dir, rec); e == nil {
		t.Fatal("expected image hash mismatch")
	}
	rec.SHA256 = h256
	rec.Format = "nope"
	if e := checkMemory(dir, rec); e == nil {
		t.Fatal("expected unknown format")
	}
	rec.Format = "raw"
	rec.Ranges = nil
	if e := checkMemory(dir, rec); e == nil {
		t.Fatal("expected raw mismatch")
	}
	parent := filepath.Join(dir, "reports")
	os.MkdirAll(parent, 0700)
	now := time.Now().UTC()
	for shift := 0; shift < 3; shift++ {
		base := now.Add(time.Duration(shift) * time.Second).Format("20060102T150405Z")
		if e := os.Mkdir(filepath.Join(parent, base), 0700); e != nil {
			t.Fatal(e)
		}
		for i := 1; i < 100; i++ {
			if e := os.Mkdir(filepath.Join(parent, base+"-"+itoa(i+1)), 0700); e != nil {
				t.Fatal(e)
			}
		}
	}
	if _, e := nextReportDir(parent); e == nil {
		t.Fatal("expected report collision")
	}
	if item := analyzeCollection(context.Background(), dir, nil, "", nil, nil); item.Status != "failed" {
		t.Fatal(item)
	}
}

func TestVerifyProgressStartsAtZero(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "host", "stamp")
	if e := os.MkdirAll(dir, 0700); e != nil {
		t.Fatal(e)
	}
	payload := bytes.Repeat([]byte("x"), 9<<20)
	if e := os.WriteFile(filepath.Join(dir, "blob.bin"), payload, 0600); e != nil {
		t.Fatal(e)
	}
	rec := CollectionRecord{
		Schema: "k957-collection/1", Version: "0.14.0", ID: "id", Case: "case", Status: "complete",
		Artifacts: []CollectionArtifact{{Name: "blob.bin", Size: int64(len(payload)), SHA256: "00"}},
	}
	body, e := json.Marshal(rec)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(dir, "collection.json"), body, 0600); e != nil {
		t.Fatal(e)
	}
	var first Progress
	var partial bool
	ctx := WithProgress(context.Background(), func(p Progress) {
		if first.Phase == "" {
			first = p
		}
		if p.TotalBytes > 0 && p.Bytes > 0 && p.Bytes < p.TotalBytes {
			partial = true
		}
	})
	if _, e = VerifyStore(ctx, root, ""); e == nil {
		t.Fatal("expected an unverified collection")
	}
	if first.Bytes != 0 || first.TotalBytes != int64(len(payload)) {
		t.Fatalf("start %+v", first)
	}
	if !partial {
		t.Fatal("verification did not report progress before the file was finished")
	}

	empty := t.TempDir()
	missing := filepath.Join(empty, "host", "stamp")
	if e = os.MkdirAll(missing, 0700); e != nil {
		t.Fatal(e)
	}
	var step Progress
	ctx = WithProgress(context.Background(), func(p Progress) {
		if step.Steps == 0 {
			step = p
		}
	})
	VerifyStore(ctx, empty, "")
	if step.Step != 0 || step.Steps != 1 || step.TotalBytes != 0 {
		t.Fatalf("missing collection start %+v", step)
	}
}

func TestAnalyzeProgressStartsAtZero(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "host", "stamp")
	if e := os.MkdirAll(dir, 0700); e != nil {
		t.Fatal(e)
	}
	payload := bytes.Repeat([]byte("x"), 9<<20)
	if e := os.WriteFile(filepath.Join(dir, "blob.bin"), payload, 0600); e != nil {
		t.Fatal(e)
	}
	rec := CollectionRecord{
		Schema: "k957-collection/1", Version: "0.14.0", ID: "id", Case: "case", Status: "complete",
		Artifacts: []CollectionArtifact{{Name: "blob.bin", Size: int64(len(payload)), SHA256: "00"}},
	}
	body, e := json.Marshal(rec)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(dir, "collection.json"), body, 0600); e != nil {
		t.Fatal(e)
	}
	var first Progress
	var partial bool
	ctx := WithProgress(context.Background(), func(p Progress) {
		if first.Phase == "" {
			first = p
		}
		if p.Phase == "analyze" && p.TotalBytes > 0 && p.Bytes > 0 && p.Bytes < p.TotalBytes {
			partial = true
		}
	})
	if _, e = AnalyzeStore(ctx, root, "", "", ""); e == nil {
		t.Fatal("expected an unverified collection")
	}
	if first.Phase != "analyze" || first.Bytes != 0 || first.TotalBytes != int64(len(payload)) {
		t.Fatalf("start %+v", first)
	}
	if !partial {
		t.Fatal("analysis did not report progress before the file was finished")
	}

	image := filepath.Join(t.TempDir(), "memory.raw")
	if e = os.WriteFile(image, payload, 0600); e != nil {
		t.Fatal(e)
	}
	var scanPartial bool
	scanCtx := WithProgress(context.Background(), func(p Progress) {
		if p.Bytes > 0 && p.Bytes < p.TotalBytes && p.Detail == "memory.raw" {
			scanPartial = true
		}
	})
	meter := &verifyMeter{ctx: scanCtx, phase: "analyze", total: int64(len(payload))}
	if _, e = scanMemoryFileProgress(image, nil, meter, int64(len(payload))); e != nil {
		t.Fatal(e)
	}
	if !scanPartial || meter.done != int64(len(payload)) {
		t.Fatalf("scan progress done=%d partial=%v", meter.done, scanPartial)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
