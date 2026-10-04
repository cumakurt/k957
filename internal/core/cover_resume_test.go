package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"
)

func checkpoint(t *testing.T, root, body string) string {
	t.Helper()
	work := t.TempDir()
	if e := os.Mkdir(filepath.Join(work, "chunks"), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(work, "state.json"), []byte(body), 0600); e != nil {
		t.Fatal(e)
	}
	return work
}

func baseCheckpoint(root string) string {
	return `{"schema":"` + workSchema + `","root":` + strconv.Quote(root) + `,"max_file":1000,"max_total":1000,"max_files":10,"manifest":{"schema":"` + ResumeSchema + `","version":"` + Version + `","inventory_frozen":true,"epochs":[{"id":"e1","started":"2026-01-02T03:04:05Z","outcome":"complete"}]},"files":[]}`
}

func TestCheckpointValidation(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "a.txt")
	if e := os.WriteFile(src, []byte("hi"), 0600); e != nil {
		t.Fatal(e)
	}
	work := checkpoint(t, root, baseCheckpoint(root))
	var state WorkState
	if e := readWork(work, &state); e != nil {
		t.Fatal(e)
	}
	cases := []string{
		baseCheckpoint(root) + "{}",
		`{"schema":"no","root":"` + root + `","max_file":1,"max_total":1,"max_files":1,"manifest":{"schema":"` + ResumeSchema + `","version":"` + Version + `","inventory_frozen":true}}`,
		`{"encryption":"no","schema":"` + workSchema + `","root":` + strconv.Quote(root) + `,"max_file":1,"max_total":1,"max_files":1,"manifest":{"schema":"` + ResumeSchema + `","version":"` + Version + `","inventory_frozen":true,"epochs":[{"id":"e1","started":"2026-01-02T03:04:05Z","outcome":"ok"}]}}`,
		`{"schema":"` + workSchema + `","root":` + strconv.Quote(root) + `,"max_file":1,"max_total":1,"max_files":1,"manifest":{"schema":"` + ResumeSchema + `","version":"` + Version + `","inventory_frozen":true,"epochs":[{"id":"","started":"2026-01-02T03:04:05Z","outcome":"ok"}]}}`,
		`not-json`,
	}
	for _, body := range cases {
		if e := readWork(checkpoint(t, root, body), &state); e == nil {
			t.Fatal("expected checkpoint error")
		}
	}
	os.WriteFile(filepath.Join(work, "state.enc"), []byte("x"), 0600)
	if e := readWork(work, &state); e == nil {
		t.Fatal("expected mode mismatch")
	}
	os.Remove(filepath.Join(work, "state.enc"))
	if runtime.GOOS != "windows" && os.Geteuid() != 0 {
		os.Chmod(work, 0000)
		if e := readWork(work, &state); e == nil {
			t.Fatal("expected unreadable work")
		}
		os.Chmod(work, 0700)
	}

	os.Remove(filepath.Join(work, "state.json"))
	os.Mkdir(filepath.Join(work, "state.json"), 0700)
	if e := readWork(work, &state); e == nil {
		t.Fatal("expected non-regular checkpoint")
	}
	os.Remove(filepath.Join(work, "state.json"))
	os.WriteFile(filepath.Join(work, "state.json"), []byte(baseCheckpoint(root)), 0000)
	if e := readWork(work, &state); e == nil {
		t.Fatal("expected unreadable checkpoint")
	}
	os.Chmod(filepath.Join(work, "state.json"), 0600)

	badID := `{"schema":"` + workSchema + `","root":` + strconv.Quote(root) + `,"max_file":1000,"max_total":1000,"max_files":10,"manifest":{"schema":"` + ResumeSchema + `","version":"` + Version + `","inventory_frozen":true,"epochs":[{"id":"e1","started":"2026-01-02T03:04:05Z","outcome":"complete"}]},"files":[{"expected_size":2,"item":{"id":"bad","source":"` + src + `","object":"objects/E000001","kind":"file"}}]}`
	if e := readWork(checkpoint(t, root, badID), &state); e == nil {
		t.Fatal("expected bad source")
	}
	neg := `{"schema":"` + workSchema + `","root":` + strconv.Quote(root) + `,"max_file":1000,"max_total":1000,"max_files":10,"manifest":{"schema":"` + ResumeSchema + `","version":"` + Version + `","inventory_frozen":true,"epochs":[{"id":"e1","started":"2026-01-02T03:04:05Z","outcome":"complete"}]},"files":[{"expected_size":-1,"item":{"id":"E000001","source":"` + src + `","object":"objects/E000001","kind":"file"}}]}`
	if e := readWork(checkpoint(t, root, neg), &state); e == nil {
		t.Fatal("expected bad size")
	}
	over := `{"schema":"` + workSchema + `","root":` + strconv.Quote(root) + `,"max_file":1000,"max_total":1,"max_files":10,"manifest":{"schema":"` + ResumeSchema + `","version":"` + Version + `","inventory_frozen":true,"epochs":[{"id":"e1","started":"2026-01-02T03:04:05Z","outcome":"complete"}]},"files":[{"expected_size":2,"item":{"id":"E000001","source":"` + src + `","object":"objects/E000001","kind":"file"}}]}`
	if e := readWork(checkpoint(t, root, over), &state); e == nil {
		t.Fatal("expected budget error")
	}
	if e := validateEpochs([]Epoch{{ID: ""}}); e == nil {
		t.Fatal("expected invalid epoch")
	}
	if e := validateEpochs([]Epoch{{ID: "e", Started: time.Now(), Outcome: "ok"}, {ID: "e", Started: time.Now(), Outcome: "ok"}}); e == nil {
		t.Fatal("expected duplicate epoch")
	}
	epochs := []Epoch{{ID: "e1", Started: time.Now(), Outcome: "ok"}}
	item := Item{Parts: []Part{{Size: 0, SHA256: "zz", Epoch: "missing"}}}
	if e := validatePartMetadata(item, epochs, 10, false); e == nil {
		t.Fatal("expected bad part")
	}
	sum := sha256.Sum256([]byte("hi"))
	item.Parts = []Part{{Offset: 0, Size: 8, SHA256: hex.EncodeToString(sum[:]), Epoch: "e1", Acquired: time.Now()}}
	if e := validatePartMetadata(item, epochs, 4, false); e == nil {
		t.Fatal("expected part overflow")
	}
	item.Parts = nil
	item.Size = 1
	if e := validatePartMetadata(item, epochs, 4, true); e == nil {
		t.Fatal("expected incomplete metadata")
	}
	if _, e := chunkData(work, Part{SHA256: "abcd", Size: 1}); e == nil {
		t.Fatal("expected missing chunk")
	}
	chunk := filepath.Join(work, "chunks", "abcd")
	os.Mkdir(chunk, 0700)
	if _, e := chunkData(work, Part{SHA256: "abcd", Size: 1}); e == nil {
		t.Fatal("expected chunk type error")
	}
}

func TestResumableEarlyErrors(t *testing.T) {
	d, o := fixture(t, true)
	keyInSource := filepath.Join(o.Root, "sign.key")
	os.WriteFile(keyInSource, []byte("abcd"), 0600)
	o.SignKey = keyInSource
	if _, e := CollectResumable(context.Background(), o, filepath.Join(d, "work"), false); e == nil {
		t.Fatal("expected key inside source")
	}
	o.SignKey = ""
	o.EncryptionKey = filepath.Join(d, "missing-key")
	if _, e := CollectResumable(context.Background(), o, filepath.Join(d, "work"), false); e == nil {
		t.Fatal("expected missing encryption key")
	}
	ctx := &cancelAfter{Context: context.Background(), left: 0}
	o.EncryptionKey = ""
	o.SignKey = ""
	if _, e := CollectResumable(ctx, o, filepath.Join(d, "work-cancel"), false); e == nil {
		t.Fatal("expected cancel")
	}
	already := filepath.Join(d, "already")
	os.Mkdir(already, 0700)
	if _, e := CollectResumable(context.Background(), o, already, false); e == nil {
		t.Fatal("expected existing work")
	}
	file := filepath.Join(d, "not-dir")
	os.WriteFile(file, []byte("x"), 0600)
	if _, e := CollectResumable(context.Background(), o, file, true); e == nil {
		t.Fatal("expected resume directory error")
	}
	useRand(t, failReader{})
	if e := saveWork(t.TempDir(), WorkState{}, &workCrypto{}); e == nil {
		t.Fatal("expected seal failure")
	}
}
