package core

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestCheckpointBlockedReplacementPreservesPrevious(t *testing.T) {
	work := t.TempDir()
	state := WorkState{Manifest: Manifest{Case: "before"}}
	if err := saveWork(work, state); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(work, "state.json")
	reader, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	state.Manifest.Case = "after"
	if err = saveWork(work, state); err == nil {
		t.Fatal("expected a persistent sharing conflict")
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, JSON(WorkState{Manifest: Manifest{Case: "before"}})) {
		t.Fatalf("failed replacement damaged the previous checkpoint: %v", err)
	}
	leftovers, err := filepath.Glob(filepath.Join(work, ".checkpoint-*"))
	if err != nil || len(leftovers) != 0 {
		t.Fatalf("failed replacement left temporary files: %v, %v", leftovers, err)
	}
}
