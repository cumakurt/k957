package core

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExternalJSONRejectsAmbiguity(t *testing.T) {
	for _, body := range []string{`[{"PID":1,"PID":2}]`, `[] []`, `[`, strings.Repeat("[", 66) + strings.Repeat("]", 66)} {
		if validateExternalJSON([]byte(body)) == nil {
			t.Fatal("accepted", body)
		}
	}
	if err := validateExternalJSON([]byte(`[{"PID":7,"Name":"test","__children":[]}]`)); err != nil {
		t.Fatal(err)
	}
}

func TestImageStagingAndSymbolBoundaries(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	source := filepath.Join(dir, "image.raw")
	if err := os.WriteFile(source, []byte("image"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := stageRawImage(ctx, source, filepath.Join(dir, "bad"), strings.Repeat("a", 64), 100); err == nil {
		t.Fatal("wrong image identity accepted")
	}
	sum, size, err := stageRawImage(ctx, source, filepath.Join(dir, "good"), "", 100)
	if err != nil || size != 5 || !validHash(sum) {
		t.Fatal(sum, size, err)
	}
	symbols := filepath.Join(dir, "symbols")
	if err := os.Mkdir(symbols, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(symbols, "plugin.py"), []byte("raise RuntimeError"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := stageSymbols(ctx, symbols, filepath.Join(dir, "staged")); err == nil {
		t.Fatal("plugin code accepted as symbols")
	}
	if _, err := ExamineMemory(ctx, source, filepath.Join(dir, "out"), "", "tool", symbols, "arbitrary.plugin"); err == nil {
		t.Fatal("arbitrary plugin accepted")
	}
}
