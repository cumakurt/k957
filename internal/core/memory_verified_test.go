package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

func TestVerifiedMemoryScanRejectsInvalidInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "memory.raw")
	image := []byte("failed password\n")
	if err := os.WriteFile(path, image, 0600); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"", "invalid", strings.Repeat("0", 64)} {
		if m, err := scanVerifiedMemoryFile(context.Background(), path, expected, BuiltinRules(), nil); err == nil || m.SHA256 != "" || len(m.Hits) > 0 {
			t.Fatal("unsigned or incorrectly bound results accepted", expected, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := scanVerifiedMemoryFile(ctx, path, digestBytes(image), nil, nil); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled scan proceeded", err)
	}
	if _, err := scanVerifiedMemoryFile(context.Background(), filepath.Dir(path), digestBytes(image), nil, nil); err == nil {
		t.Fatal("directory treated as a memory image")
	}
	if err := os.WriteFile(path, []byte{}, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := scanVerifiedMemoryFile(context.Background(), path, digestBytes(nil), nil, nil); err == nil {
		t.Fatal("empty image accepted")
	}
}

func unavailableMemoryTemp(t *testing.T) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "unavailable")
	for _, variable := range []string{"TMPDIR", "TEMP", "TMP"} {
		t.Setenv(variable, dir)
	}
}

func TestVerifiedMemoryScanWithoutTemporaryStorage(t *testing.T) {
	for _, format := range []string{"raw", "lime"} {
		t.Run(format, func(t *testing.T) {
			payload := []byte("Linux version 1.2.3-synthetic\nfailed password\n")
			image := payload
			if format == "lime" {
				header := make([]byte, limeHeaderSize)
				binary.LittleEndian.PutUint32(header, limeMagic)
				binary.LittleEndian.PutUint32(header[4:], limeVersion)
				binary.LittleEndian.PutUint64(header[8:], 0x1000)
				binary.LittleEndian.PutUint64(header[16:], 0x1000+uint64(len(payload))-1)
				image = append(header, payload...)
			}
			path := filepath.Join(t.TempDir(), "memory."+format)
			if err := os.WriteFile(path, image, 0600); err != nil {
				t.Fatal(err)
			}
			unavailableMemoryTemp(t)
			m, err := scanVerifiedMemoryFile(context.Background(), path, digestBytes(image), BuiltinRules(), nil)
			if err != nil {
				t.Fatal(err)
			}
			if m.Format != format || m.SHA256 != digestBytes(image) || m.Bytes != uint64(len(payload)) || len(m.Hits) == 0 {
				t.Fatalf("unexpected authenticated scan: %+v", m)
			}
			if format == "lime" && m.Hits[0].Physical != 0x1000+uint64(bytes.Index(payload, []byte("failed password"))) {
				t.Fatal("LiME physical address changed")
			}
			if after, err := os.ReadFile(path); err != nil || !bytes.Equal(after, image) {
				t.Fatal("scan changed source image", err)
			}
		})
	}
}

func TestVerifiedMemoryScanRejectsChangedBytesAndCancellation(t *testing.T) {
	for _, action := range []string{"mutate", "cancel", "replace"} {
		t.Run(action, func(t *testing.T) {
			image := bytes.Repeat([]byte("x"), 9<<20)
			path := filepath.Join(t.TempDir(), "memory.raw")
			if err := os.WriteFile(path, image, 0600); err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			changed := false
			replacementDenied := false
			ctx = WithProgress(ctx, func(p Progress) {
				if changed || p.Bytes < verifyReportEvery {
					return
				}
				changed = true
				switch action {
				case "cancel":
					cancel()
				case "mutate":
					f, err := os.OpenFile(path, os.O_WRONLY, 0600)
					if err != nil {
						t.Fatal(err)
					}
					_, err = f.WriteAt([]byte("y"), int64(len(image)-1024))
					closeErr := f.Close()
					if err != nil || closeErr != nil {
						t.Fatal(err, closeErr)
					}
					if err = os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
						t.Fatal(err)
					}
				case "replace":
					if err := os.Rename(path, path+".previous"); err != nil {
						if runtime.GOOS == "windows" && errors.Is(err, syscall.Errno(32)) {
							replacementDenied = true // ERROR_SHARING_VIOLATION protects the open evidence handle.
							return
						}
						t.Fatal(err)
					}
					if err := os.WriteFile(path, image, 0600); err != nil {
						t.Fatal(err)
					}
				}
			})
			meter := &verifyMeter{ctx: ctx, phase: "analyze", total: int64(len(image))}
			m, err := scanVerifiedMemoryFile(ctx, path, digestBytes(image), BuiltinRules(), meter)
			if replacementDenied {
				if err != nil || m.SHA256 != digestBytes(image) {
					t.Fatalf("protected image failed verification: %v", err)
				}
				return
			}
			if err == nil || !changed || m.SHA256 != "" || len(m.Hits) > 0 {
				t.Fatalf("unverified scan accepted: changed=%v result=%+v error=%v", changed, m, err)
			}
			if action == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation was lost", err)
			}
		})
	}
}

func TestMemoryOnlyStoreAndCaseWithoutTemporaryStorage(t *testing.T) {
	dir := t.TempDir()
	kcore, iomem := filepath.Join(dir, "kcore"), filepath.Join(dir, "iomem")
	payload := make([]byte, 4096)
	copy(payload, "Linux version 1.2.3-synthetic\nfailed password\n")
	writeKcore(t, kcore, 0x100000, len(payload), payload)
	if err := os.WriteFile(iomem, []byte("00100000-00100fff : System RAM\n"), 0600); err != nil {
		t.Fatal(err)
	}
	store := filepath.Join(dir, "store")
	rec, err := CollectFull(context.Background(), FullOptions{OutputDir: store, Memory: true, IOMem: iomem, Kcore: kcore})
	if err != nil || rec.Memory == nil || rec.Status != "complete" {
		t.Fatal("synthetic collection failed", rec.Status, err)
	}
	before := workDigests(t, rec.Directory)
	caseDir := filepath.Join(dir, "case")
	unavailableMemoryTemp(t)
	result, err := AnalyzeStore(context.Background(), store, "", "", "")
	if err != nil || result.Analyzed != 1 || result.Failed != 0 {
		t.Fatal("memory-only store analysis failed", result, err)
	}
	var analysis Analysis
	body, err := os.ReadFile(filepath.Join(result.Collections[0].Report, "analysis.json"))
	if err != nil || json.Unmarshal(body, &analysis) != nil || len(analysis.Memories) != 1 || analysis.Memories[0].SHA256 != rec.Memory.SHA256 {
		t.Fatal("report lost its signed image binding", err)
	}
	if _, err = BuildCase(context.Background(), store, caseDir, "", nil); err != nil {
		t.Fatal("case memory analysis failed", err)
	}
	for name, expected := range before {
		body, err := os.ReadFile(name)
		if err != nil || sha256.Sum256(body) != expected {
			t.Fatal("analysis changed acquired evidence", name, err)
		}
	}
}
