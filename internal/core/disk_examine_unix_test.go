//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package core

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func diskFailureFixture(t *testing.T, script string) (string, string, string) {
	t.Helper()
	dir := t.TempDir()
	image := filepath.Join(dir, "image.raw")
	if err := os.WriteFile(image, make([]byte, 1024), 0600); err != nil {
		t.Fatal(err)
	}
	digest, err := fileSHA256(image)
	if err != nil {
		t.Fatal(err)
	}
	tool := filepath.Join(dir, "tool")
	if err := os.WriteFile(tool, []byte("#!/bin/sh\n"+script), 0700); err != nil {
		t.Fatal(err)
	}
	return image, digest, tool
}

func TestDiskToolFailureRetainsDiagnosticReceipt(t *testing.T) {
	image, digest, tool := diskFailureFixture(t, "printf 'r/r * 12: failed.txt\\n'; printf 'synthetic failure\\n' >&2; exit 7\n")
	out := filepath.Join(t.TempDir(), "failed")
	result, err := ExamineDisk(context.Background(), image, out, digest, tool, 0, 512)
	if err == nil || result.Status != "failed" || result.Tool.ExitCode != 7 || result.Error == "" || len(result.Entries) != 0 || result.Coverage.Status != "failed" || result.Coverage.TotalKnown {
		t.Fatalf("failed tool promoted to successful examination: %+v %v", result, err)
	}
	body, err := os.ReadFile(filepath.Join(out, "disk.json"))
	if err != nil {
		t.Fatal(err)
	}
	var receipt DiskExamination
	if err = json.Unmarshal(body, &receipt); err != nil || receipt.Tool.SHA256 != result.Tool.SHA256 {
		t.Fatal("missing invocation identity", err)
	}
	for name, want := range map[string]string{"listing.partial.txt": result.Tool.StdoutSHA256, "tool.stderr": result.Tool.StderrSHA256} {
		got, err := fileSHA256(filepath.Join(out, name))
		if err != nil || got != want {
			t.Fatal("failed output does not bind diagnostic bytes", name, err)
		}
	}
	if _, err = os.Stat(filepath.Join(out, "listing.txt")); !os.IsNotExist(err) {
		t.Fatal("failed listing published as successful listing")
	}
	if after, err := fileSHA256(image); err != nil || after != digest {
		t.Fatal("source changed", err)
	}
}

func TestDiskRecoveryFailureAndCancellationDoNotPublishRecoveredContent(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		t.Run(map[bool]string{false: "exit", true: "cancel"}[canceled], func(t *testing.T) {
			script := "printf 'partial synthetic bytes'; printf 'failure\\n' >&2; exit 9\n"
			if canceled {
				script = "printf 'partial synthetic bytes'; sleep 30\n"
			}
			image, digest, tool := diskFailureFixture(t, script)
			ctx := context.Background()
			if canceled {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 300*time.Millisecond)
				defer cancel()
			}
			out := filepath.Join(t.TempDir(), "failed")
			started := time.Now()
			result, err := RecoverDiskEntry(ctx, image, out, digest, tool, "12", 0, 512)
			if err == nil || result.Status != "failed" || result.SHA256 != "" || result.Bytes != 0 || result.ImageSHA256 != digest {
				t.Fatalf("partial recovery promoted to successful content: %+v %v", result, err)
			}
			if canceled && (ctx.Err() == nil || time.Since(started) > 3*time.Second) {
				t.Fatal("cancellation did not stop tool promptly")
			}
			if _, err = os.Stat(filepath.Join(out, "recovered.bin")); !os.IsNotExist(err) {
				t.Fatal("failed recovery uses successful output name")
			}
			if got, err := fileSHA256(filepath.Join(out, "recovered.partial.bin")); err != nil || got != result.Tool.StdoutSHA256 {
				t.Fatal("partial output hash missing", err)
			}
			body, err := os.ReadFile(filepath.Join(out, "recovery.json"))
			if err != nil || !strings.Contains(string(body), `"status": "failed"`) {
				t.Fatal("failed receipt missing", err)
			}
		})
	}
}

func TestDiskPreflightFailureRemovesOnlyNewOutput(t *testing.T) {
	image, digest, _ := diskFailureFixture(t, "exit 0\n")
	out := filepath.Join(t.TempDir(), "failed")
	if _, err := ExamineDisk(context.Background(), image, out, digest, filepath.Join(t.TempDir(), "missing-tool"), 0, 512); err == nil {
		t.Fatal("missing tool accepted")
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("pre-invocation failure retained output")
	}
	if err := os.Mkdir(out, 0700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(out, "existing")
	if err := os.WriteFile(marker, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ExamineDisk(context.Background(), image, out, digest, "missing", 0, 512); err == nil {
		t.Fatal("existing destination overwritten")
	}
	if body, err := os.ReadFile(marker); err != nil || string(body) != "preserve" {
		t.Fatal("existing output changed", err)
	}
}

func TestFailedDiskOutputRejectsChangedHashAndSize(t *testing.T) {
	for _, invalidHash := range []bool{false, true} {
		dir, out := t.TempDir(), t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "stdout"), []byte("three"), 0600); err != nil {
			t.Fatal(err)
		}
		tool, limit := ToolInvocation{}, int64(2)
		if invalidHash {
			tool.StdoutSHA256, limit = strings.Repeat("a", 64), 10
		}
		if err := retainFailedDiskOutput(dir, out, "stdout", "partial", limit, &tool); err == nil {
			t.Fatal("unbounded or changed diagnostic output accepted")
		}
	}
}
