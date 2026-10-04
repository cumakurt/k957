package core

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestSharedExportCancellationAndExistingDirectory(t *testing.T) {
	a, _ := sharedFixture(t)
	s, err := BuildSharedReport(a, SharePolicy{Schema: sharePolicySchema})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	out := filepath.Join(t.TempDir(), "shared")
	if err := ExportSharedContext(ctx, s, out); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled export succeeded", err)
	}
	if _, err := os.Lstat(out); !os.IsNotExist(err) {
		t.Fatal("canceled export created a directory", err)
	}
	if err := os.Mkdir(out, 0700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(out, "original.txt")
	if err := WriteNew(marker, []byte("retain")); err != nil {
		t.Fatal(err)
	}
	if err := ExportSharedContext(context.Background(), s, out); err == nil {
		t.Fatal("existing directory accepted")
	}
	if data, err := os.ReadFile(marker); err != nil || string(data) != "retain" {
		t.Fatal("existing output changed", err)
	}
}

func TestSharedCSVStreamingPreservesInputAndCancels(t *testing.T) {
	rows := [][]string{{"=1+1", "value,comma"}}
	path := filepath.Join(t.TempDir(), "rows.csv")
	if err := sharedCSV(path, []string{"first", "second"}, rows); err != nil {
		t.Fatal(err)
	}
	if rows[0][0] != "=1+1" {
		t.Fatal("sharing changed caller-owned row")
	}
	data, err := os.ReadFile(path)
	if err != nil || !bytes.Contains(data, []byte("'=1+1")) {
		t.Fatal("CSV formula protection lost", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	path = filepath.Join(t.TempDir(), "canceled.csv")
	if err := sharedCSVContext(ctx, path, nil, rows); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled CSV succeeded", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("partial CSV retained", err)
	}
}

type cancelOnWrite struct {
	cancel context.CancelFunc
}

func (w cancelOnWrite) Write(p []byte) (int, error) {
	w.cancel()
	return len(p), nil
}

func TestContextWriterObservesCancellationDuringWrite(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	writer := contextWriter{ctx: ctx, w: cancelOnWrite{cancel: cancel}}
	if n, err := writer.Write([]byte("synthetic")); n != 9 || !errors.Is(err, context.Canceled) {
		t.Fatal("write cancellation not propagated", n, err)
	}
	if n, err := writer.Write([]byte("more")); n != 0 || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled writer continued", n, err)
	}
}

func TestWriteNewUsesExclusiveFailureCleanup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "record.json")
	failure := errors.New("synthetic write failure")
	if err := writeFileNew(path, func(w io.Writer) error {
		if _, err := w.Write([]byte("partial")); err != nil {
			return err
		}
		return failure
	}); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("failed new file retained", err)
	}
	if err := WriteNew(path, []byte("complete")); err != nil {
		t.Fatal(err)
	}
	if err := WriteNew(path, []byte("replacement")); err == nil {
		t.Fatal("existing record replaced")
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "complete" {
		t.Fatal("existing record changed", err)
	}
}
