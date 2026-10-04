package core

import (
	"encoding/csv"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestStreamingCSVFailureAndExclusiveOutput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rows.csv")
	failure := errors.New("synthetic emit failure")
	if err := writeCSVNew(path, func(w *csv.Writer) error { w.Write([]string{"partial"}); return failure }); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("partial export retained", err)
	}
	if err := writeCSVNew(path, func(w *csv.Writer) error { return w.Write([]string{"Café", "value,with comma"}) }); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	if err := writeCSVNew(path, func(w *csv.Writer) error { return nil }); err == nil {
		t.Fatal("existing CSV replaced")
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("existing bytes changed")
	}
}
