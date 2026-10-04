package core

import (
	"context"
	"encoding/csv"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestCaseExportsPreserveRowsAndChronologicalTies(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "index.sqlite")
	index, err := newCaseIndex(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer index.close()
	exports, err := newCaseExports(ctx, index.tx)
	if err != nil {
		t.Fatal(err)
	}
	defer exports.close()
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	times := []time.Time{base.Add(time.Nanosecond), base, {}, time.Unix(-1, 20), base, base.Add(10 * time.Nanosecond)}
	var inventory, timeline [][]string
	var body []bodyfileRow
	for i, stamp := range times {
		it := Item{ID: "E" + strconv.Itoa(i), Source: "=formula,source|\n" + strconv.Itoa(i), Size: int64(i), SHA256: strings.Repeat("A", 64), Modified: stamp}
		id := FileIdentity{MediaType: "application/octet-stream", ExtensionMismatch: i%2 == 0}
		if err = exports.add(ctx, "@host", "collection", it, id); err != nil {
			t.Fatal(err)
		}
		inventory = append(inventory, []string{"@host", "collection", it.ID, it.Source, strconv.Itoa(i), strings.ToLower(it.SHA256), id.MediaType, strconv.FormatBool(id.ExtensionMismatch)})
		body = append(body, bodyfileRow{Name: "@host/" + it.Source, Size: it.Size, Modified: stamp})
		if !stamp.IsZero() {
			timeline = append(timeline, []string{stamp.UTC().Format(time.RFC3339Nano), "file_modified", "@host", "collection", it.ID, it.Source})
		}
	}
	boundaries := []CaseEvent{{Time: base, Type: "collection_finished", Host: "@host", Collection: "collection"}, {Time: base, Type: "collection_started", Host: "@host", Collection: "collection"}}
	if err = exports.boundaries(ctx, boundaries); err != nil {
		t.Fatal(err)
	}
	for _, ev := range boundaries {
		timeline = append(timeline, []string{ev.Time.UTC().Format(time.RFC3339Nano), ev.Type, ev.Host, ev.Collection, "", ev.Source})
	}
	sort.SliceStable(timeline, func(i, j int) bool {
		left, _ := time.Parse(time.RFC3339Nano, timeline[i][0])
		right, _ := time.Parse(time.RFC3339Nano, timeline[j][0])
		return left.Before(right)
	})
	if err = exports.close(); err != nil {
		t.Fatal(err)
	}
	// A full examination index must not silently truncate legacy inventory.
	index.count = caseIndexLimit
	if err = index.add(ctx, CaseRow{}, "omitted"); err != nil || !index.limited {
		t.Fatal(err)
	}
	if err = index.finish(); err != nil {
		t.Fatal(err)
	}
	if err = exportLegacyCase(ctx, path, dir); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string][][]string{"inventory.csv": inventory, "timeline.csv": timeline} {
		file, err := os.Open(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		got, err := csv.NewReader(file).ReadAll()
		file.Close()
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range want {
			for i := range row {
				row[i] = csvSafe(row[i])
			}
		}
		if !reflect.DeepEqual(got[1:], want) {
			t.Fatalf("%s rows differ: got %v want %v", name, got[1:], want)
		}
	}
	wantBody := filepath.Join(dir, "expected-body.txt")
	if err = writeBodyfile(body, wantBody); err != nil {
		t.Fatal(err)
	}
	want, _ := os.ReadFile(wantBody)
	got, _ := os.ReadFile(filepath.Join(dir, "bodyfile.txt"))
	if string(got) != string(want) {
		t.Fatal("bodyfile bytes differ")
	}
	if err = exportLegacyCase(ctx, path, dir); err == nil {
		t.Fatal("existing output overwritten")
	}
}

func TestCaseExportCancellationAndFailedOutputCleanup(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	index, err := newCaseIndex(ctx, filepath.Join(dir, "index.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer index.close()
	exports, err := newCaseExports(ctx, index.tx)
	if err != nil {
		t.Fatal(err)
	}
	exports.close()
	if err = index.finish(); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err = exportLegacyCase(canceled, filepath.Join(dir, "index.sqlite"), dir); err == nil {
		t.Fatal("cancellation ignored")
	}
	if _, err = os.Stat(filepath.Join(dir, "inventory.csv")); !os.IsNotExist(err) {
		t.Fatal("canceled export published", err)
	}
}
