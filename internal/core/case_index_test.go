package core

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCaseIndexScopePagesAndLiteralSearch(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "index.sqlite")
	w, e := newCaseIndex(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	defer w.close()
	digests := []string{strings.Repeat("a", 64), strings.Repeat("b", 64)}
	for i := 0; i < 3; i++ {
		stamp := time.Date(2024, 1, 1, 0, 0, 0, i, time.UTC)
		row := CaseRow{Kind: "event", Collection: "collection", Digest: digests[i%2], Host: "host", Evidence: "E1", Source: "=formula", Time: &stamp, Payload: JSON(Event{Evidence: "E1", Detail: "literal%_ marker"})}
		if e = w.add(ctx, row, "literal%_ marker"); e != nil {
			t.Fatal(e)
		}
	}
	if e = w.finish(); e != nil {
		t.Fatal(e)
	}
	page, e := QueryCase(ctx, path, CaseQuery{Limit: 1, Text: "%_"})
	if e != nil || len(page.Rows) != 1 || !page.More {
		t.Fatalf("%+v %v", page, e)
	}
	first := page.Rows[0].Time
	page, e = QueryCase(ctx, path, CaseQuery{Limit: 2, Digest: digests[1], Evidence: "E1"})
	if e != nil || len(page.Rows) != 1 || page.Rows[0].Digest != digests[1] {
		t.Fatalf("scope failure %+v %v", page, e)
	}
	page, e = QueryCase(ctx, path, CaseQuery{Limit: 2, After: first, Before: first})
	if e != nil || len(page.Rows) != 1 {
		t.Fatalf("timestamp precision lost %+v %v", page, e)
	}
	for _, q := range []CaseQuery{{Limit: 0}, {Limit: 201}, {Limit: 1, Offset: -1}, {Limit: 1, Kind: "event' OR 1=1"}, {Limit: 1, Digest: "fake"}} {
		if _, e = QueryCase(ctx, path, q); e == nil {
			t.Fatal("invalid bounds accepted", q)
		}
	}
	if _, e = QueryCase(ctx, path, CaseQuery{Limit: 1, Text: "' OR 1=1 --"}); e != nil {
		t.Fatal(e)
	}
	dest := filepath.Join(t.TempDir(), "export.csv")
	if e = exportCaseIndex(ctx, path, dest); e != nil {
		t.Fatal(e)
	}
	body, e := os.ReadFile(dest)
	if e != nil || !strings.Contains(string(body), "'=formula") {
		t.Fatalf("unsafe CSV %s %v", body, e)
	}
}

func TestCaseIndexLimitIsDisclosed(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "index.sqlite")
	w, e := newCaseIndex(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	defer w.close()
	w.count = caseIndexLimit
	if e = w.add(ctx, CaseRow{Kind: "event", Payload: []byte("{}")}, ""); e != nil {
		t.Fatal(e)
	}
	if !w.limited || w.eligible != 1 || w.events != 0 {
		t.Fatal("limit was concealed")
	}
}
