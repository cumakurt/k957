package core

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTemporalCorrelationOmitsUntimedRecords(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	index := filepath.Join(dir, "case-index.sqlite")
	w, err := newCaseIndex(ctx, index)
	if err != nil {
		t.Fatal(err)
	}
	defer w.close()
	stamp := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 4; i++ {
		digest := strings.Repeat(string(rune('a'+i)), 64)
		ev := Event{Type: "log", Evidence: "E1", SourceIP: "192.0.2.1"}
		var indexedTime *time.Time
		if i >= 2 {
			ev.Time = stamp
			indexedTime = &stamp
		}
		if err := w.add(ctx, CaseRow{Kind: "event", Digest: digest, Evidence: "E1", Time: indexedTime, Payload: JSON(ev)}, "synthetic"); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.finish(); err != nil {
		t.Fatal(err)
	}
	p, err := LoadTemporalPolicy("")
	if err != nil {
		t.Fatal(err)
	}
	r, err := CorrelateCase(ctx, dir, "source_ip", time.Minute, p)
	if err != nil || len(r.Groups) != 1 {
		t.Fatalf("untimed records became temporal candidates: groups=%d err=%v", len(r.Groups), err)
	}
	for _, ref := range r.Groups[0].References {
		if !ref.EstimatedUTC.Equal(stamp) || ref.Reference.Time.IsZero() {
			t.Fatal("candidate has fabricated absolute time")
		}
	}
	if c := r.Coverage[0]; c.Eligible != 4 || c.Emitted != 2 || c.Reasons["missing_absolute_time"] != 2 {
		t.Fatalf("missing time coverage lost: %+v", c)
	}
	page, err := QueryCase(ctx, index, CaseQuery{Kind: "event", Limit: 10})
	if err != nil || len(page.Rows) != 4 {
		t.Fatal("untimed original records removed", err)
	}
}
