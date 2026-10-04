package core

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// An explicit benchmark measures the derived index, not a million-object
// acquisition or native forensic accuracy. Run with -benchtime=1x.
func BenchmarkCaseIndexMillion(b *testing.B) {
	for attempt := 0; attempt < b.N; attempt++ {
		ctx := context.Background()
		dir := b.TempDir()
		path := filepath.Join(dir, "index.sqlite")
		w, err := newCaseIndex(ctx, path)
		if err != nil {
			b.Fatal(err)
		}
		digest := strings.Repeat("a", 64)
		stamp := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
		row := CaseRow{Kind: "event", Collection: "synthetic", Digest: digest, Host: "host", Evidence: "E1", Source: "synthetic.jsonl", Time: &stamp, Payload: JSON(Event{Time: stamp, Evidence: "E1", Detail: "synthetic benchmark"})}
		start := time.Now()
		var peakHeap uint64
		for i := 0; i < caseIndexLimit; i++ {
			stamp = stamp.Add(time.Nanosecond)
			if err = w.add(ctx, row, "synthetic benchmark"); err != nil {
				w.close()
				b.Fatal(err)
			}
			if i%10000 == 0 {
				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				peakHeap = max(peakHeap, m.HeapInuse)
			}
		}
		if err = w.add(ctx, row, "one omitted row"); err != nil || !w.limited || w.eligible != caseIndexLimit+1 {
			w.close()
			b.Fatal("million row bound", err)
		}
		if err = w.finish(); err != nil {
			b.Fatal(err)
		}
		b.ReportMetric(time.Since(start).Seconds(), "insert_seconds")
		b.ReportMetric(float64(peakHeap)/(1<<20), "sampled_heap_MiB")
		start = time.Now()
		page, err := QueryCase(ctx, path, CaseQuery{Digest: digest, Evidence: "E1", Limit: 200, Offset: 999800})
		if err != nil || len(page.Rows) != 200 || page.More {
			b.Fatal("last page mismatch", err)
		}
		b.ReportMetric(float64(time.Since(start).Microseconds())/1000, "last_page_ms")
		start = time.Now()
		page, err = QueryCase(ctx, path, CaseQuery{Text: "missing marker", Limit: 200})
		if err != nil || len(page.Rows) != 0 {
			b.Fatal("literal scan mismatch", err)
		}
		b.ReportMetric(float64(time.Since(start).Microseconds())/1000, "negative_search_ms")
		start = time.Now()
		if err = exportCaseIndex(ctx, path, filepath.Join(dir, "events.csv")); err != nil {
			b.Fatal(err)
		}
		b.ReportMetric(time.Since(start).Seconds(), "csv_seconds")
		info, err := os.Stat(path)
		if err != nil {
			b.Fatal(err)
		}
		b.ReportMetric(float64(info.Size())/(1<<20), "index_MiB")
	}
}
