package core

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"time"
)

type ReportMetric struct {
	Label string
	Count int64
	Width int
}
type ReportBrief struct {
	Cover                                        []ReportMetric
	Reviews                                      []ReportMetric
	Timeline                                     []ReportMetric
	Types                                        []ReportMetric
	Confirmed, Unreviewed, Rejected, NeedsReview int
	DatedEvents                                  int
	MemoryBytes                                  uint64
	MemoryResults                                int64
}

func reportBrief(a Analysis) ReportBrief {
	objects := len(a.Manifest.Items)
	ids := map[string]bool{}
	for _, it := range a.Manifest.Items {
		ids[it.ID] = true
	}
	for _, m := range a.Memories {
		if !ids[m.Evidence] {
			objects++
		}
	}
	b := ReportBrief{Cover: []ReportMetric{{"Evidence objects", int64(objects), 0}, {"Reviewable findings", int64(len(a.Findings)), 0}, {"Timeline rows", int64(len(a.Timeline)), 0}, {"Collection issues", int64(len(a.Manifest.Issues) + len(a.CollectionIssues)), 0}}}
	for _, f := range a.Findings {
		switch f.Review {
		case "confirmed":
			b.Confirmed++
		case "rejected":
			b.Rejected++
		case "needs-review":
			b.NeedsReview++
		default:
			b.Unreviewed++
		}
	}
	total := max(1, len(a.Findings))
	b.Reviews = []ReportMetric{{"Confirmed", int64(b.Confirmed), 100 * b.Confirmed / total}, {"Unreviewed", int64(b.Unreviewed), 100 * b.Unreviewed / total}, {"Needs review", int64(b.NeedsReview), 100 * b.NeedsReview / total}, {"Rejected", int64(b.Rejected), 100 * b.Rejected / total}}
	for _, m := range a.Memories {
		b.MemoryBytes += m.Bytes
		if m.Results != nil {
			b.MemoryResults += m.Results.Rows
		}
	}
	var first, last time.Time
	for _, e := range a.Timeline {
		if e.Time.IsZero() {
			continue
		}
		b.DatedEvents++
		if first.IsZero() || e.Time.Before(first) {
			first = e.Time
		}
		if last.IsZero() || last.Before(e.Time) {
			last = e.Time
		}
	}
	if b.DatedEvents > 0 {
		bins := 12
		if first.Equal(last) {
			bins = 1
		}
		counts := make([]int64, bins)
		start := float64(first.Unix()) + float64(first.Nanosecond())/1e9
		end := float64(last.Unix()) + float64(last.Nanosecond())/1e9
		for _, e := range a.Timeline {
			if e.Time.IsZero() {
				continue
			}
			slot := 0
			if end > start {
				at := float64(e.Time.Unix()) + float64(e.Time.Nanosecond())/1e9
				slot = min(bins-1, max(0, int((at-start)/(end-start)*float64(bins))))
			}
			counts[slot]++
		}
		peak := int64(1)
		for _, n := range counts {
			peak = max(peak, n)
		}
		for i, n := range counts {
			stamp := first
			if bins > 1 {
				seconds := start + (end-start)*float64(i)/float64(bins)
				stamp = time.Unix(int64(seconds), 0).UTC()
			}
			b.Timeline = append(b.Timeline, ReportMetric{stamp.UTC().Format("2006-01-02 15:04"), n, int(n * 100 / peak)})
		}
	}
	types := countTypes(a.Timeline)
	peak := 1
	for _, t := range types {
		peak = max(peak, t.Count)
	}
	for _, t := range types {
		b.Types = append(b.Types, ReportMetric{t.Type, int64(t.Count), t.Count * 100 / peak})
	}
	return b
}

type ReviewQueueEntry struct {
	Finding  string `json:"finding_id"`
	Priority int    `json:"priority"`
	Basis    string `json:"basis"`
	Evidence string `json:"evidence"`
	Source   string `json:"source"`
	Review   string `json:"review"`
}

func reviewQueue(a Analysis) []ReviewQueueEntry {
	rules := map[string]Rule{}
	for _, r := range a.Rules {
		rules[r.ID] = r
	}
	queue := make([]ReviewQueueEntry, 0, len(a.Findings))
	for _, f := range a.Findings {
		rank, basis := 4, "Literal match; source context and analyst review required"
		r := rules[f.Rule]
		if r.SHA256 != "" {
			rank, basis = 2, "Exact file hash match to the supplied rule; list provenance requires review"
		} else if r.Event != nil {
			rank, basis = 3, "Structured event predicate; no malware verdict implied"
		}
		switch f.Review {
		case "confirmed":
			rank, basis = 1, "Examiner confirmed this finding; consult the signed decision and reason"
		case "needs-review":
			rank, basis = 2, "Examiner requested further review"
		case "rejected":
			rank, basis = 5, "Examiner rejected this finding; retain the decision for audit"
		}
		queue = append(queue, ReviewQueueEntry{f.ID, rank, basis, f.Evidence, f.Source, f.Review})
	}
	sort.SliceStable(queue, func(i, j int) bool { return queue[i].Priority < queue[j].Priority })
	return queue
}
func exportPortableAnalysis(ctx context.Context, a Analysis, out string) error {
	if e := exportAttackLayer(a, out); e != nil {
		return e
	}
	if e := exportIndicators(a, out); e != nil {
		return e
	}
	if err := WriteJSONNew(filepath.Join(out, "review-queue.json"), struct {
		Schema string             `json:"schema"`
		Note   string             `json:"note"`
		Rows   []ReviewQueueEntry `json:"rows"`
	}{"k957-review-queue/1", "Priority is a documented review order, not a threat probability or severity score. Volume does not affect rank.", reviewQueue(a)}); err != nil {
		return err
	}
	path := filepath.Join(out, "timeline.jsonl")
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	encoder := json.NewEncoder(f)
	for _, ev := range a.Timeline {
		if e = ctx.Err(); e != nil {
			return e
		}
		if ev.Time.IsZero() {
			continue
		}
		row := struct {
			Message       string        `json:"message"`
			Datetime      string        `json:"datetime"`
			TimestampDesc string        `json:"timestamp_desc"`
			Evidence      string        `json:"evidence_id"`
			Source        string        `json:"source"`
			Line          int           `json:"line"`
			Offset        int64         `json:"byte_offset"`
			RawTime       string        `json:"original_time,omitempty"`
			Record        *NativeRecord `json:"native,omitempty"`
		}{ev.Detail, ev.Time.UTC().Format(time.RFC3339Nano), ev.Type, ev.Evidence, ev.Source, ev.Line, ev.ByteOffset, ev.OriginalTime, ev.Native}
		if row.Message == "" {
			row.Message = ev.Type + " · " + ev.Source
		}
		if e = encoder.Encode(row); e != nil {
			return e
		}
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	hashes := map[string]bool{}
	for _, item := range a.Manifest.Items {
		if validHash(item.SHA256) {
			hashes[item.SHA256] = true
		}
	}
	for _, m := range a.Memories {
		if validHash(m.SHA256) {
			hashes[m.SHA256] = true
		}
	}
	ips := map[string]bool{}
	for _, ev := range a.Timeline {
		for _, value := range []string{ev.SourceIP, ev.DestinationIP} {
			if ip := net.ParseIP(value); ip != nil {
				ips[ip.String()] = true
			}
		}
	}
	for name, values := range map[string]map[string]bool{"file-sha256.txt": hashes, "ip-addresses.txt": ips} {
		if e := writeLinesNew(filepath.Join(out, name), sortedSet(values)); e != nil {
			return e
		}
	}
	return WriteJSONNew(filepath.Join(out, "portable-exports.json"), struct {
		Schema string `json:"schema"`
		Digest string `json:"source_analysis_digest"`
		Events int    `json:"dated_events"`
		Files  int    `json:"distinct_sha256"`
		IPs    int    `json:"distinct_ips"`
		Note   string `json:"note"`
	}{"k957-portable-exports/1", digestJSON(a), reportBrief(a).DatedEvents, len(hashes), len(ips), "timeline.jsonl uses the Timesketch datetime/message/timestamp_desc fields and retains evidence references. Undated events are retained in analysis.json and timeline.csv. Hashes and IPs are observations, not threat-intelligence verdicts; no online lookup was performed."})
}
func writeLinesNew(path string, lines []string) error {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	for _, line := range lines {
		if _, e = fmt.Fprintln(f, line); e != nil {
			return e
		}
	}
	if e = f.Sync(); e != nil {
		return e
	}
	return f.Close()
}

func sortedSet(values map[string]bool) []string {
	rows := make([]string, 0, len(values))
	for value := range values {
		rows = append(rows, value)
	}
	sort.Strings(rows)
	return rows
}
