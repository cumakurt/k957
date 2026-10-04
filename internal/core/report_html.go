package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"sort"
	"strings"
	"time"
)

const reportPageSize = 25

// reportView is the examination document rendered to report.html.
// Counts and sentences come from the analysis record. Missing sections stay absent.
type reportView struct {
	USNGroups                                                                                           []usnGroupPreview
	USNGroupCount                                                                                       int
	Adaptive                                                                                            *AdaptiveSummary
	Indicators                                                                                          *IndicatorSummary
	Brief                                                                                               ReportBrief
	NetworkInterpretations                                                                              []NetworkInterpretation
	Coverage                                                                                            []Coverage
	ParseSummaries                                                                                      []ParseSummary
	FindingsTruncated, Canceled                                                                         bool
	HashSet                                                                                             *HashSetSummary
	Case, Host, System, Operator, Scope, Status, Signature, Version, Run, EvidenceDigest, PackageDigest string
	Started, Finished, Created, CollectionWindow, TimelineSpan, Lead                                    string
	ItemCount, FindingCount, IssueCount, Unreviewed, TimelineCount, SkipCount                           int
	ActivityCounts                                                                                      []ActivityCount
	Accounts                                                                                            []accountCount
	FindingGroups                                                                                       []findingGroup
	EventCounts                                                                                         []eventCount
	MediaCounts                                                                                         []mediaCount
	Persistence                                                                                         []Event
	Memories                                                                                            []memoryView
	Mismatches                                                                                          []FileIdentity
	HashMatches                                                                                         []HashMatch
	Correlations                                                                                        []Correlation
	Windows                                                                                             []Event
	Flows                                                                                               []NetworkFlow
	Captures                                                                                            []CaptureSummary
	Epochs                                                                                              []Epoch
	Reviews                                                                                             []ReviewEvent
	Custody                                                                                             *CustodyStatus
	ReviewSignature, ReviewDigest                                                                       string
	MethodNotes, SkipSample                                                                             []string
	Issues                                                                                              []Issue
	FindingsJSON, InventoryJSON                                                                         template.JS
	ParseCounts                                                                                         []eventCount
}

type findingGroup struct {
	Rule, Description string
	Count, Sources    int
	InMemory          bool
	Samples           []Finding
}

type accountCount struct {
	Name  string
	Count int
}

type eventCount struct {
	Type  string
	Count int
}

type mediaCount struct {
	Type  string
	Count int
}

type memoryView struct {
	MemoryAnalysis
	ByteLabel       string
	BannerPlausible bool
	Samples         []MemoryHit
	URLSample       []string
	ObsCounts       []eventCount
	ObsSample       []MemoryObservation
}

type findingRow struct {
	ID, Rule, Description, Evidence, Source, Excerpt, Review string
	Line                                                     int
}

type inventoryRow struct {
	ID, Source, Kind, SHA256 string
	Size                     int64
	Changed                  bool
}

func renderReportHTML(a Analysis) ([]byte, error) {
	view, e := newReportView(a)
	if e != nil {
		return nil, e
	}
	var b bytes.Buffer
	if e = reportHTMLTemplate.Execute(&b, view); e != nil {
		return nil, e
	}
	return b.Bytes(), nil
}

func newReportView(a Analysis) (reportView, error) {
	usnGroups := usnFileGroups(a.Timeline)
	v := reportView{
		USNGroups: previewUSNGroups(usnGroups), USNGroupCount: len(usnGroups),
		Adaptive:       a.Adaptive,
		Brief:          reportBrief(a),
		Indicators:     a.Indicators,
		Coverage:       analysisCoverage(a),
		ParseSummaries: a.ParseSummaries, FindingsTruncated: a.FindingsTruncated, Canceled: a.Canceled, HashSet: a.HashSet,
		Case: a.Manifest.Case, Host: a.Manifest.Host, Operator: a.Manifest.Operator,
		Scope: a.Manifest.Scope, Status: a.Manifest.Status, Signature: a.Signature,
		Version: a.Version, Run: a.Run, EvidenceDigest: a.EvidenceDigest, PackageDigest: a.PackageDigest,
		System:  a.Manifest.OS + "/" + a.Manifest.Arch,
		Started: reportTime(a.Manifest.Started), Finished: reportTime(a.Manifest.Finished),
		Created:   reportTime(a.Created),
		ItemCount: len(a.Manifest.Items), FindingCount: len(a.Findings),
		IssueCount: len(a.Manifest.Issues), TimelineCount: len(a.Timeline),
		ActivityCounts: a.ActivityCounts, Issues: a.Manifest.Issues,
		HashMatches: a.HashMatches, Correlations: a.Correlations,
		Windows: windowsEvents(a.Timeline), Flows: a.NetworkFlows, Captures: a.CaptureSummaries, NetworkInterpretations: a.NetworkInterpretations,
		Epochs: a.Manifest.Epochs, Reviews: a.ReviewHistory, Custody: a.Custody,
		ReviewSignature: a.ReviewSignature, ReviewDigest: a.ReviewDigest,
	}
	if a.CollectionStatus != "" {
		v.Status = a.CollectionStatus
		v.Issues = append(append([]Issue(nil), a.Manifest.Issues...), a.CollectionIssues...)
		v.IssueCount = len(v.Issues)
	}
	if v.Status == "" {
		v.Status = "not recorded"
	}
	if v.Signature == "" {
		v.Signature = "not recorded"
	}
	if v.Scope == "" {
		v.Scope = "not recorded"
	}
	if v.Operator == "" {
		v.Operator = "not recorded"
	}
	v.CollectionWindow = collectionWindow(a.Manifest.Started, a.Manifest.Finished)
	v.TimelineSpan = timelineSpan(a.Timeline)
	v.FindingGroups = groupFindings(a.Findings)
	v.EventCounts = countTypes(a.Timeline)
	v.MediaCounts = countMedia(a.FileTypes)
	v.Mismatches = mismatches(a.FileTypes, 12)
	v.Accounts = countAccounts(a.Activities)
	v.Persistence = persistenceEvents(a.Timeline, 40)
	v.MethodNotes, v.SkipSample, v.SkipCount = splitReportNotes(a.Notes)
	v.ParseCounts = countParse(a.ParseSummaries)
	for _, f := range a.Findings {
		if f.Review == "" || f.Review == "unreviewed" {
			v.Unreviewed++
		}
	}
	for _, m := range a.Memories {
		mv := memoryView{
			MemoryAnalysis: m, ByteLabel: reportBytes(m.Bytes), BannerPlausible: plausibleBanner(m.KernelBanner),
			Samples: sampleHits(m.Hits, 5), ObsCounts: observationCounts(m.Observations), ObsSample: sampleObservations(m.Observations, 16),
		}
		if len(m.URLs) > 8 {
			mv.URLSample = append([]string(nil), m.URLs[:8]...)
		} else {
			mv.URLSample = m.URLs
		}
		v.Memories = append(v.Memories, mv)
	}
	v.Lead = reportLead(v)
	findings, e := scriptJSON(slimFindings(a.Findings))
	if e != nil {
		return v, e
	}
	inventory, e := scriptJSON(slimInventory(a.Manifest.Items))
	if e != nil {
		return v, e
	}
	v.FindingsJSON, v.InventoryJSON = findings, inventory
	return v, nil
}

func reportLead(v reportView) string {
	lead := fmt.Sprintf("%s collected %d files from %s (%s).", v.Scope, v.ItemCount, v.Host, v.System)
	if len(v.Memories) == 1 {
		lead += fmt.Sprintf(" A %s %s memory image was scanned.", v.Memories[0].ByteLabel, v.Memories[0].Format)
	} else if len(v.Memories) > 1 {
		lead += fmt.Sprintf(" %d memory images were scanned.", len(v.Memories))
	} else {
		lead += " No memory image was included in this analysis."
	}
	lead += fmt.Sprintf(" Rule and hash-set checks recorded %d findings; %d have no analyst decision.", v.FindingCount, v.Unreviewed)
	return lead
}

func collectionWindow(start, end time.Time) string {
	if start.IsZero() && end.IsZero() {
		return "not recorded"
	}
	if start.IsZero() || end.IsZero() || end.Before(start) {
		return reportTime(start) + " – " + reportTime(end) + " UTC"
	}
	return reportTime(start) + " – " + reportTime(end) + " (" + reportDuration(end.Sub(start)) + ")"
}

func timelineSpan(events []Event) string {
	if len(events) == 0 {
		return "No timeline rows were recorded."
	}
	var start, end time.Time
	counts := map[string]int{}
	for _, e := range events {
		counts[e.Type]++
		if e.Time.IsZero() {
			continue
		}
		if start.IsZero() || e.Time.Before(start) {
			start = e.Time
		}
		if end.IsZero() || e.Time.After(end) {
			end = e.Time
		}
	}
	parts := make([]string, 0, len(counts))
	for _, c := range sortedCounts(counts) {
		parts = append(parts, fmt.Sprintf("%d %s", c.Count, c.Type))
	}
	span := "not recorded"
	if !start.IsZero() {
		span = reportTime(start) + " – " + reportTime(end)
	}
	return fmt.Sprintf("%d rows (%s). Earliest and latest source timestamps: %s. These are host-clock values converted to UTC, not one incident window.", len(events), strings.Join(parts, ", "), span)
}

func groupFindings(findings []Finding) []findingGroup {
	type acc struct {
		findingGroup
		seen map[string]bool
	}
	order := []string{}
	by := map[string]*acc{}
	for _, f := range findings {
		g := by[f.Rule]
		if g == nil {
			g = &acc{findingGroup: findingGroup{Rule: f.Rule, Description: f.Description}, seen: map[string]bool{}}
			by[f.Rule] = g
			order = append(order, f.Rule)
		}
		g.Count++
		if f.Source != "" && !g.seen[f.Source] {
			g.seen[f.Source] = true
			g.Sources++
		}
		if isMemorySource(f.Source) || f.Evidence == "MEMORY" {
			g.InMemory = true
		}
		if len(g.Samples) < 3 {
			g.Samples = append(g.Samples, f)
		}
	}
	out := make([]findingGroup, 0, len(order))
	for _, rule := range order {
		out = append(out, by[rule].findingGroup)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].InMemory != out[j].InMemory {
			return out[i].InMemory
		}
		if out[i].Count != out[j].Count {
			return out[i].Count < out[j].Count
		}
		return out[i].Rule < out[j].Rule
	})
	return out
}

func isMemorySource(source string) bool {
	return strings.HasSuffix(strings.ToLower(source), ".lime") || strings.HasSuffix(strings.ToLower(source), ".raw")
}

func countTypes(events []Event) []eventCount {
	counts := map[string]int{}
	for _, e := range events {
		name := e.Type
		if name == "" {
			name = "unspecified"
		}
		counts[name]++
	}
	return sortedCounts(counts)
}

func countMedia(ids []FileIdentity) []mediaCount {
	counts := map[string]int{}
	for _, id := range ids {
		name := id.MediaType
		if name == "" {
			name = "unidentified"
		}
		counts[name]++
	}
	rows := sortedCounts(counts)
	out := make([]mediaCount, 0, len(rows))
	for i, row := range rows {
		if i == 8 {
			break
		}
		out = append(out, mediaCount{Type: row.Type, Count: row.Count})
	}
	return out
}

func mismatches(ids []FileIdentity, limit int) []FileIdentity {
	var out []FileIdentity
	for _, id := range ids {
		if !id.ExtensionMismatch {
			continue
		}
		out = append(out, id)
		if len(out) == limit {
			break
		}
	}
	return out
}

func countAccounts(rows []Activity) []accountCount {
	counts := map[string]int{}
	for _, row := range rows {
		if row.User == "" {
			continue
		}
		counts[row.User]++
	}
	type pair struct {
		name  string
		count int
	}
	var pairs []pair
	for name, count := range counts {
		pairs = append(pairs, pair{name, count})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].count != pairs[j].count {
			return pairs[i].count > pairs[j].count
		}
		return pairs[i].name < pairs[j].name
	})
	out := make([]accountCount, 0, len(pairs))
	for i, p := range pairs {
		if i == 8 {
			break
		}
		out = append(out, accountCount{Name: p.name, Count: p.count})
	}
	return out
}

func persistenceEvents(events []Event, limit int) []Event {
	var out []Event
	for _, e := range events {
		switch e.Type {
		case "scheduled_task", "launch_agent", "systemd_exec", "prefetch":
			out = append(out, e)
			if len(out) == limit {
				return out
			}
		}
	}
	return out
}

func splitReportNotes(notes []string) (method, sample []string, skips int) {
	for _, note := range notes {
		if isItemSkip(note) {
			skips++
			if len(sample) < 5 {
				sample = append(sample, note)
			}
			continue
		}
		method = append(method, note)
	}
	return method, sample, skips
}

func isItemSkip(note string) bool {
	if strings.Contains(note, "non UTF-8") || strings.Contains(note, "binary text scan skipped") {
		return true
	}
	if len(note) > 2 && note[0] == 'E' {
		for i := 1; i < len(note) && note[i] != ':'; i++ {
			if note[i] < '0' || note[i] > '9' {
				return false
			}
			if note[i] == ':' {
				break
			}
		}
		return strings.Contains(note, ":")
	}
	return false
}

func countParse(rows []ParseSummary) []eventCount {
	counts := map[string]int{}
	for _, row := range rows {
		name := row.Format
		if name == "" {
			name = "unspecified"
		}
		counts[name]++
	}
	return sortedCounts(counts)
}

func sortedCounts(counts map[string]int) []eventCount {
	out := make([]eventCount, 0, len(counts))
	for name, count := range counts {
		out = append(out, eventCount{Type: name, Count: count})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Type < out[j].Type
	})
	return out
}

func observationCounts(rows []MemoryObservation) []eventCount {
	counts := map[string]int{}
	for _, row := range rows {
		name := row.Kind
		if name == "" {
			name = "unspecified"
		}
		counts[name]++
	}
	return sortedCounts(counts)
}

func sampleObservations(rows []MemoryObservation, limit int) []MemoryObservation {
	if len(rows) <= limit {
		return rows
	}
	return rows[:limit]
}

func sampleHits(hits []MemoryHit, limit int) []MemoryHit {
	if len(hits) <= limit {
		return hits
	}
	return hits[:limit]
}

func plausibleBanner(s string) bool {
	const prefix = "linux version "
	if len(s) <= len(prefix) || !strings.HasPrefix(strings.ToLower(s), prefix) {
		return false
	}
	c := s[len(prefix)]
	return c >= '0' && c <= '9'
}

func slimFindings(findings []Finding) []findingRow {
	out := make([]findingRow, 0, len(findings))
	for _, f := range findings {
		out = append(out, findingRow{ID: f.ID, Rule: f.Rule, Description: f.Description, Evidence: f.Evidence, Source: f.Source, Line: f.Line, Excerpt: f.Excerpt, Review: f.Review})
	}
	return out
}

func slimInventory(items []Item) []inventoryRow {
	out := make([]inventoryRow, 0, len(items))
	for _, it := range items {
		out = append(out, inventoryRow{ID: it.ID, Source: it.Source, Kind: it.Kind, Size: it.Size, SHA256: it.SHA256, Changed: it.Changed})
	}
	return out
}

// scriptJSON is safe inside a script element because encoding/json escapes
// <, > and & (including a closing script tag) as well as U+2028 and U+2029.
func scriptJSON(v any) (template.JS, error) {
	b, e := json.Marshal(v)
	if e != nil {
		return "", e
	}
	return template.JS(b), nil
}

func reportTime(t time.Time) string {
	if t.IsZero() {
		return "not recorded"
	}
	return t.UTC().Format(time.RFC3339)
}

func reportPreciseTime(t time.Time) string {
	if t.IsZero() {
		return "not recorded"
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func reportDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	d = d.Round(time.Second)
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm%02ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
}

func reportBytes(n uint64) string {
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	value := float64(n)
	unit := 0
	for value >= 1024 && unit < len(units)-1 {
		value /= 1024
		unit++
	}
	if unit == 0 {
		return fmt.Sprintf("%d B", n)
	}
	return fmt.Sprintf("%.1f %s", value, units[unit])
}
