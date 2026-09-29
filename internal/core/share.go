package core

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const shareSchema = "k957-shared-report/1"
const sharePolicySchema = "k957-share-policy/1"

type SharePolicy struct {
	Schema   string   `json:"schema"`
	Keep     []string `json:"keep"`
	Literals []string `json:"literals,omitempty"`
}
type SharedPolicySummary struct {
	Keep            []string `json:"keep"`
	LiteralCount    int      `json:"literal_count"`
	FreeTextOmitted bool     `json:"free_text_omitted"`
}
type SharedItem struct {
	ID        string     `json:"id"`
	Source    string     `json:"source"`
	Kind      string     `json:"kind"`
	Size      int64      `json:"size"`
	Modified  *time.Time `json:"modified,omitempty"`
	Collected *time.Time `json:"collected,omitempty"`
	Changed   bool       `json:"changed_during_acquisition"`
}
type SharedFinding struct {
	ID       string `json:"id"`
	Rule     string `json:"rule"`
	Evidence string `json:"evidence"`
	Source   string `json:"source"`
	Line     int    `json:"line"`
	Review   string `json:"review"`
	Reviewer string `json:"reviewer,omitempty"`
}
type SharedEvent struct {
	CaptureContext
	Packet          int        `json:"packet,omitempty"`
	Protocol        string     `json:"protocol,omitempty"`
	SourcePort      uint16     `json:"source_port,omitempty"`
	DestinationPort uint16     `json:"destination_port,omitempty"`
	CapturedLength  int64      `json:"captured_length,omitempty"`
	OriginalLength  int64      `json:"original_length,omitempty"`
	TCPFlags        uint8      `json:"tcp_flags,omitempty"`
	Time            *time.Time `json:"time,omitempty"`
	Type            string     `json:"type"`
	Evidence        string     `json:"evidence"`
	Source          string     `json:"source"`
	Line            int        `json:"line"`
	ByteOffset      int64      `json:"byte_offset"`
	User            string     `json:"user,omitempty"`
	Host            string     `json:"host,omitempty"`
	SourceIP        string     `json:"source_ip,omitempty"`
	DestinationIP   string     `json:"destination_ip,omitempty"`
}
type SharedReference struct {
	CaptureContext
	Packet   int        `json:"packet,omitempty"`
	Evidence string     `json:"evidence"`
	Source   string     `json:"source"`
	Line     int        `json:"line"`
	Offset   int64      `json:"byte_offset"`
	Role     string     `json:"role"`
	Time     *time.Time `json:"time,omitempty"`
}
type SharedCorrelation struct {
	Kind       string            `json:"kind"`
	Value      string            `json:"value"`
	Events     int               `json:"events"`
	Sources    int               `json:"sources"`
	First      *time.Time        `json:"first,omitempty"`
	Last       *time.Time        `json:"last,omitempty"`
	References []SharedReference `json:"references"`
	Truncated  bool              `json:"references_truncated"`
}
type SharedReview struct {
	Sequence int        `json:"sequence"`
	Finding  string     `json:"finding"`
	Decision string     `json:"decision"`
	Analyst  string     `json:"analyst"`
	Created  *time.Time `json:"created,omitempty"`
}
type SharedCustody struct {
	Sequence   int        `json:"sequence"`
	Action     string     `json:"action"`
	Actor      string     `json:"actor"`
	From       string     `json:"from"`
	To         string     `json:"to"`
	Location   string     `json:"location"`
	OccurredAt *time.Time `json:"occurred_at,omitempty"`
	RecordedAt *time.Time `json:"recorded_at,omitempty"`
}
type SharedParse struct {
	Evidence string `json:"evidence"`
	Format   string `json:"format"`
	Rows     int    `json:"rows"`
	Parsed   int    `json:"parsed"`
	Skipped  int    `json:"skipped"`
	Limited  bool   `json:"limited"`
	HasError bool   `json:"has_error"`
}

// A separate allowlisted projection: never serialize a modified Analysis or
// Manifest. No raw notes, rules, signature payloads, hashes or reverse map leave.
type SharedReport struct {
	CaptureSummaries []SharedCaptureSummary `json:"capture_summaries,omitempty"`
	NetworkFlows     []SharedNetworkFlow    `json:"network_flows,omitempty"`
	Schema           string                 `json:"schema"`
	Version          string                 `json:"version"`
	ID               string                 `json:"id"`
	Created          time.Time              `json:"created"`
	Policy           SharedPolicySummary    `json:"policy"`
	Case             string                 `json:"case"`
	Host             string                 `json:"host"`
	Operator         string                 `json:"operator"`
	CollectionStatus string                 `json:"collection_status"`
	SourceIssueCount int                    `json:"source_issue_count"`
	SourceNoteCount  int                    `json:"source_note_count"`
	Items            []SharedItem           `json:"items"`
	Findings         []SharedFinding        `json:"findings"`
	Timeline         []SharedEvent          `json:"timeline"`
	Correlations     []SharedCorrelation    `json:"correlations"`
	Reviews          []SharedReview         `json:"reviews"`
	Custody          []SharedCustody        `json:"custody"`
	CurrentHolder    string                 `json:"current_holder,omitempty"`
	PendingTo        string                 `json:"pending_to,omitempty"`
	ParseSummaries   []SharedParse          `json:"parse_summaries"`
	Notes            []string               `json:"notes"`
}

func LoadSharePolicy(path string) (p SharePolicy, e error) {
	if path == "" {
		return SharePolicy{Schema: sharePolicySchema, Keep: []string{}, Literals: []string{}}, nil
	}
	b, e := ReadLimited(path, 1<<20)
	if e != nil {
		return p, e
	}
	// Reuse the strict, duplicate-key rejecting decoder used by custody data.
	if e = custodyJSON(b, &p); e != nil {
		return p, e
	}
	_, e = validateSharePolicy(p)
	return
}
func validateSharePolicy(p SharePolicy) (map[string]bool, error) {
	if p.Schema != sharePolicySchema || len(p.Keep) > 8 || len(p.Literals) > 100 {
		return nil, errors.New("invalid share policy schema or bounds")
	}
	allowed := map[string]bool{"case": true, "users": true, "hosts": true, "ips": true, "paths": true, "actors": true, "locations": true, "timestamps": true}
	keep := map[string]bool{}
	for _, s := range p.Keep {
		if !allowed[s] || keep[s] {
			return nil, errors.New("unknown or duplicate share keep category")
		}
		keep[s] = true
	}
	for _, s := range p.Literals {
		if strings.TrimSpace(s) == "" || len(s) > 512 || !utf8.ValidString(s) {
			return nil, errors.New("invalid share literal; 1..512 UTF-8 bytes required")
		}
	}
	return keep, nil
}

type shareMasker struct {
	keep         map[string]bool
	aliases      map[string]string
	counts       map[string]int
	replacements *regexp.Regexp
}

func (m *shareMasker) value(kind, s string) string {
	if s == "" {
		return ""
	}
	if m.keep[kind] {
		if m.replacements != nil {
			return m.replacements.ReplaceAllLiteralString(s, "[MASKED]")
		}
		return s
	}
	key := kind + "\x00" + s
	if alias, ok := m.aliases[key]; ok {
		return alias
	}
	m.counts[kind]++
	alias := fmt.Sprintf("[%s-%06d]", strings.ToUpper(kind), m.counts[kind])
	m.aliases[key] = alias
	return alias
}
func (m *shareMasker) stamp(t time.Time) *time.Time {
	if !m.keep["timestamps"] || t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}
func shareEnum(s string, allowed ...string) string {
	for _, a := range allowed {
		if s == a {
			return s
		}
	}
	return "other"
}
func newShareMasker(a Analysis, p SharePolicy) (*shareMasker, error) {
	keep, e := validateSharePolicy(p)
	if e != nil {
		return nil, e
	}
	m := &shareMasker{keep: keep, aliases: map[string]string{}, counts: map[string]int{}}
	// Fully masked reports contain no retained source text to search.
	anyText := false
	for k := range keep {
		if k != "timestamps" {
			anyText = true
		}
	}
	if !anyText {
		return m, nil
	}
	terms := map[string]bool{}
	size := 0
	add := func(kind, s string) {
		if s != "" && !keep[kind] && !terms[s] {
			terms[s] = true
			size += len(regexp.QuoteMeta(s))
		}
	}
	add("case", a.Manifest.Case)
	add("hosts", a.Manifest.Host)
	add("actors", a.Manifest.Operator)
	for _, x := range a.Manifest.Epochs {
		add("hosts", x.Host)
	}
	for _, x := range a.Manifest.Items {
		add("paths", x.Source)
	}
	for _, x := range a.Findings {
		add("paths", x.Source)
		add("actors", x.Reviewer)
	}
	for _, x := range a.Timeline {
		add("paths", x.Source)
		add("users", x.User)
		add("hosts", x.Host)
		add("ips", x.SourceIP)
		add("ips", x.DestinationIP)
	}
	for _, x := range a.Correlations {
		kind := map[string]string{"user": "users", "host": "hosts", "ip": "ips"}[x.Kind]
		if kind != "" {
			add(kind, x.Value)
		}
		for _, r := range x.References {
			add("paths", r.Source)
		}
	}
	for _, x := range a.ReviewHistory {
		add("actors", x.Analyst)
	}
	if a.Custody != nil {
		add("actors", a.Custody.CurrentHolder)
		add("actors", a.Custody.PendingTo)
		for _, x := range a.Custody.Events {
			add("actors", x.Actor)
			add("actors", x.From)
			add("actors", x.To)
			add("locations", x.Location)
		}
	}
	for _, f := range a.NetworkFlows {
		add("paths", f.Source)
		add("ips", f.SourceIP)
		add("ips", f.DestinationIP)
	}
	for _, c := range a.CaptureSummaries {
		add("paths", c.Source)
	}
	for _, s := range p.Literals {
		add("literal", s)
	}
	if len(terms) > 20000 || size > 1<<20 {
		return nil, errors.New("share retained-text matching budget exceeded; use fully masked policy")
	}
	if len(terms) > 0 {
		patterns := make([]string, 0, len(terms))
		for s := range terms {
			patterns = append(patterns, regexp.QuoteMeta(s))
		}
		sort.Strings(patterns)
		m.replacements, e = regexp.Compile("(?i)(?:" + strings.Join(patterns, "|") + ")")
		if e != nil {
			return nil, errors.New("share matching pattern exceeds supported complexity")
		}
		m.replacements.Longest()
	}
	return m, nil
}

// BuildSharedReport accepts a fresh, verified analysis and retains only explicitly
// selected fields. Its result is not a signed evidence or review input.
func BuildSharedReport(a Analysis, p SharePolicy) (s SharedReport, err error) {
	if a.Version != Version || !validHash(a.EvidenceDigest) {
		return s, errors.New("current verified analysis required for sharing")
	}
	m, e := newShareMasker(a, p)
	if e != nil {
		return s, e
	}
	keep := append([]string{}, p.Keep...)
	sort.Strings(keep)
	s = SharedReport{Schema: shareSchema, Version: Version, ID: ID(), Created: time.Now().UTC(), Policy: SharedPolicySummary{Keep: keep, LiteralCount: len(p.Literals), FreeTextOmitted: true}, Case: m.value("case", a.Manifest.Case), Host: m.value("hosts", a.Manifest.Host), Operator: m.value("actors", a.Manifest.Operator), CollectionStatus: shareEnum(a.Manifest.Status, "complete", "partial"), SourceIssueCount: len(a.Manifest.Issues), SourceNoteCount: len(a.Notes), Items: []SharedItem{}, Findings: []SharedFinding{}, Timeline: []SharedEvent{}, Correlations: []SharedCorrelation{}, Reviews: []SharedReview{}, Custody: []SharedCustody{}, ParseSummaries: []SharedParse{}, Notes: []string{
		"Bu çıktı maskelenmiş türev rapordur; özgün delil, analist kararı veya imzalı devir kaydı yerine kullanılamaz.",
		"Alıntılar, olay açıklamaları, kural içerikleri, notlar, hata metinleri, kapsam, imzalar, hashler ve özgün kimlikler çıkarıldı. Ayrıntılı sınırlamalar özgün raporda bulunur.",
		"Takma değerler yalnızca bu raporda tutarlıdır; geri eşleme tablosu verilmez. Sayılar, dosya boyutları, ilişkiler, satır/byte konumları ve sıralama korunur; anonimlik garantisi yoktur.",
		"Açık bırakılan metin alanlarında bilinen maskeli değerler ve ek literal ifadeler büyük/küçük harf duyarsız değiştirilir. Alternatif yazımlar, kodlamalar veya bilinmeyen kişisel bilgiler otomatik tespit edilmez.",
		"Paylaşmadan önce raporu inceleyin. Rapordaki oluşturma zamanı bu türev rapora aittir; kaynak zamanları yalnızca timestamps açık bırakılmışsa gösterilir.",
	}}
	ids := map[string]string{}
	for i, x := range a.Manifest.Items {
		ids[x.ID] = fmt.Sprintf("E%06d", i+1)
	}
	sourceID := func(id string) string {
		if v, ok := ids[id]; ok {
			return v
		}
		return "unmapped"
	}
	ruleIDs := map[string]string{}
	for i, r := range a.Rules {
		ruleIDs[r.ID] = fmt.Sprintf("R%04d", i+1)
	}
	findingIDs := map[string]string{}
	for _, x := range a.Manifest.Items {
		s.Items = append(s.Items, SharedItem{ID: sourceID(x.ID), Source: m.value("paths", x.Source), Kind: shareEnum(x.Kind, "file", "snapshot"), Size: x.Size, Modified: m.stamp(x.Modified), Collected: m.stamp(x.Collected), Changed: x.Changed})
	}
	for i, x := range a.Findings {
		fid := fmt.Sprintf("F%06d", i+1)
		findingIDs[x.ID] = fid
		rule := ruleIDs[x.Rule]
		if rule == "" {
			rule = "unmapped"
		}
		s.Findings = append(s.Findings, SharedFinding{ID: fid, Rule: rule, Evidence: sourceID(x.Evidence), Source: m.value("paths", x.Source), Line: x.Line, Review: shareEnum(x.Review, "unreviewed", "confirmed", "rejected", "needs-review"), Reviewer: m.value("actors", x.Reviewer)})
	}
	for _, x := range a.Timeline {
		s.Timeline = append(s.Timeline, SharedEvent{CaptureContext: x.CaptureContext, Packet: x.Packet, Protocol: shareNetworkProtocol(x.Protocol), SourcePort: x.SourcePort, DestinationPort: x.DestinationPort, CapturedLength: x.CapturedLength, OriginalLength: x.OriginalLength, TCPFlags: x.TCPFlags, Time: m.stamp(x.Time), Type: shareEnum(x.Type, "collected", "file_modified", "log_timestamp", "pcap_packet", "windows_event"), Evidence: sourceID(x.Evidence), Source: m.value("paths", x.Source), Line: x.Line, ByteOffset: x.ByteOffset, User: m.value("users", x.User), Host: m.value("hosts", x.Host), SourceIP: m.value("ips", x.SourceIP), DestinationIP: m.value("ips", x.DestinationIP)})
	}
	for _, x := range a.Correlations {
		kind := map[string]string{"user": "users", "host": "hosts", "ip": "ips"}[x.Kind]
		if kind == "" {
			continue
		}
		c := SharedCorrelation{Kind: x.Kind, Value: m.value(kind, x.Value), Events: x.Events, Sources: x.Sources, First: m.stamp(x.First), Last: m.stamp(x.Last), Truncated: x.Truncated, References: []SharedReference{}}
		for _, r := range x.References {
			c.References = append(c.References, SharedReference{CaptureContext: r.CaptureContext, Packet: r.Packet, Evidence: sourceID(r.Evidence), Source: m.value("paths", r.Source), Line: r.Line, Offset: r.Offset, Role: shareEnum(r.Role, "user", "host", "source_ip", "destination_ip", "source_ip,destination_ip"), Time: m.stamp(r.Time)})
		}
		s.Correlations = append(s.Correlations, c)
	}
	for _, x := range a.ReviewHistory {
		fid := findingIDs[x.Finding]
		if fid == "" {
			fid = "unmapped"
		}
		s.Reviews = append(s.Reviews, SharedReview{Sequence: x.Sequence, Finding: fid, Decision: shareEnum(x.Decision, "confirmed", "rejected", "needs-review"), Analyst: m.value("actors", x.Analyst), Created: m.stamp(x.Created)})
	}
	if a.Custody != nil {
		s.CurrentHolder = m.value("actors", a.Custody.CurrentHolder)
		s.PendingTo = m.value("actors", a.Custody.PendingTo)
		for _, x := range a.Custody.Events {
			s.Custody = append(s.Custody, SharedCustody{Sequence: x.Sequence, Action: shareEnum(x.Action, "register", "transfer", "accept", "cancel", "note"), Actor: m.value("actors", x.Actor), From: m.value("actors", x.From), To: m.value("actors", x.To), Location: m.value("locations", x.Location), OccurredAt: m.stamp(x.OccurredAt), RecordedAt: m.stamp(x.RecordedAt)})
		}
	}
	for _, x := range a.ParseSummaries {
		s.ParseSummaries = append(s.ParseSummaries, SharedParse{Evidence: sourceID(x.Evidence), Format: shareEnum(x.Format, "CSV", "JSONL", "text/RFC3339", "PCAP", "PCAPNG", windowsXMLFormat), Rows: x.Rows, Parsed: x.Parsed, Skipped: x.Skipped, Limited: x.Limited, HasError: x.Error != ""})
	}
	projectSharedNetwork(a, &s, m, sourceID)
	return s, nil
}
