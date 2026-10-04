package core

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type Rule struct {
	Techniques  []string   `json:"techniques,omitempty"`
	Event       *EventRule `json:"event,omitempty"`
	ID          string     `json:"id"`
	Description string     `json:"description"`
	Contains    string     `json:"contains"`
	SHA256      string     `json:"sha256"`
}
type Finding struct {
	Event       *EventReference `json:"event,omitempty"`
	ID          string          `json:"id"`
	Reviewer    string          `json:"reviewer,omitempty"`
	ReviewNote  string          `json:"review_note,omitempty"`
	Rule        string          `json:"rule"`
	Description string          `json:"description"`
	Evidence    string          `json:"evidence"`
	Source      string          `json:"source"`
	Line        int             `json:"line,omitempty"`
	Excerpt     string          `json:"excerpt,omitempty"`
	Review      string          `json:"review"`
}
type Event struct {
	USN      *USNReference         `json:"usn,omitempty"`
	Registry *RegistryReference    `json:"registry,omitempty"`
	Launchd  *LaunchdReference     `json:"launchd,omitempty"`
	Cloud    *CloudReference       `json:"cloud,omitempty"`
	Network  []ProtocolObservation `json:"network,omitempty"`
	Native   *NativeRecord         `json:"native,omitempty"`
	CaptureContext
	Windows         *WindowsEventContext `json:"windows,omitempty"`
	Packet          int                  `json:"packet,omitempty"`
	Protocol        string               `json:"protocol,omitempty"`
	SourcePort      uint16               `json:"source_port,omitempty"`
	DestinationPort uint16               `json:"destination_port,omitempty"`
	CapturedLength  int64                `json:"captured_length,omitempty"`
	OriginalLength  int64                `json:"original_length,omitempty"`
	TCPFlags        uint8                `json:"tcp_flags,omitempty"`
	User            string               `json:"user,omitempty"`
	Host            string               `json:"host,omitempty"`
	SourceIP        string               `json:"source_ip,omitempty"`
	DestinationIP   string               `json:"destination_ip,omitempty"`
	ByteOffset      int64                `json:"byte_offset,omitempty"`
	Line            int                  `json:"line,omitempty"`
	Detail          string               `json:"detail,omitempty"`
	OriginalTime    string               `json:"original_time,omitempty"`
	Time            time.Time            `json:"time"`
	Type            string               `json:"type"`
	Evidence        string               `json:"evidence"`
	Source          string               `json:"source"`
}

const findingLimit = 10000
const analysisEventLimit = 50000

type memoryOnlyKey struct{}

type Analysis struct {
	Adaptive               *AdaptiveSummary        `json:"adaptive_executables,omitempty"`
	Indicators             *IndicatorSummary       `json:"indicators,omitempty"`
	NetworkInterpretations []NetworkInterpretation `json:"network_interpretations,omitempty"`
	RuleEvaluations        []RuleEvaluation        `json:"rule_evaluations,omitempty"`
	ParserRuns             []ParserRun             `json:"parser_runs,omitempty"`
	Coverage               []Coverage              `json:"coverage,omitempty"`
	PackageDigest          string                  `json:"package_digest,omitempty"`
	CollectionStatus       string                  `json:"collection_status,omitempty"`
	CollectionIssues       []Issue                 `json:"collection_issues,omitempty"`
	FindingsTruncated      bool                    `json:"findings_truncated,omitempty"`
	Canceled               bool                    `json:"canceled,omitempty"`
	HashSet                *HashSetSummary         `json:"hash_set,omitempty"`
	Memories               []MemoryAnalysis        `json:"memories,omitempty"`
	CaptureSummaries       []CaptureSummary        `json:"capture_summaries,omitempty"`
	NetworkFlows           []NetworkFlow           `json:"network_flows,omitempty"`
	Custody                *CustodyStatus          `json:"custody,omitempty"`
	ParseSummaries         []ParseSummary          `json:"parse_summaries,omitempty"`
	Correlations           []Correlation           `json:"correlations,omitempty"`
	ReviewDigest           string                  `json:"review_digest,omitempty"`
	EvidenceDigest         string                  `json:"evidence_digest"`
	ReviewHistory          []ReviewEvent           `json:"review_history,omitempty"`
	ReviewSignature        string                  `json:"review_signature,omitempty"`
	Version                string                  `json:"version"`
	Run                    string                  `json:"run"`
	Created                time.Time               `json:"created"`
	Signature              string                  `json:"signature"`
	Manifest               Manifest                `json:"manifest"`
	Rules                  []Rule                  `json:"rules"`
	FileTypes              []FileIdentity          `json:"file_types,omitempty"`
	HashMatches            []HashMatch             `json:"hash_matches,omitempty"`
	Activities             []Activity              `json:"activities,omitempty"`
	ActivityCounts         []ActivityCount         `json:"activity_counts,omitempty"`
	Findings               []Finding               `json:"findings"`
	Timeline               []Event                 `json:"timeline"`
	Notes                  []string                `json:"notes"`
}

func LoadRules(path string) ([]Rule, error) {
	if path == "" {
		return []Rule{}, nil
	}
	b, e := ReadLimited(path, 1<<20)
	if e != nil {
		return nil, e
	}
	var rules []Rule
	if e = custodyJSON(b, &rules); e != nil {
		return nil, e
	}
	if len(rules) > 100 {
		return nil, errors.New("max 100 rules")
	}
	seen := map[string]bool{}
	for _, r := range rules {
		techniques := map[string]bool{}
		for _, id := range r.Techniques {
			if !attackTechniquePattern.MatchString(id) || techniques[id] {
				return nil, errors.New("techniques require unique ATT&CK IDs such as T1059 or T1059.001")
			}
			techniques[id] = true
		}
		conditions := 0
		if r.Contains != "" {
			conditions++
		}
		if r.SHA256 != "" {
			conditions++
		}
		if r.Event != nil {
			conditions++
		}
		if r.ID == "" || len(r.ID) > 256 || len(r.Description) > 4096 || seen[r.ID] || conditions != 1 {
			return nil, errors.New("each rule needs unique id and exactly one contains, sha256 or event condition")
		}
		if r.Event != nil {
			if _, _, e := prepareEventRule(*r.Event); e != nil {
				return nil, e
			}
		}
		seen[r.ID] = true
		if len(r.Contains) > 4096 {
			return nil, errors.New("rule pattern too long")
		}
		if r.SHA256 != "" {
			if len(r.SHA256) != 64 || strings.Trim(r.SHA256, "0123456789abcdef") != "" {
				return nil, errors.New("invalid rule hash")
			}
		}
	}
	return rules, nil
}
func Analyze(p *Package, rules []Rule) Analysis {
	return AnalyzeContext(context.Background(), p, rules)
}

func AnalyzeContext(ctx context.Context, p *Package, rules []Rule) Analysis {
	a := Analysis{EvidenceDigest: p.ManifestSHA256, Version: Version, Run: ID(), Created: time.Now().UTC(), Signature: p.Signature, Manifest: p.Manifest, Rules: rules, Findings: []Finding{}, Timeline: []Event{}, FileTypes: []FileIdentity{}, Notes: []string{"Timeline includes file metadata, explicit log/XML timestamps and supported PCAP packet timestamps; these are not proof of execution or user attribution.", "Literal, SHA-256 and structured event rules produce review candidates. Every finding requires analyst review.", "Text scanning covers supported UTF-8/XML records up to 8 MiB per file and 128 MiB total. Separate bounded workers interpret selected SQLite/WAL browser visits, EVTX system metadata, clean Registry key/value projections, binary launchd plists and exported USN v2/v3 records. USN names are not resolved paths, reason flags may accumulate changes, and journal coverage is not proven complete. CloudTrail exports and PCAP/PCAPNG have separate bounded parsers; unsupported binary formats remain inventory entries.", "Clock offsets are not measured. Timestamps reflect the source host clock converted to UTC.", "File types are magic-byte hints from the first 560 bytes, or explicit filename candidates for formats such as USN that require later record validation. An extension mismatch is recorded, not treated as a finding. bodyfile.txt exports mtime only; atime, ctime, crtime, uid, gid and MD5 are zero because SHA-256 is authoritative.", "Activity rows interpret SSH, sudo, cron, account creation, shell and PowerShell history, Windows security events, Prefetch names and persistence commands. They are triage readings, not findings and not proof of attribution."}}
	if p.Manifest.InventoryFrozen {
		a.Notes = append(a.Notes, "Resumable acquisition: inventory was frozen at the first run. Completed files are reused without rereading the source. Newly created source files are excluded.", "Parts can originate from different invocations. This package is not a single point-in-time snapshot. See acquisition epochs and part provenance in analysis.json.")
	}
	if p.Manifest.Acquisition != nil {
		a.Notes = append(a.Notes, "Acquisition method: "+p.Manifest.Acquisition.Method+"; origin: "+p.Manifest.Acquisition.Origin)
		a.Notes = append(a.Notes, p.Manifest.Acquisition.Notes...)
	}
	var scanned, captureBytes int64
	logCount := 0
	sessionCount := 0
	protocolCount, protocolBytes := 0, 0
	windowsXML := false
	platformArtifacts := false
	for i, it := range p.Manifest.Items {
		if ctx.Err() != nil {
			a.Canceled = true
			a.Notes = append(a.Notes, "Analysis canceled; remaining evidence objects were not examined")
			break
		}
		if only, _ := ctx.Value(memoryOnlyKey{}).(bool); only && !limeCandidate(p.Files[it.Object], it.Source) {
			continue
		}
		ReportProgress(ctx, Progress{Phase: "examine", Detail: it.Source, Step: i + 1, Steps: len(p.Manifest.Items)})
		identity := identifyVerifiedItem(p, it)
		a.FileTypes = append(a.FileTypes, identity)
		a.Timeline = append(a.Timeline, Event{Time: it.Collected, Type: "collected", Evidence: it.ID, Source: it.Source})
		if !it.Modified.IsZero() {
			a.Timeline = append(a.Timeline, Event{Time: it.Modified, Type: "file_modified", Evidence: it.ID, Source: it.Source})
		}
		for _, r := range rules {
			if r.SHA256 != "" && r.SHA256 == it.SHA256 {
				appendFinding(&a, Finding{Rule: r.ID, Description: r.Description, Evidence: it.ID, Source: it.Source, Review: "unreviewed"})
			}
		}
		if format := nativeFormat(identity); format != "" {
			result, run, e := analyzeNative(ctx, p, it, format, analysisEventLimit-logCount)
			if e != nil {
				result.Summary.Error = e.Error()
				run.Error = e.Error()
			}
			a.ParserRuns = append(a.ParserRuns, run)
			a.ParseSummaries = append(a.ParseSummaries, result.Summary)
			a.Timeline = append(a.Timeline, result.Events...)
			logCount += len(result.Events)
			continue
		}
		if identity.MediaType == "application/x-lime" || strings.EqualFold(filepath.Ext(it.Source), ".lime") {
			m, e := scanPackageMemoryContext(ctx, p.Files[it.Object], it, rules)
			if e != nil {
				a.ParseSummaries = append(a.ParseSummaries, ParseSummary{Evidence: it.ID, Format: "memory", Error: e.Error()})
				a.Notes = append(a.Notes, it.ID+": memory image: "+e.Error())
				continue
			}
			if e = examinePackageMemory(ctx, p.Files[it.Object], it, p.Manifest.OS, &m); e != nil {
				a.ParseSummaries = append(a.ParseSummaries, ParseSummary{Evidence: it.ID, Format: "memory", Error: e.Error()})
				if ctx.Err() != nil {
					a.Canceled = true
				}
				continue
			}
			rememberMemory(&a, m)
			continue
		}
		if identity.MediaType == "application/x-pcapng" || identity.MediaType == "application/vnd.tcpdump.pcap" || strings.EqualFold(filepath.Ext(it.Source), ".pcap") || strings.EqualFold(filepath.Ext(it.Source), ".cap") || strings.EqualFold(filepath.Ext(it.Source), ".pcapng") {
			summary := newCaptureSummary(it)
			if it.Size > pcapFileLimit || captureBytes+it.Size > pcapTotalLimit {
				summary.Limited = true
				summary.Error = "capture size or total byte budget exceeded"
			} else {
				captureBytes += it.Size
				b, e := readVerifiedEntryContext(ctx, p.Files[it.Object], it, pcapFileLimit)
				if e != nil {
					summary.Error = e.Error()
				} else {
					events, flows, parsed, interpretation := parseCaptureAdvanced(b, it, analysisEventLimit-logCount, pcapFlowLimit-len(a.NetworkFlows), networkSessionLimit-sessionCount, 5000-protocolCount, (4<<20)-protocolBytes)
					protocolCount += len(interpretation.Observations)
					protocolBytes += interpretation.MetadataBytes
					sessionCount += len(interpretation.Sessions)
					a.NetworkInterpretations = append(a.NetworkInterpretations, interpretation)
					summary = parsed
					logCount += summary.Records
					a.Timeline = append(a.Timeline, events...)
					a.NetworkFlows = append(a.NetworkFlows, flows...)
				}
			}
			a.CaptureSummaries = append(a.CaptureSummaries, summary)
			a.ParseSummaries = append(a.ParseSummaries, ParseSummary{Evidence: it.ID, Format: summary.Format, Rows: summary.Records, Parsed: summary.Parsed, Skipped: summary.Skipped, Limited: summary.Limited, Error: summary.Error})
			continue
		}
		if it.Size > 8<<20 || scanned+it.Size > 128<<20 {
			a.ParseSummaries = append(a.ParseSummaries, ParseSummary{Evidence: it.ID, Format: "unparsed", Limited: true, SkipReasons: map[string]int{"text_size_or_budget": 1}})
			a.Notes = append(a.Notes, it.ID+": text scan skipped: size/budget limit")
			continue
		}
		b, e := readVerifiedEntryContext(ctx, p.Files[it.Object], it, 8<<20)
		if e != nil {
			a.ParseSummaries = append(a.ParseSummaries, ParseSummary{Evidence: it.ID, Format: "unparsed", Error: e.Error()})
			a.Notes = append(a.Notes, it.ID+": "+e.Error())
			continue
		}
		scanned += int64(len(b))
		var events []Event
		var summary ParseSummary
		if ev, ok := prefetchEvent(b, it); ok {
			platformArtifacts = true
			if logCount < analysisEventLimit {
				a.Timeline = append(a.Timeline, ev)
				logCount++
				a.ParseSummaries = append(a.ParseSummaries, ParseSummary{Evidence: it.ID, Format: "WindowsPrefetch", Rows: 1, Parsed: 1})
			} else {
				a.ParseSummaries = append(a.ParseSummaries, ParseSummary{Evidence: it.ID, Format: "WindowsPrefetch", Rows: 1, Limited: true})
			}
			continue
		}
		if evs, sum, ok := parseCloudTrail(ctx, b, it, analysisEventLimit-logCount); ok {
			events, summary = evs, sum
			logCount += len(evs)
		} else if evs, sum, ok := parsePersistence(b, it, analysisEventLimit-logCount); ok {
			platformArtifacts = true
			events, summary = evs, sum
			logCount += len(evs)
		} else if strings.EqualFold(filepath.Ext(it.Source), ".xml") {
			windowsXML = true
			events, summary, b = parseWindowsXML(b, it, analysisEventLimit-logCount)
			logCount += summary.Rows
		} else {
			if !utf8.Valid(b) || bytes.IndexByte(b, 0) >= 0 {
				a.ParseSummaries = append(a.ParseSummaries, ParseSummary{Evidence: it.ID, Format: "unparsed", SkipReasons: map[string]int{"unsupported_text_encoding_or_binary": 1}})
				a.Notes = append(a.Notes, it.ID+": non UTF-8/binary text scan skipped")
				continue
			}
			events, summary = parseLogData(b, it, analysisEventLimit-logCount)
			logCount += len(events)
			appendActivities(&a, activitiesFromText(b, it))
		}
		a.ParseSummaries = append(a.ParseSummaries, summary)
		a.Timeline = append(a.Timeline, events...)
		if summary.Format == "CloudTrail" {
			continue
		}
		for ln, line := range strings.Split(string(b), "\n") {
			if ctx.Err() != nil {
				a.Canceled = true
				break
			}
			if len(a.Findings) >= findingLimit && a.FindingsTruncated {
				break
			}
			lower := strings.ToLower(line)
			for _, r := range rules {
				if r.Contains != "" && strings.Contains(lower, strings.ToLower(r.Contains)) {
					if len(a.Findings) >= findingLimit {
						markFindingsTruncated(&a)
						break
					}
					excerpt := []rune(line)
					if len(excerpt) > 400 {
						excerpt = excerpt[:400]
					}
					a.Findings = append(a.Findings, Finding{Rule: r.ID, Description: r.Description, Evidence: it.ID, Source: it.Source, Line: ln + 1, Excerpt: string(excerpt), Review: "unreviewed"})
				}
			}
		}
	}
	if ctx.Err() != nil {
		a.Canceled = true
	}
	deriveActivities(&a)
	evaluateEventRules(ctx, &a)
	if platformArtifacts {
		a.Notes = append(a.Notes, "Scheduled Task XML, launchd plists, systemd ExecStart lines and Windows Prefetch headers are extracted as triage events. Commands are copied from the file; they are not proof that the program ran. Selected binary launchd plist, EVTX, clean Registry and browser SQLite/WAL records have separate native workers. Exported USN v2/v3 streams have a native worker. SRUM, MFT, USN v4 and live journal acquisition, transaction-log recovery and compressed Prefetch remain unsupported.")
	}
	if windowsXML {
		a.Notes = append(a.Notes, "Windows event XML exports (.xml): UTF-8 or BOM-marked UTF-16, Windows Event namespace, single events/fragments or an Events wrapper. Only explicit-zone SystemTime with at most nanosecond precision is interpreted; RawTime is not converted. System metadata and ordered EventData/Data fields are retained without provider-specific interpretation. SID values are unresolved identifiers; host names are normalized for correlation. Unsupported payload sections are marked, not decoded. EVTX has a separate worker; this XML decoder does not load event-message DLLs or external XML resources. Limits: 20,000 records and 250,000 XML tokens per file; 256 KiB decoded bytes, depth 32 and 2,048 nodes per event; 32 attributes per element, 4,096 UTF-8 bytes per text/attribute value and 64 Data fields per event. Byte offsets refer to original encoded evidence, including its BOM. Literal rules scan decoded XML lines, not provider-interpreted messages. Shared reports omit Windows-specific context/data fields.")
	}
	if len(a.CaptureSummaries) > 0 {
		a.Notes = append(a.Notes, "PCAP v2.4 and PCAPNG: Ethernet/raw-IP/Linux SLL/SLL2 TCP/UDP headers plus selected DNS, initial HTTP headers and TLS ClientHello metadata. PCAPNG Enhanced Packet Blocks are analyzed; untimed Simple Packet Blocks and obsolete Packet Blocks are counted and skipped. Other blocks are counted as ignored. Binary/sub-nanosecond timestamps are floored to nanoseconds. Interface names, comments and decryption secrets are not exported. No live capture, IP fragment reassembly, external DNS lookup or TLS decryption. Bounded TCP session candidates/reassembly and selected protocol projections retain packet references and explicit gap/overlap policies. Complete IPv4/TCP/UDP checksums are checked; invalid_or_offloaded is not a malicious verdict. Directional five-tuples group all matching packets within one evidence object and PCAPNG section/interface; MAC/VLAN/SLL2 operating-system interface identity is not part of the grouping; directional flow totals retain repeated packets; separate session candidates apply SYN, idle, RST and FIN boundaries. Byte counters are recorded frame sizes, not application traffic. Each capture is limited to 64 MiB and 20,000 records, 256 MiB total, shared 50,000 log-event/capture-record budget, 10,000 flows total and 20 references per flow. PCAPNG also has limits of 100,000 blocks, 256 sections and 1,024 interfaces per file. See capture summaries for omissions; IP addresses do not identify people.")
	}
	for i := range a.Findings {
		a.Findings[i].ID = findingID(a.EvidenceDigest, a.Findings[i])
	}
	sort.SliceStable(a.Timeline, func(i, j int) bool { return a.Timeline[i].Time.Before(a.Timeline[j].Time) })
	var eNotes []string
	a.Correlations, eNotes = correlate(a.Timeline)
	a.Notes = append(a.Notes, eNotes...)
	applyConfiguredIndicators(ctx, &a)
	a.Coverage = analysisCoverage(a)
	return a
}
func Export(a Analysis, out string) error { return ExportContext(context.Background(), a, out) }

func ExportContext(ctx context.Context, a Analysis, out string) (err error) {
	if e := ctx.Err(); e != nil {
		return e
	}
	if a.Canceled {
		return errors.New("cannot export a canceled analysis")
	}
	a.Coverage = analysisCoverage(a)
	if e := os.Mkdir(out, 0700); e != nil {
		return fmt.Errorf("new output directory required: %w", e)
	}
	ok := false
	defer func() {
		if !ok {
			os.RemoveAll(out)
		}
	}()
	if e := WriteJSONNew(filepath.Join(out, "analysis.json"), a); e != nil {
		return e
	}
	if e := exportNetworkInterpretations(a.NetworkInterpretations, out); e != nil {
		return e
	}
	if e := exportUSN(ctx, a.Timeline, out); e != nil {
		return e
	}
	if e := exportUSNGroups(ctx, a, out); e != nil {
		return e
	}
	if e := writeCSVNew(filepath.Join(out, "timeline.csv"), func(c *csv.Writer) error {
		if err := c.Write([]string{"time_utc", "event_type", "evidence_id", "source", "line", "original_time", "detail", "user", "host", "source_ip", "destination_ip", "byte_offset", "packet", "protocol", "source_port", "destination_port", "captured_length", "original_length", "tcp_flags", "section", "interface_id"}); err != nil {
			return err
		}
		for _, v := range a.Timeline {
			if err := c.Write([]string{v.Time.Format(time.RFC3339Nano), v.Type, v.Evidence, csvSafe(v.Source), strconv.Itoa(v.Line), csvSafe(v.OriginalTime), csvSafe(v.Detail), csvSafe(v.User), csvSafe(v.Host), csvSafe(v.SourceIP), csvSafe(v.DestinationIP), strconv.FormatInt(v.ByteOffset, 10), strconv.Itoa(v.Packet), v.Protocol, strconv.Itoa(int(v.SourcePort)), strconv.Itoa(int(v.DestinationPort)), strconv.FormatInt(v.CapturedLength, 10), strconv.FormatInt(v.OriginalLength, 10), strconv.Itoa(int(v.TCPFlags)), strconv.Itoa(v.Section), strconv.FormatUint(uint64(v.InterfaceID), 10)}); err != nil {
				return err
			}
		}
		return nil
	}); e != nil {
		return e
	}
	if e := writeCSVNew(filepath.Join(out, "findings.csv"), func(c *csv.Writer) error {
		if err := c.Write([]string{"finding_id", "rule", "evidence_id", "source", "line", "review", "analyst", "reason", "excerpt"}); err != nil {
			return err
		}
		for _, f := range a.Findings {
			if err := c.Write([]string{f.ID, csvSafe(f.Rule), f.Evidence, csvSafe(f.Source), strconv.Itoa(f.Line), f.Review, csvSafe(f.Reviewer), csvSafe(f.ReviewNote), csvSafe(f.Excerpt)}); err != nil {
				return err
			}
		}
		return nil
	}); e != nil {
		return e
	}
	if e := writeCSVNew(filepath.Join(out, "correlations.csv"), func(c *csv.Writer) error {
		if err := c.Write([]string{"kind", "value", "event_count", "source_count", "first_utc", "last_utc", "reference_count", "references_truncated"}); err != nil {
			return err
		}
		for _, v := range a.Correlations {
			if err := c.Write([]string{v.Kind, csvSafe(v.Value), strconv.Itoa(v.Events), strconv.Itoa(v.Sources), v.First.Format(time.RFC3339Nano), v.Last.Format(time.RFC3339Nano), strconv.Itoa(len(v.References)), strconv.FormatBool(v.Truncated)}); err != nil {
				return err
			}
		}
		return nil
	}); e != nil {
		return e
	}
	if a.Custody != nil {
		if e := exportCustodyCSV(a.Custody, filepath.Join(out, "custody.csv")); e != nil {
			return e
		}
	}
	if e := exportNetwork(a, out); e != nil {
		return e
	}
	if e := exportMemoryKernel(ctx, a, out); e != nil {
		return e
	}
	if e := exportMemoryResults(ctx, a, out); e != nil {
		return e
	}
	if e := exportMemoryContext(ctx, a, out); e != nil {
		return e
	}
	if e := exportWindowsEvents(a, out); e != nil {
		return e
	}
	if e := writeIdentities(a, filepath.Join(out, "filetypes.csv")); e != nil {
		return e
	}
	if e := writeHashMatches(a.HashMatches, filepath.Join(out, "hash-matches.csv")); e != nil {
		return e
	}
	body := make([]bodyfileRow, 0, len(a.Manifest.Items))
	for _, it := range a.Manifest.Items {
		body = append(body, bodyfileRow{Name: it.Source, Size: it.Size, Modified: it.Modified})
	}
	if e := writeBodyfile(body, filepath.Join(out, "bodyfile.txt")); e != nil {
		return e
	}
	if e := writePersistence(a, filepath.Join(out, "persistence.csv")); e != nil {
		return e
	}
	if e := writeActivities(a, filepath.Join(out, "activity.csv")); e != nil {
		return e
	}
	if e := exportPortableAnalysis(ctx, a, out); e != nil {
		return e
	}
	if e := exportDefaultPDF(ctx, a, out); e != nil {
		return e
	}
	page, e := renderReportHTML(a)
	if e != nil {
		return e
	}
	if e = WriteNew(filepath.Join(out, "report.html"), page); e != nil {
		return e
	}
	ok = true
	return nil
}
func csvSafe(s string) string {
	if strings.ContainsAny(strings.TrimLeft(s, " \t\r\n")[:min(1, len(strings.TrimLeft(s, " \t\r\n")))], "=+-@") || strings.HasPrefix(s, "\t") || strings.HasPrefix(s, "\r") {
		return "'" + s
	}
	return s
}

// A finding cap must never stop inventory, parsing or timeline construction.
func markFindingsTruncated(a *Analysis) {
	if !a.FindingsTruncated {
		a.FindingsTruncated = true
		a.Notes = append(a.Notes, "Finding limit reached: additional findings omitted; inventory and supported event parsing continue")
	}
}

func appendFinding(a *Analysis, f Finding) {
	if len(a.Findings) >= findingLimit {
		markFindingsTruncated(a)
		return
	}
	a.Findings = append(a.Findings, f)
}
