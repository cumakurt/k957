package core

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type Rule struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Contains    string `json:"contains"`
	SHA256      string `json:"sha256"`
}
type Finding struct {
	ID          string `json:"id"`
	Reviewer    string `json:"reviewer,omitempty"`
	ReviewNote  string `json:"review_note,omitempty"`
	Rule        string `json:"rule"`
	Description string `json:"description"`
	Evidence    string `json:"evidence"`
	Source      string `json:"source"`
	Line        int    `json:"line,omitempty"`
	Excerpt     string `json:"excerpt,omitempty"`
	Review      string `json:"review"`
}
type Event struct {
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
type Analysis struct {
	CaptureSummaries []CaptureSummary `json:"capture_summaries,omitempty"`
	NetworkFlows     []NetworkFlow    `json:"network_flows,omitempty"`
	Custody          *CustodyStatus   `json:"custody,omitempty"`
	ParseSummaries   []ParseSummary   `json:"parse_summaries,omitempty"`
	Correlations     []Correlation    `json:"correlations,omitempty"`
	ReviewDigest     string           `json:"review_digest,omitempty"`
	EvidenceDigest   string           `json:"evidence_digest"`
	ReviewHistory    []ReviewEvent    `json:"review_history,omitempty"`
	ReviewSignature  string           `json:"review_signature,omitempty"`
	Version          string           `json:"version"`
	Run              string           `json:"run"`
	Created          time.Time        `json:"created"`
	Signature        string           `json:"signature"`
	Manifest         Manifest         `json:"manifest"`
	Rules            []Rule           `json:"rules"`
	Findings         []Finding        `json:"findings"`
	Timeline         []Event          `json:"timeline"`
	Notes            []string         `json:"notes"`
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
	if e = json.Unmarshal(b, &rules); e != nil {
		return nil, e
	}
	if len(rules) > 100 {
		return nil, errors.New("max 100 rules")
	}
	seen := map[string]bool{}
	for _, r := range rules {
		if r.ID == "" || seen[r.ID] || (r.Contains == "") == (r.SHA256 == "") {
			return nil, errors.New("each rule needs unique id and exactly one contains/sha256 condition")
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
	a := Analysis{EvidenceDigest: p.ManifestSHA256, Version: Version, Run: ID(), Created: time.Now().UTC(), Signature: p.Signature, Manifest: p.Manifest, Rules: rules, Findings: []Finding{}, Timeline: []Event{}, Notes: []string{"Timeline includes file metadata, explicit log/XML timestamps and supported PCAP packet timestamps; these are not proof of execution or user attribution.", "Rules are literal matches, not malware verdicts. Every finding requires analyst review.", "Text scanning covers UTF-8 files and supported Windows event XML up to 8 MiB each, 128 MiB total; PCAP and PCAPNG are parsed separately; other binary formats are inventoried, not parsed.", "Clock offsets are not measured. Timestamps reflect the source host clock converted to UTC."}}
	if p.Manifest.InventoryFrozen {
		a.Notes = append(a.Notes, "Resumable acquisition: inventory was frozen at the first run. Completed files are reused without rereading the source. Newly created source files are excluded.", "Parts can originate from different invocations. This package is not a single point-in-time snapshot. See acquisition epochs and part provenance in analysis.json.")
	}
	var scanned, captureBytes int64
	logCount := 0
	windowsXML := false
	for _, it := range p.Manifest.Items {
		a.Timeline = append(a.Timeline, Event{Time: it.Collected, Type: "collected", Evidence: it.ID, Source: it.Source})
		if !it.Modified.IsZero() {
			a.Timeline = append(a.Timeline, Event{Time: it.Modified, Type: "file_modified", Evidence: it.ID, Source: it.Source})
		}
		for _, r := range rules {
			if r.SHA256 != "" && r.SHA256 == it.SHA256 {
				if len(a.Findings) >= 10000 {
					a.Notes = append(a.Notes, "Finding limit reached: remaining analysis not executed")
					goto done
				}
				a.Findings = append(a.Findings, Finding{Rule: r.ID, Description: r.Description, Evidence: it.ID, Source: it.Source, Review: "unreviewed"})
			}
		}
		if captureCandidate(p.Files[it.Object], it.Source) {
			summary := newCaptureSummary(it)
			if it.Size > pcapFileLimit || captureBytes+it.Size > pcapTotalLimit {
				summary.Limited = true
				summary.Error = "capture size or total byte budget exceeded"
			} else {
				captureBytes += it.Size
				b, e := readEntry(p.Files[it.Object], pcapFileLimit)
				if e != nil {
					summary.Error = e.Error()
				} else {
					events, flows, parsed := parsePCAP(b, it, 50000-logCount, pcapFlowLimit-len(a.NetworkFlows))
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
			a.Notes = append(a.Notes, it.ID+": text scan skipped: size/budget limit")
			continue
		}
		b, e := readEntry(p.Files[it.Object], 8<<20)
		if e != nil {
			a.Notes = append(a.Notes, it.ID+": "+e.Error())
			continue
		}
		scanned += int64(len(b))
		var events []Event
		var summary ParseSummary
		if strings.EqualFold(filepath.Ext(it.Source), ".xml") {
			windowsXML = true
			events, summary, b = parseWindowsXML(b, it, 50000-logCount)
			logCount += summary.Rows
		} else {
			if !utf8.Valid(b) || bytes.IndexByte(b, 0) >= 0 {
				a.Notes = append(a.Notes, it.ID+": non UTF-8/binary text scan skipped")
				continue
			}
			events, summary = parseLogData(b, it, 50000-logCount)
			logCount += len(events)
		}
		a.ParseSummaries = append(a.ParseSummaries, summary)
		a.Timeline = append(a.Timeline, events...)
		for ln, line := range strings.Split(string(b), "\n") {
			lower := strings.ToLower(line)
			for _, r := range rules {
				if r.Contains != "" && strings.Contains(lower, strings.ToLower(r.Contains)) {
					if len(a.Findings) >= 10000 {
						a.Notes = append(a.Notes, "Finding limit reached: remaining analysis not executed")
						goto done
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
done:
	if windowsXML {
		a.Notes = append(a.Notes, "Windows event XML exports (.xml): UTF-8 or BOM-marked UTF-16, Windows Event namespace, single events/fragments or an Events wrapper. Only explicit-zone SystemTime with at most nanosecond precision is interpreted; RawTime is not converted. System metadata and ordered EventData/Data fields are retained without provider-specific interpretation. SID values are unresolved identifiers; host names are normalized for correlation. Unsupported payload sections are marked, not decoded. No EVTX binary parsing, event-message DLL loading or external XML resources. Limits: 20,000 records and 250,000 XML tokens per file; 256 KiB decoded bytes, depth 32 and 2,048 nodes per event; 32 attributes per element, 4,096 UTF-8 bytes per text/attribute value and 64 Data fields per event. Byte offsets refer to original encoded evidence, including its BOM. Literal rules scan decoded XML lines, not provider-interpreted messages. Shared reports omit Windows-specific context/data fields.")
	}
	if len(a.CaptureSummaries) > 0 {
		a.Notes = append(a.Notes, "PCAP v2.4 and PCAPNG: Ethernet/raw-IP/Linux SLL/SLL2 TCP/UDP headers only. PCAPNG Enhanced Packet Blocks are analyzed; untimed Simple Packet Blocks and obsolete Packet Blocks are counted and skipped. Other blocks are counted as ignored. Binary/sub-nanosecond timestamps are floored to nanoseconds. Interface names, comments and decryption secrets are not exported. No capture, payload inspection, checksums, reassembly, DNS resolution or session reconstruction. Directional five-tuples group all matching packets within one evidence object and PCAPNG section/interface; MAC/VLAN/SLL2 operating-system interface identity is not part of the grouping; retransmissions and repeated sessions are not deduplicated. Byte counters are recorded frame sizes, not application traffic. Each capture is limited to 64 MiB and 20,000 records, 256 MiB total, shared 50,000 log-event/capture-record budget, 10,000 flows total and 20 references per flow. PCAPNG also has limits of 100,000 blocks, 256 sections and 1,024 interfaces per file. See capture summaries for omissions; IP addresses do not identify people.")
	}
	for i := range a.Findings {
		a.Findings[i].ID = findingID(a.EvidenceDigest, a.Findings[i])
	}
	sort.SliceStable(a.Timeline, func(i, j int) bool { return a.Timeline[i].Time.Before(a.Timeline[j].Time) })
	var eNotes []string
	a.Correlations, eNotes = correlate(a.Timeline)
	a.Notes = append(a.Notes, eNotes...)
	return a
}
func Export(a Analysis, out string) (err error) {
	if e := os.Mkdir(out, 0700); e != nil {
		return fmt.Errorf("new output directory required: %w", e)
	}
	ok := false
	defer func() {
		if !ok {
			os.RemoveAll(out)
		}
	}()
	if e := WriteNew(filepath.Join(out, "analysis.json"), JSON(a)); e != nil {
		return e
	}
	var b bytes.Buffer
	c := csv.NewWriter(&b)
	c.Write([]string{"time_utc", "event_type", "evidence_id", "source", "line", "original_time", "detail", "user", "host", "source_ip", "destination_ip", "byte_offset", "packet", "protocol", "source_port", "destination_port", "captured_length", "original_length", "tcp_flags", "section", "interface_id"})
	for _, v := range a.Timeline {
		c.Write([]string{v.Time.Format(time.RFC3339Nano), v.Type, v.Evidence, csvSafe(v.Source), strconv.Itoa(v.Line), csvSafe(v.OriginalTime), csvSafe(v.Detail), csvSafe(v.User), csvSafe(v.Host), csvSafe(v.SourceIP), csvSafe(v.DestinationIP), strconv.FormatInt(v.ByteOffset, 10), strconv.Itoa(v.Packet), v.Protocol, strconv.Itoa(int(v.SourcePort)), strconv.Itoa(int(v.DestinationPort)), strconv.FormatInt(v.CapturedLength, 10), strconv.FormatInt(v.OriginalLength, 10), strconv.Itoa(int(v.TCPFlags)), strconv.Itoa(v.Section), strconv.FormatUint(uint64(v.InterfaceID), 10)})
	}
	c.Flush()
	if e := c.Error(); e != nil {
		return e
	}
	if e := WriteNew(filepath.Join(out, "timeline.csv"), b.Bytes()); e != nil {
		return e
	}
	b.Reset()
	c = csv.NewWriter(&b)
	c.Write([]string{"finding_id", "rule", "evidence_id", "source", "line", "review", "analyst", "reason", "excerpt"})
	for _, f := range a.Findings {
		c.Write([]string{f.ID, csvSafe(f.Rule), f.Evidence, csvSafe(f.Source), strconv.Itoa(f.Line), f.Review, csvSafe(f.Reviewer), csvSafe(f.ReviewNote), csvSafe(f.Excerpt)})
	}
	c.Flush()
	if e := c.Error(); e != nil {
		return e
	}
	if e := WriteNew(filepath.Join(out, "findings.csv"), b.Bytes()); e != nil {
		return e
	}
	b.Reset()
	c = csv.NewWriter(&b)
	c.Write([]string{"kind", "value", "event_count", "source_count", "first_utc", "last_utc", "reference_count", "references_truncated"})
	for _, v := range a.Correlations {
		c.Write([]string{v.Kind, csvSafe(v.Value), strconv.Itoa(v.Events), strconv.Itoa(v.Sources), v.First.Format(time.RFC3339Nano), v.Last.Format(time.RFC3339Nano), strconv.Itoa(len(v.References)), strconv.FormatBool(v.Truncated)})
	}
	c.Flush()
	if e := c.Error(); e != nil {
		return e
	}
	if e := WriteNew(filepath.Join(out, "correlations.csv"), b.Bytes()); e != nil {
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
	if e := exportWindowsEvents(a, out); e != nil {
		return e
	}
	t, e := template.New("report").Funcs(template.FuncMap{"endpoint": networkEndpoint, "windowsEvents": windowsEvents}).Parse(reportTemplate)
	if e != nil {
		return e
	}
	b.Reset()
	if e = t.Execute(&b, a); e != nil {
		return e
	}
	if e = WriteNew(filepath.Join(out, "report.html"), b.Bytes()); e != nil {
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

const reportTemplate = `<!doctype html><html lang="tr"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>k957 · {{.Manifest.Case}}</title><style>
:root{color-scheme:dark}body{font:15px system-ui;background:#0a1220;color:#dce6f4;margin:0}main{max-width:1200px;margin:auto;padding:40px}header{border-bottom:1px solid #334155;padding-bottom:24px}h1{font-size:44px;margin:0;color:#62e3b7}h2{margin-top:38px}small{color:#9cacc2}.grid{display:flex;gap:16px;flex-wrap:wrap}.card{padding:20px;background:#142236;border:1px solid #293d56;border-radius:12px;flex:1}b{color:#62e3b7}table{border-collapse:collapse;width:100%;background:#111e30}td,th{text-align:left;border-bottom:1px solid #304158;padding:10px;vertical-align:top;overflow-wrap:anywhere}code{white-space:pre-wrap;overflow-wrap:anywhere}.scroll{overflow:auto;max-height:600px}input{padding:12px;background:#17273d;border:1px solid #536b88;color:white;width:90%;margin:18px 0}a{color:#62e3b7}.note{padding:14px;border-left:3px solid #e6b566;background:#242434}section{margin:24px 0}@media print{:root{color-scheme:light}body{background:white;color:black}main{padding:0}h1,b,a{color:#125640}.card,table,.note{background:white;color:black}.scroll{max-height:none;overflow:visible}input{display:none}tr{break-inside:avoid}}
</style><main><header><small>DİJİTAL DELİL İNCELEME · v{{.Version}}</small><h1>k957 Analyze</h1><p>Vaka: <strong>{{.Manifest.Case}}</strong> · {{.Manifest.Host}} · {{.Manifest.OS}}/{{.Manifest.Arch}}</p><small>Analiz: {{.Run}} · {{.Created}}</small></header>
<section class="grid"><div class="card">Delil<br><b>{{len .Manifest.Items}}</b></div><div class="card">Kural eşleşmesi<br><b>{{len .Findings}}</b></div><div class="card">Toplama sorunu<br><b>{{len .Manifest.Issues}}</b></div><div class="card">Durum<br><b>{{.Manifest.Status}}</b></div></section>
<p class="note">SHA-256 bütünlük kontrolü başarılı. İmza: {{.Signature}}. Bütünlük doğrulaması, kaynak verinin gerçekliğini tek başına kanıtlamaz. Bulgular analist incelemesi gerektirir.</p>
{{if .Manifest.Epochs}}<h2>Edinim dönemleri</h2><p class="note">Envanter ilk çalıştırmada sabitlendi. Parçalar farklı dönemlerde alınmış olabilir; paket tek bir anlık görüntü değildir. Tamamlanmış dosyalar yeniden kaynak okuması yapılmadan kullanılır.</p><div class="scroll"><table><thead><tr><th>Dönem</th><th>Başlangıç / Bitiş</th><th>Sonuç</th></tr></thead><tbody>{{range .Manifest.Epochs}}<tr><td>{{.ID}}<br>{{.Host}} · {{.OS}}/{{.Arch}}</td><td>{{.Started}}<br>{{.Finished}}</td><td>{{.Outcome}}</td></tr>{{end}}</tbody></table></div>{{end}}
<h2>İnceleme kapsamı</h2><p>{{.Manifest.Scope}}</p><p>Operatör: {{.Manifest.Operator}} · Toplama: {{.Manifest.Started}} – {{.Manifest.Finished}}</p>
<input id="search" placeholder="Tablolarda kaynak, delil kimliği veya bulgu ara…" aria-label="Rapor tablolarında ara">
<h2>Bulgular</h2><div class="scroll"><table><thead><tr><th>Kural</th><th>Kaynak</th><th>Eşleşme</th><th>Değerlendirme</th></tr></thead><tbody>{{range .Findings}}<tr><td>{{.Rule}}<br>{{.Description}}<br><small>{{.ID}}</small></td><td><a href="#{{.Evidence}}">{{.Evidence}}</a><br>{{.Source}}<br>Satır {{.Line}}</td><td><code>{{.Excerpt}}</code></td><td>{{.Review}}<br>{{.Reviewer}}<br>{{.ReviewNote}}</td></tr>{{else}}<tr><td colspan="4">Eşleşme yok. Bu sonuç olay yaşanmadığını göstermez.</td></tr>{{end}}</tbody></table></div>
{{if .ReviewHistory}}<h2>Analist değerlendirme geçmişi</h2><p class="note">Değerlendirme imzası: {{.ReviewSignature}}.<br>Değerlendirme kaydı özeti: {{.ReviewDigest}}. Kararlar analist yorumlarıdır; otomatik eşleşme kayıtları ve ham delil korunmuştur.</p><div class="scroll"><table><thead><tr><th>Sıra / Bulgu</th><th>Analist / Tarih</th><th>Karar / Gerekçe</th></tr></thead><tbody>{{range .ReviewHistory}}<tr><td>{{.Sequence}}<br>{{.Finding}}</td><td>{{.Analyst}}<br>{{.Created}}</td><td>{{.Decision}}<br>{{.Note}}</td></tr>{{end}}</tbody></table></div>{{end}}
{{if .Custody}}<h2>İmzalı muhafaza ve devir kayıtları</h2><p class="note">{{.Custody.Trust}}<br>Kayda göre mevcut sorumlu: {{.Custody.CurrentHolder}}<br>{{if .Custody.PendingTo}}Teslim alma onayı beklenen kişi: {{.Custody.PendingTo}}{{else}}Bekleyen devir yok.{{end}}<br>Son kayıt özeti: <code>{{.Custody.Head}}</code><br>Güven listesi özeti: <code>{{.Custody.TrustDigest}}</code><br>İmzalar beyanları doğrular; fiziksel teslimi, gerçek kişi kimliğini veya güvenilir zaman damgasını kanıtlamaz. Geçmişin eksiksizliği için bağımsız saklanan son kayıt özeti karşılaştırılmalıdır.</p><div class="scroll"><table><thead><tr><th>Sıra / İşlem</th><th>İmzalayan / Taraflar</th><th>Beyan zamanı / Kayıt zamanı</th><th>Konum / Not</th><th>Anahtar parmak izi</th></tr></thead><tbody>{{range .Custody.Events}}<tr><td>{{.Sequence}} / {{.Action}}</td><td>{{.Actor}}<br>{{.From}} → {{.To}}</td><td>{{.OccurredAt}}<br>{{.RecordedAt}}</td><td>{{.Location}}<br>{{.Note}}</td><td><code>{{.Signer}}</code></td></tr>{{end}}</tbody></table></div>{{end}}
{{if .CaptureSummaries}}<h2>PCAP / PCAPNG kapsamı</h2><p class="note">Yalnızca paket başlıkları incelendi. Akışlar yönlü 5'li anahtara göre gruplanır; tamamlanmış bağlantı veya kişi atfı değildir. Fragmentler yeniden birleştirilmez, checksum doğrulanmaz. Sayaçlar yalnızca okunabilen kayıtları kapsar.</p><div class="scroll"><table><thead><tr><th>Delil / Biçim</th><th>Kayıt / Ayrıştırılan / Atlanan</th><th>Eksik yakalama / Akış dışı</th><th>Atlama nedenleri / Sınır / Hata</th></tr></thead><tbody>{{range .CaptureSummaries}}<tr><td>{{.Evidence}} / {{.Format}}<br>{{.ByteOrder}} / {{.Resolution}}{{if .Sections}}<br>Bölüm: {{.Sections}} / Arayüz: {{len .Interfaces}} / Blok: {{.Blocks}} / İncelenmeyen blok: {{.IgnoredBlocks}}{{range .Interfaces}}<br>Bölüm {{.Section}}, arayüz {{.InterfaceID}}, link {{.LinkType}}, çözünürlük {{.Resolution}}, zaman ofseti {{.TimeOffset}} s {{.UnsupportedReason}}{{end}}{{else}} / link {{.LinkType}}{{end}}</td><td>{{.Records}} / {{.Parsed}} / {{.Skipped}}</td><td>{{.TruncatedPackets}} / {{.FlowOmittedPackets}}</td><td>{{range $key,$value := .SkipReasons}}{{$key}}: {{$value}}<br>{{end}}{{.Limited}}<br>{{.Error}}</td></tr>{{end}}</tbody></table></div>{{end}}
{{if .NetworkFlows}}<h2>Yönlü ağ akışları</h2><div class="scroll"><table><thead><tr><th>Delil / Protokol</th><th>Kaynak → Hedef</th><th>Paket / Yakalanan / Bildirilen bayt</th><th>İlk / Son</th><th>Paket referansları</th></tr></thead><tbody>{{range .NetworkFlows}}<tr><td>{{.Evidence}} / {{.Protocol}}{{if .Section}}<br>Bölüm {{.Section}} / Arayüz {{.InterfaceID}}{{end}}</td><td>{{endpoint .SourceIP .SourcePort}} → {{endpoint .DestinationIP .DestinationPort}}</td><td>{{.Packets}} / {{.CapturedBytes}} / {{.OriginalBytes}}</td><td>{{.First}}<br>{{.Last}}</td><td>{{range .References}}Paket {{.Packet}}{{if .Section}} / Bölüm {{.Section}} / Arayüz {{.InterfaceID}}{{end}}, byte {{.ByteOffset}}<br>{{end}}{{if .ReferencesTruncated}}Referans listesi sınırlandı.{{end}}</td></tr>{{end}}</tbody></table></div>{{end}}
{{with windowsEvents .Timeline}}<h2>Windows olay XML kayıtları</h2><p class="note">XML dışa aktarımındaki alanlar gösterilir. Olay kimliği tek başına bir eylemi veya kişiyi kanıtlamaz. EventData alanları sağlayıcıya özel yorumlanmaz; SID değerleri çözümlenmemiştir. Ham EVTX biçimi ayrıştırılmaz.</p><div class="scroll"><table><thead><tr><th>Delil / Konum</th><th>Sağlayıcı / Olay / Kayıt</th><th>Zaman / Bilgisayar / SID</th><th>İleti / Veri / Eksikler</th></tr></thead><tbody>{{range .}}<tr><td><a href="#{{.Evidence}}">{{.Evidence}}</a><br>{{.Source}}<br>Satır {{.Line}} / byte {{.ByteOffset}}</td><td>{{.Windows.Provider}}<br>{{.Windows.ProviderGUID}}<br>{{.Windows.EventSource}}<br>Olay {{.Windows.EventID}} / Kayıt {{.Windows.RecordID}}<br>{{.Windows.Channel}}{{with .Windows.Qualifiers}}<br>Qualifiers: {{.}}{{end}}{{with .Windows.Level}}<br>Düzey: {{.}}{{end}}{{with .Windows.Version}}<br>Sürüm: {{.}}{{end}}</td><td>{{.Time}}<br>{{.Host}}<br>{{.User}}</td><td>{{.Detail}}{{range .Windows.Data}}<br><strong>{{.Name}}</strong>: <code>{{.Value}}</code>{{end}}{{if .Windows.PayloadOmitted}}<br>Bazı payload bölümleri incelenmedi.{{end}}{{if .Windows.MessageTruncated}}<br>İleti kısaltıldı.{{end}}</td></tr>{{end}}</tbody></table></div>{{end}}
<h2>Ayrıştırma kapsamı</h2><div class="scroll"><table><thead><tr><th>Delil / Biçim</th><th>Okunan / Olay / Atlanan</th><th>Sınır / Hata</th></tr></thead><tbody>{{range .ParseSummaries}}<tr><td>{{.Evidence}} / {{.Format}}</td><td>{{.Rows}} / {{.Parsed}} / {{.Skipped}}</td><td>{{.Limited}}<br>{{.Error}}{{range $key,$value := .SkipReasons}}<br>{{$key}}: {{$value}}{{end}}</td></tr>{{end}}</tbody></table></div>
<h2>Farklı delillerde ortak varlıklar</h2><p class="note">Aynı değer en az iki delil nesnesinde bulundu. Bu, bağımsız iki kaynak veya aynı kişi/cihaz olduğunu kanıtlamaz. NAT, paylaşılan hesaplar ve kopya loglar değerlendirilmelidir.</p><div class="scroll"><table><thead><tr><th>Tür / Değer</th><th>Olay / Delil sayısı</th><th>İlk / Son zaman</th><th>Kaynak kayıtları</th></tr></thead><tbody>{{range .Correlations}}<tr><td>{{.Kind}}<br>{{.Value}}</td><td>{{.Events}} / {{.Sources}}</td><td>{{.First}}<br>{{.Last}}</td><td>{{range .References}}<a href="#{{.Evidence}}">{{.Evidence}}</a>:{{.Line}} {{if .Packet}}paket {{.Packet}}{{if .Section}} / Bölüm {{.Section}} / Arayüz {{.InterfaceID}}{{end}}{{end}} ({{.Role}})<br>{{end}}{{if .Truncated}}Referans listesi sınırlandı.{{end}}</td></tr>{{else}}<tr><td colspan="4">İlişki bulunamadı veya desteklenen yapılandırılmış alan yok.</td></tr>{{end}}</tbody></table></div>
<h2>Zaman çizelgesi · UTC</h2><div class="scroll"><table><thead><tr><th>Zaman</th><th>Olay</th><th>Delil</th><th>Kaynak</th></tr></thead><tbody>{{range .Timeline}}<tr><td>{{.Time}}</td><td>{{.Type}}</td><td><a href="#{{.Evidence}}">{{.Evidence}}</a></td><td>{{.Source}}<br>Satır {{.Line}} {{if .Packet}}· Paket {{.Packet}}{{if .Section}} / Bölüm {{.Section}} / Arayüz {{.InterfaceID}}{{end}} / byte {{.ByteOffset}} · {{.Protocol}} {{.SourcePort}} → {{.DestinationPort}}{{end}} · {{.Detail}}<br>{{.User}} · {{.Host}} · {{.SourceIP}} → {{.DestinationIP}}</td></tr>{{end}}</tbody></table></div>
<h2>Delil envanteri</h2><div class="scroll"><table><thead><tr><th>Kimlik / Kaynak</th><th>Bayt</th><th>SHA-256</th><th>Tür / Değişim</th></tr></thead><tbody>{{range .Manifest.Items}}<tr id="{{.ID}}"><td>{{.ID}}<br>{{.Source}}</td><td>{{.Size}}</td><td><code>{{.SHA256}}</code></td><td>{{.Kind}} / {{.Changed}}</td></tr>{{end}}</tbody></table></div>
<h2>Toplama eksikleri</h2>{{range .Manifest.Issues}}<p class="note"><strong>{{.Source}}</strong><br>{{.Reason}}</p>{{else}}<p>Kaydedilmiş toplama hatası yok; yalnızca seçilen kapsam için geçerlidir.</p>{{end}}
<h2>Sınırlamalar ve yöntem</h2>{{range .Notes}}<p>{{.}}</p>{{end}}<p>Ham delil değiştirilmeden incelendi. Rapordan orijinal kayıtları doğrulamak için delil kimliği, kaynak yolu ve SHA-256 kullanılmalıdır. HTML tarayıcının yazdır işleviyle PDF olarak kaydedilebilir.</p>
<footer><small>k957 · Kaynakları izlenebilir inceleme · Otomatik rapor, nihai uzman görüşü değildir.</small></footer></main><script>document.getElementById('search').addEventListener('input',function(){const q=this.value.toLocaleLowerCase();document.querySelectorAll('tbody tr').forEach(r=>{r.hidden=!r.textContent.toLocaleLowerCase().includes(q)})})</script></html>`
