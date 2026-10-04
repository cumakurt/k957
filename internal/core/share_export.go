package core

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

func sharedTime(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.Format(time.RFC3339Nano)
}
func sharedCSV(path string, header []string, rows [][]string) error {
	return sharedCSVContext(context.Background(), path, header, rows)
}

func sharedCSVContext(ctx context.Context, path string, header []string, rows [][]string) error {
	return writeFileNew(path, func(out io.Writer) error {
		w := csv.NewWriter(contextWriter{ctx: ctx, w: out})
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := w.Write(header); err != nil {
			return err
		}
		for _, row := range rows {
			if err := ctx.Err(); err != nil {
				return err
			}
			safe := make([]string, len(row))
			for i, value := range row {
				safe[i] = csvSafe(value)
			}
			if err := w.Write(safe); err != nil {
				return err
			}
		}
		w.Flush()
		if err := w.Error(); err != nil {
			return err
		}
		return ctx.Err()
	})
}

func ExportShared(s SharedReport, out string) error {
	return ExportSharedContext(context.Background(), s, out)
}

// ExportSharedContext retains the legacy API while propagating cancellation
// through CSV, HTML and PDF generation and removing incomplete new bundles.
func ExportSharedContext(ctx context.Context, s SharedReport, out string) (err error) {
	if err = ctx.Err(); err != nil {
		return err
	}
	if s.Schema != shareSchema || s.Version != Version || !s.Policy.FreeTextOmitted {
		return errors.New("invalid shared report schema")
	}
	if err = os.Mkdir(out, 0700); err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			os.RemoveAll(out)
		}
	}()
	if err = writeFileNew(filepath.Join(out, "shared.json"), func(w io.Writer) error {
		encoder := json.NewEncoder(contextWriter{ctx: ctx, w: w})
		encoder.SetIndent("", "  ")
		return encoder.Encode(s)
	}); err != nil {
		return err
	}
	rows := [][]string{}
	for _, x := range s.Items {
		rows = append(rows, []string{x.ID, x.Source, x.Kind, strconv.FormatInt(x.Size, 10), sharedTime(x.Modified), sharedTime(x.Collected), strconv.FormatBool(x.Changed)})
	}
	if err = sharedCSVContext(ctx, filepath.Join(out, "evidence.csv"), []string{"id", "source", "kind", "size", "modified", "collected", "changed"}, rows); err != nil {
		return err
	}
	rows = [][]string{}
	for _, x := range s.Findings {
		rows = append(rows, []string{x.ID, x.Rule, x.Evidence, x.Source, strconv.Itoa(x.Line), x.Review, x.Reviewer})
	}
	if err = sharedCSVContext(ctx, filepath.Join(out, "findings.csv"), []string{"id", "rule", "evidence", "source", "line", "review", "reviewer"}, rows); err != nil {
		return err
	}
	rows = [][]string{}
	for _, x := range s.Timeline {
		rows = append(rows, []string{sharedTime(x.Time), x.Type, x.Evidence, x.Source, strconv.Itoa(x.Line), strconv.FormatInt(x.ByteOffset, 10), x.User, x.Host, x.SourceIP, x.DestinationIP, strconv.Itoa(x.Packet), x.Protocol, strconv.Itoa(int(x.SourcePort)), strconv.Itoa(int(x.DestinationPort)), strconv.FormatInt(x.CapturedLength, 10), strconv.FormatInt(x.OriginalLength, 10), strconv.Itoa(int(x.TCPFlags)), strconv.Itoa(x.Section), strconv.FormatUint(uint64(x.InterfaceID), 10)})
	}
	if err = sharedCSVContext(ctx, filepath.Join(out, "timeline.csv"), []string{"time", "type", "evidence", "source", "line", "byte_offset", "user", "host", "source_ip", "destination_ip", "packet", "protocol", "source_port", "destination_port", "captured_length", "original_length", "tcp_flags", "section", "interface_id"}, rows); err != nil {
		return err
	}
	rows = [][]string{}
	for _, x := range s.Correlations {
		rows = append(rows, []string{x.Kind, x.Value, strconv.Itoa(x.Events), strconv.Itoa(x.Sources), sharedTime(x.First), sharedTime(x.Last), strconv.FormatBool(x.Truncated)})
	}
	if err = sharedCSVContext(ctx, filepath.Join(out, "correlations.csv"), []string{"kind", "value", "events", "sources", "first", "last", "references_truncated"}, rows); err != nil {
		return err
	}
	rows = [][]string{}
	for _, x := range s.Reviews {
		rows = append(rows, []string{strconv.Itoa(x.Sequence), x.Finding, x.Decision, x.Analyst, sharedTime(x.Created)})
	}
	if err = sharedCSVContext(ctx, filepath.Join(out, "reviews.csv"), []string{"sequence", "finding", "decision", "analyst", "created"}, rows); err != nil {
		return err
	}
	if len(s.Custody) > 0 {
		rows = [][]string{}
		for _, x := range s.Custody {
			rows = append(rows, []string{strconv.Itoa(x.Sequence), x.Action, x.Actor, x.From, x.To, x.Location, sharedTime(x.OccurredAt), sharedTime(x.RecordedAt)})
		}
		if err = sharedCSVContext(ctx, filepath.Join(out, "custody.csv"), []string{"sequence", "action", "actor", "from", "to", "location", "occurred_at", "recorded_at"}, rows); err != nil {
			return err
		}
	}
	if e := exportSharedNetworkContext(ctx, s, out); e != nil {
		return e
	}
	t, e := template.New("shared").Funcs(template.FuncMap{"stamp": sharedTime, "endpoint": networkEndpoint}).Parse(sharedTemplate)
	if e != nil {
		return e
	}
	if err = writeFileNew(filepath.Join(out, "report.html"), func(w io.Writer) error {
		return t.Execute(contextWriter{ctx: ctx, w: w}, s)
	}); err != nil {
		return err
	}
	if e := exportSharedPDF(ctx, s, out); e != nil {
		return e
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	ok = true
	return nil
}

const sharedTemplate = `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>k957 · Masked sharing</title><style>` + reportStyle + `</style><main><header><small>k957 v{{.Version}} · DERIVED REPORT</small><h1>Masked sharing report</h1><p>Case: {{.Case}} · Host: {{.Host}} · Operator: {{.Operator}}</p><small>Sharing ID: {{.ID}} · Created: {{.Created}}</small><p class="reading-edition"><a href="report.pdf">PDF reading edition</a> · <a href="documents.json">Document coverage</a></p></header>
<p class="notice">This output is not original evidence or a digitally signed record. It is derived from source verification and examination. Free text has been omitted; anonymity is not guaranteed.</p>
{{if .FindingsTruncated}}<p class="notice">The finding limit was reached; additional findings were omitted. The finding count is a lower bound.</p>{{end}}
<section class="grid"><p class="card">Evidence objects: <b>{{len .Items}}</b></p><p class="card">Findings: <b>{{len .Findings}}</b></p><p class="card">Collection issues: <b>{{.SourceIssueCount}}</b></p><p class="card">Collection status: <b>{{.CollectionStatus}}</b></p></section>
<h2>Sharing scope</h2><p>Fields explicitly retained: {{range .Policy.Keep}}{{.}} · {{else}}None{{end}}<br>Additional masking expressions: {{.Policy.LiteralCount}}. Method/limitation notes omitted from the original report: {{.SourceNoteCount}}.</p>
<input id="search" placeholder="Search the sharing report…" aria-label="Search the sharing report">
<h2>Findings</h2><div class="scroll"><table><thead><tr><th>Finding / Rule</th><th>Evidence / Source</th><th>Line</th><th>Review</th></tr></thead><tbody>{{range .Findings}}<tr><td>{{.ID}} / {{.Rule}}</td><td><a href="#{{.Evidence}}">{{.Evidence}}</a><br>{{.Source}}</td><td>{{.Line}}</td><td>{{.Review}}<br>{{.Reviewer}}</td></tr>{{else}}<tr><td colspan="4">No findings to display.</td></tr>{{end}}</tbody></table></div>
<h2>Evidence inventory</h2><div class="scroll"><table><thead><tr><th>ID / Source</th><th>Kind / Bytes</th><th>Modified / Collected</th><th>Changed during acquisition</th></tr></thead><tbody>{{range .Items}}<tr id="{{.ID}}"><td>{{.ID}}<br>{{.Source}}</td><td>{{.Kind}} / {{.Size}}</td><td>{{stamp .Modified}}<br>{{stamp .Collected}}</td><td>{{.Changed}}</td></tr>{{end}}</tbody></table></div>
<h2>Timeline</h2><p>Times appear only when explicitly retained by the policy; source event order is preserved.</p><div class="scroll"><table><thead><tr><th>Time / Event</th><th>Evidence / Position</th><th>User / Host</th><th>IP</th></tr></thead><tbody>{{range .Timeline}}<tr><td>{{stamp .Time}}<br>{{.Type}}</td><td>{{.Evidence}} · {{.Source}}<br>Line {{.Line}} / Byte {{.ByteOffset}} {{if .Packet}} / Packet {{.Packet}}{{if .Section}} / Section {{.Section}} / Interface {{.InterfaceID}}{{end}}<br>{{.Protocol}} {{.SourcePort}} → {{.DestinationPort}}{{end}}</td><td>{{.User}}<br>{{.Host}}</td><td>{{.SourceIP}} → {{.DestinationIP}}</td></tr>{{end}}</tbody></table></div>
<h2>Shared values</h2><div class="scroll"><table><thead><tr><th>Kind / Value</th><th>Event / Evidence count</th><th>References</th></tr></thead><tbody>{{range .Correlations}}<tr><td>{{.Kind}} / {{.Value}}</td><td>{{.Events}} / {{.Sources}}</td><td>{{range .References}}{{.Evidence}}:{{.Line}} {{if .Packet}}packet {{.Packet}}{{if .Section}} / Section {{.Section}} / Interface {{.InterfaceID}}{{end}}{{end}} ({{.Role}})<br>{{end}}{{if .Truncated}}List truncated.{{end}}</td></tr>{{end}}</tbody></table></div>
{{if .Reviews}}<h2>Examiner decisions</h2><div class="scroll"><table><thead><tr><th>Sequence / Finding</th><th>Decision / Examiner</th><th>Time</th></tr></thead><tbody>{{range .Reviews}}<tr><td>{{.Sequence}} / {{.Finding}}</td><td>{{.Decision}} / {{.Analyst}}</td><td>{{stamp .Created}}</td></tr>{{end}}</tbody></table></div>{{end}}
{{if .Custody}}<h2>Masked custody history summary</h2><p>Recorded holder: {{.CurrentHolder}}. {{if .PendingTo}}Pending recipient: {{.PendingTo}}{{end}} Signatures and verification digests are omitted from this sharing copy.</p><div class="scroll"><table><thead><tr><th>Sequence / Action</th><th>Signer / Parties</th><th>Location</th><th>Declared / Recorded time</th></tr></thead><tbody>{{range .Custody}}<tr><td>{{.Sequence}} / {{.Action}}</td><td>{{.Actor}}<br>{{.From}} → {{.To}}</td><td>{{.Location}}</td><td>{{stamp .OccurredAt}}<br>{{stamp .RecordedAt}}</td></tr>{{end}}</tbody></table></div>{{end}}
{{if .CaptureSummaries}}<h2>PCAP / PCAPNG coverage</h2><div class="scroll"><table><thead><tr><th>Evidence / Format</th><th>Records / Parsed / Skipped</th><th>Truncated packets / Outside flow budget</th><th>Skip reasons / Limited / Error</th></tr></thead><tbody>{{range .CaptureSummaries}}<tr><td>{{.Evidence}} / {{.Format}}{{if .Sections}}<br>Section: {{.Sections}} / Interface: {{.InterfaceCount}} / Blocks: {{.Blocks}} / Ignored blocks: {{.IgnoredBlocks}}{{end}}</td><td>{{.Records}} / {{.Parsed}} / {{.Skipped}}</td><td>{{.TruncatedPackets}} / {{.FlowOmittedPackets}}</td><td>{{range $key,$value := .SkipReasons}}{{$key}}: {{$value}}<br>{{end}}{{.Limited}} / {{.HasError}}</td></tr>{{end}}</tbody></table></div>{{end}}
{{if .NetworkFlows}}<h2>Directional network flows</h2><div class="scroll"><table><thead><tr><th>Evidence / Protocol</th><th>Source → Destination</th><th>Packets / Captured / Reported bytes</th><th>First / Last</th><th>Packet references</th></tr></thead><tbody>{{range .NetworkFlows}}<tr><td>{{.Evidence}} / {{.Protocol}}{{if .Section}}<br>Section {{.Section}} / Interface {{.InterfaceID}}{{end}}</td><td>{{endpoint .SourceIP .SourcePort}} → {{endpoint .DestinationIP .DestinationPort}}</td><td>{{.Packets}} / {{.CapturedBytes}} / {{.OriginalBytes}}</td><td>{{stamp .First}}<br>{{stamp .Last}}</td><td>{{range .References}}Packet {{.Packet}}{{if .Section}} / Section {{.Section}} / Interface {{.InterfaceID}}{{end}}, byte {{.ByteOffset}}<br>{{end}}{{if .ReferencesTruncated}}Reference list truncated.{{end}}</td></tr>{{end}}</tbody></table></div>{{end}}
<h2>Parsing coverage</h2><div class="scroll"><table><thead><tr><th>Evidence / Format</th><th>Read / Events / Skipped</th><th>Limited / Error</th></tr></thead><tbody>{{range .ParseSummaries}}<tr><td>{{.Evidence}} / {{.Format}}</td><td>{{.Rows}} / {{.Parsed}} / {{.Skipped}}</td><td>{{.Limited}} / {{.HasError}}</td></tr>{{end}}</tbody></table></div>
<h2>Limitations</h2>{{range .Notes}}<p>{{.}}</p>{{end}}<footer><small>k957 · Sharing copy · No reverse mapping to the original report is included.</small>` + developerHTML + `</footer></main><script>document.getElementById('search').addEventListener('input',function(){const q=this.value.toLocaleLowerCase();document.querySelectorAll('tbody tr').forEach(r=>{r.hidden=!r.textContent.toLocaleLowerCase().includes(q)})})</script></html>`
