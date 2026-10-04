package core

import "html/template"

var reportHTMLTemplate = template.Must(template.New("report").Funcs(template.FuncMap{
	"endpoint":   networkEndpoint,
	"reportTime": reportPreciseTime,
}).Parse(reportTemplateSource))

const reportTemplateSource = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>k957 examination · {{.Case}}</title>
<style>` + reportStyle + `</style>
</head>
<body>
<main>
<header>
<p class="kicker">k957 examination report · version {{.Version}}</p>
<h1>{{.Case}}</h1>
<p class="lead">{{.Lead}}</p>
<p class="meta">Analysis {{.Run}} · written {{.Created}} · host {{.Host}}</p>
<ul class="facts">
<li class="fact fact-files"><span>{{.ItemCount}}</span> files acquired</li>
<li class="fact fact-findings"><span>{{.FindingCount}}</span> rule matches<small>{{.Unreviewed}} unreviewed</small></li>
<li class="fact {{if eq .IssueCount 0}}fact-ok{{else}}fact-critical{{end}}"><span>{{.IssueCount}}</span> collection issues</li>
<li class="fact fact-time"><span>{{.TimelineCount}}</span> timeline rows</li>
{{if .Memories}}<li class="fact fact-memory"><span>{{len .Memories}}</span> memory {{if eq (len .Memories) 1}}image{{else}}images{{end}}</li>{{end}}
</ul>
<p class="reading-edition"><a href="report.pdf">PDF reading edition</a> · <a href="documents.json">Document coverage</a> · <a href="analysis.json">Full analysis record</a></p>
</header>
<nav aria-label="Report sections">
<a href="#overview">Overview</a>
<a href="#examined">Examined</a>
<a href="#findings">Findings</a>
<a href="#activity">Activity</a>
<a href="#memory">Memory</a>
<a href="#timeline">Timeline</a>
{{if .USNGroups}}<a href="#usn-files">File changes</a>{{end}}
<a href="#inventory">Inventory</a>
<a href="#limits">Limits</a>
</nav>

<section id="overview"><h2>Examination overview</h2>
<p>{{.Brief.Confirmed}} confirmed · {{.Brief.NeedsReview}} requiring further review · {{.Brief.Unreviewed}} unreviewed · {{.Brief.Rejected}} rejected. Review state records examiner decisions; automatic matches do not establish compromise.</p>
<div class="figure-grid"><figure><figcaption>Finding review states · number of findings</figcaption>{{range .Brief.Reviews}}<div class="bar-row"><span>{{.Label}}</span><span class="bar-track"><span class="bar-fill" style="width:{{.Width}}%"></span></span><span>{{.Count}}</span></div>{{end}}<p class="figure-note">Source: this analysis and its applied review ledger. Bar widths are proportions of the finding total.</p></figure>
{{if .Brief.Timeline}}<figure><figcaption>Recorded event distribution · UTC interval / rows</figcaption>{{range .Brief.Timeline}}<div class="bar-row"><span>{{.Label}}</span><span class="bar-track"><span class="bar-fill" style="width:{{.Width}}%"></span></span><span>{{.Count}}</span></div>{{end}}<p class="figure-note">{{.Brief.DatedEvents}} dated rows, across equal intervals from the first to last source timestamp. Bar widths are relative to the busiest interval. Acquisition timestamps may be present; density is not severity.</p></figure>{{end}}</div>
<p class="muted">The documented review order is <a href="review-queue.json">review-queue.json</a>. Portable timeline rows are <a href="timeline.jsonl">timeline.jsonl</a>; observed hashes and IP addresses are in the adjacent text exports.</p>
</section>

{{if .Adaptive}}<section><h2>Adaptive executable acquisition</h2><p>{{.Adaptive.Processes}} processes · {{.Adaptive.Selected}} selected paths · {{.Adaptive.Collected}} collected paths · {{.Adaptive.Unavailable}} unavailable process paths · {{.Adaptive.MappedFiles}} executable mapped-file references · {{.Adaptive.MappingIssues}} unavailable mapping references. The signed {{.Adaptive.Record}} artifact in the original collection binds discovery references to later acquired file hashes. Linux mappings include executable shared-library mappings; Windows modules include loaded DLLs. This is not an atomic process snapshot; mapped or deleted bytes require memory examination.</p></section>{{end}}

<section id="examined">
<h2>What was examined</h2>
<dl>
<dt>Scope</dt><dd>{{.Scope}}</dd>
<dt>Host</dt><dd>{{.Host}} · {{.System}}</dd>
<dt>Operator</dt><dd>{{.Operator}}</dd>
<dt>Collection window</dt><dd>{{.CollectionWindow}}</dd>
<dt>Collection status</dt><dd>{{if eq .Status "complete"}}<span class="ok">complete</span>{{else}}<span class="warn">{{.Status}}</span>{{end}}</dd>
<dt>Finding coverage</dt><dd>{{if .FindingsTruncated}}<span class="warn">limited: additional findings omitted</span>{{else}}No finding truncation recorded{{end}}</dd>
<dt>Signature</dt><dd>{{.Signature}}</dd>
<dt>Evidence digest</dt><dd class="mono">{{.EvidenceDigest}}</dd>
{{if .PackageDigest}}<dt>Package manifest digest</dt><dd class="mono">{{.PackageDigest}}</dd>{{end}}
<dt>Files acquired</dt><dd>{{.ItemCount}}</dd>
<dt>Collection issues</dt><dd>{{if eq .IssueCount 0}}None recorded for the selected scope.{{else}}{{.IssueCount}}{{end}}</dd>
</dl>
<h3>Time range</h3>
<p>{{.TimelineSpan}}</p>
{{if .Coverage}}<h3>Examination coverage</h3>
<p class="muted">When the total is unknown, eligible counts are observed inputs and omitted counts are lower bounds.</p>
<table><thead><tr><th>Stage</th><th>Format</th><th>Unit</th><th>Status</th><th>Eligible</th><th>Emitted</th><th>Omitted</th><th>Total known</th></tr></thead><tbody>
{{range .Coverage}}<tr><td>{{.Stage}}</td><td>{{.Format}}</td><td>{{.Unit}}</td><td>{{.Status}}</td><td>{{.Eligible}}</td><td>{{.Emitted}}</td><td>{{.Omitted}}</td><td>{{.TotalKnown}}</td></tr>{{end}}
</tbody></table>{{end}}
<p class="muted">The collection window is the interval recorded while this package was acquired. Timeline rows use timestamps found in the sources. A match in a log is not proof that a person performed the action.</p>
</section>

<section id="findings">
<h2>Review candidates</h2>
<p>Rows come from literal rules, exact hashes or structured event predicates. Decisions are recorded separately. {{.Unreviewed}} of {{.FindingCount}} findings are unreviewed. Matches that also appear in a memory image are listed before high-volume phrases. Volume is not severity.</p>
{{range .FindingGroups}}
<article class="group{{if .InMemory}} in-memory{{end}}">
<header>
<div><strong>{{.Rule}}</strong><div class="muted">{{.Description}}</div></div>
<div class="tag">{{.Count}} {{if eq .Count 1}}match{{else}}matches{{end}} · {{.Sources}} {{if eq .Sources 1}}source{{else}}sources{{end}}{{if .InMemory}} · also in a memory image{{end}}</div>
</header>
{{range .Samples}}
<p><a href="#inv-{{.Evidence}}">{{.Evidence}}</a> · {{.Source}}{{if .Line}} · line {{.Line}}{{end}}<br><code>{{.Excerpt}}</code> <span class="pill pill-{{.Review}}">{{.Review}}</span></p>
{{end}}
</article>
{{else}}<p>No literal matches were recorded. That does not mean the activity did not occur.</p>{{end}}
<label for="finding-search">Search matches by rule, source, evidence id or excerpt</label>
<input id="finding-search" type="search" autocomplete="off">
<div class="pager"><button type="button" id="finding-prev">Previous</button><span id="finding-page"></span><button type="button" id="finding-next">Next</button></div>
<table>
<thead><tr><th>Rule</th><th>Source</th><th>Excerpt</th><th>Review</th></tr></thead>
<tbody id="finding-rows"></tbody>
</table>
<p class="muted">The full table, including every excerpt, is findings.csv next to this file.</p>
</section>

{{if .Indicators}}<section id="indicators"><h2>Offline indicator matches</h2><p>{{len .Indicators.Matches}} exact matches against {{.Indicators.Entries}} supplied indicators. List: {{.Indicators.Name}} · source: {{.Indicators.Source}} · SHA-256 <span class="mono">{{.Indicators.SHA256}}</span>.</p><p class="note">These are observations of matching values. They do not establish malicious activity, current provider reputation or analyst confirmation. Only supported parsed fields and collected hashes were compared; unsupported sources remain subject to the coverage record.</p><table><thead><tr><th>Indicator</th><th>Value / kind</th><th>Evidence reference</th><th>Matching basis</th></tr></thead><tbody>{{range .Indicators.Matches}}<tr><td>{{.Indicator}}</td><td>{{.Kind}} · <code>{{.Value}}</code></td><td>{{.Evidence}} · {{.Source}}{{if .Event}} · line {{.Event.Line}} · packet {{.Event.Packet}}{{end}}</td><td>{{.Basis}}</td></tr>{{end}}</tbody></table><p class="muted">Full matches and list identity are in indicators.json and indicator-matches.csv.</p></section>{{end}}

<section id="activity">
<h2>Interpreted activity</h2>
<p class="note plain">These rows are readings of collected text: SSH, sudo, cron, shell history, account creation, Windows events, Prefetch names and persistence commands. They are not findings and they do not identify a person.</p>
<table>
<thead><tr><th>Platform</th><th>Action</th><th>Rows</th></tr></thead>
<tbody>{{range .ActivityCounts}}<tr><td>{{.Platform}}</td><td>{{.Action}}</td><td>{{.Count}}</td></tr>{{else}}<tr><td colspan="3">No interpreted activity in this package.</td></tr>{{end}}</tbody>
</table>
{{if .Accounts}}
<h3>Account fields read from those rows</h3>
<table>
<thead><tr><th>Account text</th><th>Rows</th></tr></thead>
<tbody>{{range .Accounts}}<tr><td>{{.Name}}</td><td>{{.Count}}</td></tr>{{end}}</tbody>
</table>
<p class="muted">The name is the text captured from the source line. It was not resolved to a person.</p>
{{end}}
{{if .Persistence}}
<h3>Persistence commands present in acquired files</h3>
<p class="muted">A listed command was present in the file. Except for a Prefetch execution name recorded by Windows, presence is not proof the command ran.</p>
<table>
<thead><tr><th>When (UTC)</th><th>Type</th><th>Account</th><th>Command</th><th>Source</th></tr></thead>
<tbody>{{range .Persistence}}<tr><td>{{.Time.UTC.Format "2006-01-02T15:04:05Z07:00"}}</td><td>{{.Type}}</td><td>{{.User}}</td><td><code>{{.Detail}}</code></td><td><a href="#inv-{{.Evidence}}">{{.Evidence}}</a><br>{{.Source}}</td></tr>{{end}}</tbody>
</table>
{{end}}
</section>

{{if .Memories}}
<section id="memory">
<h2>Memory images</h2>
<p class="note plain">The image is read in a stream. Readings below come from headers and text that are still present. They are not a kernel task list or a socket-object walk, and they do not prove a program was running at acquisition. LiME addresses are physical. Raw addresses are file offsets. Zero pages include pages stored as zeros because they were unreadable.</p>
{{range .Memories}}
<h3>{{.Source}}</h3>
<dl>
<dt>Format</dt><dd>{{.Format}} · {{.ByteLabel}} · {{.Ranges}} ranges</dd>
<dt>Zero pages</dt><dd>{{.ZeroPages}}{{if .UnreadablePages}} · unreadable pages recorded: {{.UnreadablePages}}{{end}}</dd>
<dt>Hits</dt><dd>{{if .Results}}{{.Results.Hits}} · {{len .Hits}} in preview{{else}}{{len .Hits}}{{end}}{{if .Limited}} <span class="warn">The hit list stopped at the tool limit. Later matches are absent.</span>{{end}}</dd>
<dt>URL indicators</dt><dd>{{if .Results}}{{.Results.URLs}} occurrences · {{len .URLs}} unique values in preview{{else}}{{len .URLs}}{{end}}{{if .Limited}} <span class="warn">This list may also be capped.</span>{{end}}</dd>
<dt>Image SHA-256</dt><dd class="mono">{{.SHA256}}</dd>
{{if .Results}}<dt>Complete scan results</dt><dd><a href="{{.Results.Name}}">{{.Results.Name}}</a> · {{.Results.Rows}} records · SHA-256 <span class="mono">{{.Results.SHA256}}</span></dd>{{end}}
</dl>
{{if .Kernel}}{{if .Kernel.Unavailable}}<p class="warn">Unavailable plugin modules: {{range .Kernel.Unavailable}}{{.}} · {{end}}. Review the discovery record; their analysis was not performed.</p>{{end}}<h3>Kernel examination · {{.Kernel.Status}}</h3><p>{{len .Kernel.Examinations}} installed plugin attempts. Offline symbol digest: <span class="mono">{{.Kernel.SymbolsDigest}}</span>. Inspect <a href="{{.Kernel.Directory}}/memory-suite.json">the suite record</a> for tool identities and diagnostic files.</p><table><thead><tr><th>Plugin</th><th>Status</th><th>Top-level rows</th><th>Diagnostic</th></tr></thead><tbody>{{range .Kernel.Examinations}}<tr><td>{{.Plugin}}</td><td>{{.Status}}</td><td>{{.Rows}}</td><td>{{.Error}}</td></tr>{{end}}</tbody></table>{{end}}
{{if .KernelBanner}}
<h3>Recorded kernel banner</h3>
<p><code>{{.KernelBanner}}</code></p>
{{if .BannerPlausible}}<p class="muted">The text matches the shape of a Linux version line. It was not checked against an independent symbol bundle.</p>{{else}}<p class="warn">This text does not match a Linux version line. It is shown as stored and was not confirmed as the running kernel. The collector's own strings can contain the words “linux version”.</p>{{end}}
{{else}}<p>No kernel banner was recorded.</p>{{end}}
{{if .Samples}}
<h3>Sample hits</h3>
<table>
<thead><tr><th>Rule</th><th>Address</th><th>Encoding</th><th>Excerpt</th></tr></thead>
<tbody>{{range .Samples}}<tr><td>{{.Rule}}<br><span class="muted">{{.Description}}</span></td><td class="mono">{{printf "%#x" .Physical}}</td><td>{{.Encoding}}</td><td><code>{{.Excerpt}}</code></td></tr>{{end}}</tbody>
</table>
<p class="muted">{{if .Results}}Complete hits are in the linked disk-backed results; memory-hits.csv contains every literal hit.{{else}}All retained hits are in memory-hits.csv.{{end}}</p>
{{end}}
{{if .URLSample}}
<details>
<summary>URL indicators kept from the image ({{len .URLs}})</summary>
<ul>{{range .URLSample}}<li><code>{{.}}</code></li>{{end}}</ul>
{{if gt (len .URLs) (len .URLSample)}}<p class="muted">Further indicators remain in analysis.json.</p>{{end}}
</details>
{{end}}
<h3>Symbol-free readings</h3>
{{if .ObsCounts}}
<table>
<thead><tr><th>Kind</th><th>Rows</th></tr></thead>
<tbody>{{range .ObsCounts}}<tr><td>{{.Type}}</td><td>{{.Count}}</td></tr>{{end}}</tbody>
</table>
<table>
<thead><tr><th>Kind</th><th>Address</th><th>Reading</th></tr></thead>
<tbody>{{range .ObsSample}}<tr><td>{{.Kind}}</td><td class="mono">{{printf "%#x" .Physical}}</td><td><code>{{.Detail}}</code></td></tr>{{end}}</tbody>
</table>
<p class="muted">{{if .ObservationsLimited}}The reading list stopped at the tool limit. Later rows are absent. {{end}}{{if .Results}}The complete list is in the linked disk-backed results; memory-observations.csv contains every structured observation.{{else}}The full list is memory-observations.csv.{{end}} Repeated observations at different addresses are retained. Password hashes, secret environment values, and private-key bodies are not copied.</p>
{{else}}<p>No executable header, account line, network row, module string, or command line was recorded in this image.</p>{{end}}
{{range .Notes}}<p class="muted">{{.}}</p>{{end}}
{{if .Volatility}}
<details>
<summary>Optional Volatility 3 commands</summary>
<p class="muted">Kernel symbols are supplied by the examiner. Configure K957_VOLATILITY and K957_MEMORY_SYMBOLS for automatic platform-wide analysis, or use memory-examine. These command suggestions are separate from any recorded suite execution.</p>
{{range .Volatility}}<p class="mono">{{.}}</p>{{end}}
</details>
{{end}}
{{end}}
</section>
{{end}}

<section id="timeline">
<h2>Order of recorded events</h2>
<p>{{.TimelineSpan}}</p>
<table>
<thead><tr><th>Event type</th><th>Rows</th></tr></thead>
<tbody>{{range .EventCounts}}<tr><td>{{.Type}}</td><td>{{.Count}}</td></tr>{{else}}<tr><td colspan="2">No timeline rows.</td></tr>{{end}}</tbody>
</table>
<p class="muted">The ordered table is <a href="timeline.csv">timeline.csv</a>. USN record details and raw file/parent IDs are in <a href="usn.csv">usn.csv</a>. Journal names do not establish full paths or user attribution. File modification times and log timestamps are source values. Rows typed “collected” mark when this acquisition read the file.</p>
</section>

{{if .USNGroups}}<section id="usn-files">
<h2>USN file record groups</h2>
<p>{{.USNGroupCount}} source-scoped groups · {{len .USNGroups}} shown. Counts describe emitted journal records, not distinct file operations. Names and parent IDs are observations; full paths and rename pairs are not inferred. Parser coverage identifies omitted records.</p>
<p><a href="usn-files.json">Full grouped references (JSON)</a> · <a href="usn-files.csv">Grouped file records (CSV)</a> · <a href="usn.csv">Individual records (CSV)</a></p>
<div class="table-wrap"><table><thead><tr><th>Evidence / file ID</th><th>Observed names</th><th>Parent IDs</th><th>Records / UTC bounds</th><th>Observed reason flags</th></tr></thead><tbody>
{{range .USNGroups}}<tr><td>{{.Evidence}} · v{{.Version}}<br><span class="mono">{{.FileID}}</span><br>{{.Source}}</td><td>{{range .Names}}<div>{{.}}</div>{{end}}{{if .NamesOmitted}}<small>{{.NamesOmitted}} additional names in full exports</small>{{end}}</td><td>{{range .Parents}}<div class="mono">{{.}}</div>{{end}}{{if .ParentsOmitted}}<small>{{.ParentsOmitted}} additional parents in full exports</small>{{end}}</td><td>{{.Records}} records<br>{{reportTime .First}}<br>{{reportTime .Last}}</td><td>{{range .Reasons}}<div>{{.}}</div>{{end}}</td></tr>{{end}}
</tbody></table></div>
<p class="muted">File/parent IDs use their original little-endian byte hex. Groups remain separate by evidence object, source and record version. The time range is the minimum and maximum observed timestamp, not a proven file lifetime. Full exports retain every group and record reference in the emitted analysis.</p>
</section>{{end}}

<section id="inventory">
<h2>Evidence inventory</h2>
<p>{{.ItemCount}} acquired objects. SHA-256 below is the hash recorded for that object. Compare it with the evidence package before relying on a row.</p>
{{if .MediaCounts}}
<table>
<thead><tr><th>Detected type</th><th>Objects</th></tr></thead>
<tbody>{{range .MediaCounts}}<tr><td>{{.Type}}</td><td>{{.Count}}</td></tr>{{end}}</tbody>
</table>
<p class="muted">Types use the first 560 bytes or explicit filename hints for formats such as USN. A filename candidate requires parser validation.{{if .Mismatches}} {{len .Mismatches}} shown where the name and the signature disagree.{{else}} No extension/signature disagreement was recorded.{{end}}</p>
{{end}}
{{if .Mismatches}}
<table>
<thead><tr><th>Evidence</th><th>Detected type</th><th>Source</th></tr></thead>
<tbody>{{range .Mismatches}}<tr><td><a href="#inv-{{.Evidence}}">{{.Evidence}}</a></td><td>{{.MediaType}}<br><span class="muted">{{.Description}}</span></td><td>{{.Source}}</td></tr>{{end}}</tbody>
</table>
{{end}}
<label for="inventory-search">Search inventory by id, path or hash</label>
<input id="inventory-search" type="search" autocomplete="off">
<div class="pager"><button type="button" id="inventory-prev">Previous</button><span id="inventory-page"></span><button type="button" id="inventory-next">Next</button></div>
<table>
<thead><tr><th>Identity</th><th>Bytes</th><th>SHA-256</th><th>Kind</th></tr></thead>
<tbody id="inventory-rows"></tbody>
</table>
<p class="muted">filetypes.csv and bodyfile.txt sit beside this report. bodyfile.txt has mtime only.</p>
</section>

{{if .HashMatches}}
<section id="hashes">
<h2>Examiner hash set</h2>
<p class="note plain">Exact SHA-256 comparison. known-good is not a trust decision. known-bad is not a malware verdict.</p>
<table>
<thead><tr><th>Evidence</th><th>Verdict</th><th>SHA-256</th></tr></thead>
<tbody>{{range .HashMatches}}<tr><td><a href="#inv-{{.Evidence}}">{{.Evidence}}</a><br>{{.Source}}<br>{{.Label}}</td><td>{{.Verdict}}</td><td class="mono">{{.SHA256}}</td></tr>{{end}}</tbody>
</table>
</section>
{{else if .HashSet}}<p class="muted">Examiner hash set applied: {{.HashSet.Entries}} entries; no matching evidence objects.</p>{{else}}<p class="muted">No examiner hash set was applied to this analysis.</p>{{end}}

{{if .Correlations}}
<section id="links">
<h2>Values seen in more than one object</h2>
<p class="muted">The same value occurred in at least two evidence objects. That does not prove two independent sources, or that they belong to the same person or device.</p>
<table>
<thead><tr><th>Kind</th><th>Value</th><th>Events</th><th>Sources</th><th>First / last UTC</th></tr></thead>
<tbody>{{range .Correlations}}<tr><td>{{.Kind}}</td><td><code>{{.Value}}</code></td><td>{{.Events}}</td><td>{{.Sources}}</td><td>{{.First.UTC.Format "2006-01-02T15:04:05Z07:00"}}<br>{{.Last.UTC.Format "2006-01-02T15:04:05Z07:00"}}</td></tr>{{end}}</tbody>
</table>
</section>
{{end}}

{{if .Windows}}
<section id="windows">
<h2>Windows event XML records</h2>
<p class="note plain">Fields shown are those present in the exported XML. An event id alone does not prove an action or identify a person. Event data is not interpreted per provider. Security identifiers were not resolved. Native EVTX was not parsed.</p>
<table>
<thead><tr><th>Evidence</th><th>Provider / event</th><th>Time / computer</th><th>Message and data</th></tr></thead>
<tbody>{{range .Windows}}<tr><td><a href="#inv-{{.Evidence}}">{{.Evidence}}</a><br>{{.Source}}<br>line {{.Line}}</td><td>{{.Windows.Provider}}<br>event {{.Windows.EventID}}{{if .Windows.Channel}}<br>{{.Windows.Channel}}{{end}}</td><td>{{.Time.UTC.Format "2006-01-02T15:04:05Z07:00"}}<br>{{.Host}}<br>{{.User}}</td><td>{{.Detail}}{{range .Windows.Data}}<br><strong>{{.Name}}</strong>: <code>{{.Value}}</code>{{end}}{{if .Windows.PayloadOmitted}}<br>Some payload sections were not examined.{{end}}{{if .Windows.MessageTruncated}}<br>The message was truncated.{{end}}</td></tr>{{end}}</tbody>
</table>
</section>
{{end}}

{{if .Captures}}
<section id="captures">
<h2>Packet capture coverage</h2>
<p class="muted">Only packet headers were examined. Flows are directional 5-tuples, not completed connections and not attribution.</p>
<table>
<thead><tr><th>Evidence</th><th>Format</th><th>Records / parsed / skipped</th></tr></thead>
<tbody>{{range .Captures}}<tr><td>{{.Evidence}}</td><td>{{.Format}}</td><td>{{.Records}} / {{.Parsed}} / {{.Skipped}}{{if .Limited}}<br>Limited{{end}}{{if .Error}}<br>{{.Error}}{{end}}{{if .Sections}}<br>Sections: {{.Sections}} / Interfaces: {{len .Interfaces}}{{end}}</td></tr>{{end}}</tbody>
</table>
</section>
{{end}}

{{if .NetworkInterpretations}}<section><h2>Network sessions and application metadata</h2><p>TCP streams retain only a bounded contiguous prefix. Conflicting overlaps are excluded from application interpretation. No TLS decryption, IP fragment reassembly, HTTP body or provider enrichment is performed. Checksum failures may reflect offload. Refer to network-protocols.csv and analysis.json for metadata and packet references.</p>{{range .NetworkInterpretations}}<h3>{{.Evidence}}</h3><p>{{len .Sessions}} TCP sessions · {{len .Observations}} application observations · limit reached: {{.Limited}}</p><div class="table-wrap"><table><thead><tr><th>Session</th><th>Endpoints</th><th>Packets / bytes</th><th>Omissions</th></tr></thead><tbody>{{range .Sessions}}<tr><td>{{.ID}}</td><td>{{.EndpointA}} ↔ {{.EndpointB}}</td><td>{{.Packets}} / {{.Bytes}}</td><td>Gaps: {{.Gaps}}; overlap conflict: {{.Conflict}}; limited: {{.Limited}}; references omitted: {{.ReferencesTruncated}}</td></tr>{{end}}</tbody></table></div>{{end}}</section>{{end}}
{{if .Flows}}
<section id="network">
<h2>Directed network flows</h2>
<table>
<thead><tr><th>Evidence</th><th>Flow</th><th>Packets</th><th>First / last UTC</th></tr></thead>
<tbody>{{range .Flows}}<tr><td>{{.Evidence}}<br>{{.Protocol}}{{if .Section}}<br>Section {{.Section}} / Interface {{.InterfaceID}}{{end}}</td><td>{{endpoint .SourceIP .SourcePort}} → {{endpoint .DestinationIP .DestinationPort}}</td><td>{{.Packets}}</td><td>{{.First.UTC.Format "2006-01-02T15:04:05Z07:00"}}<br>{{.Last.UTC.Format "2006-01-02T15:04:05Z07:00"}}</td></tr>{{end}}</tbody>
</table>
</section>
{{end}}

{{if .Epochs}}
<section id="epochs">
<h2>Acquisition epochs</h2>
<p class="note">Inventory was frozen on the first run. Parts may come from different invocations. This package is not one point-in-time snapshot.</p>
<table>
<thead><tr><th>Epoch</th><th>Host</th><th>Start / finish UTC</th><th>Outcome</th></tr></thead>
<tbody>{{range .Epochs}}<tr><td>{{.ID}}</td><td>{{.Host}} · {{.OS}}/{{.Arch}}</td><td>{{.Started.UTC.Format "2006-01-02T15:04:05Z07:00"}}<br>{{.Finished.UTC.Format "2006-01-02T15:04:05Z07:00"}}</td><td>{{.Outcome}}</td></tr>{{end}}</tbody>
</table>
</section>
{{end}}

{{if .Reviews}}
<section id="review">
<h2>Analyst decisions</h2>
<p class="muted">Signature: {{.ReviewSignature}}. Digest: <span class="mono">{{.ReviewDigest}}</span>. Decisions are analyst judgments. The literal matches and the original evidence remain.</p>
<table>
<thead><tr><th>Sequence</th><th>Finding</th><th>Analyst</th><th>Decision</th></tr></thead>
<tbody>{{range .Reviews}}<tr><td>{{.Sequence}}</td><td class="mono">{{.Finding}}</td><td>{{.Analyst}}<br>{{.Created}}</td><td>{{.Decision}}<br>{{.Note}}</td></tr>{{end}}</tbody>
</table>
</section>
{{end}}

{{if .Custody}}
<section id="custody">
<h2>Signed custody</h2>
<p class="note">{{.Custody.Trust}}<br>Holder recorded on the ledger: {{.Custody.CurrentHolder}}. {{if .Custody.PendingTo}}Transfer waiting for {{.Custody.PendingTo}}.{{else}}No transfer is waiting.{{end}}<br>Head <span class="mono">{{.Custody.Head}}</span><br>Trust digest <span class="mono">{{.Custody.TrustDigest}}</span><br>Signatures authenticate the statements. They do not prove physical handover, a person's identity, or a trusted timestamp.</p>
<table>
<thead><tr><th>Sequence</th><th>Action</th><th>Parties</th><th>When</th><th>Note</th></tr></thead>
<tbody>{{range .Custody.Events}}<tr><td>{{.Sequence}}</td><td>{{.Action}}</td><td>{{.Actor}}<br>{{.From}} → {{.To}}</td><td>{{.OccurredAt}}<br>{{.RecordedAt}}</td><td>{{.Location}}<br>{{.Note}}<br><span class="mono">{{.Signer}}</span></td></tr>{{end}}</tbody>
</table>
</section>
{{end}}

<section id="limits">
<h2>What this examination does not establish</h2>
{{if .Canceled}}<p class="note">Analysis canceled. Remaining evidence was not examined.</p>{{end}}
{{if .FindingsTruncated}}<p class="note">Finding limit reached. Additional findings were omitted; inventory and supported event parsing continued. Counts are lower bounds.</p>{{end}}
{{if .HashSet}}{{if .HashSet.Truncated}}<p class="note">Hash-match details were truncated. {{.HashSet.Matched}} objects matched {{.HashSet.Entries}} set entries.</p>{{end}}{{end}}
{{if .ParseSummaries}}
<details><summary>Per-object parser coverage and omissions</summary>
<table><thead><tr><th>Evidence</th><th>Parser</th><th>Rows / parsed / skipped</th><th>Limits and errors</th></tr></thead><tbody>
{{range .ParseSummaries}}<tr><td>{{.Evidence}}</td><td>{{.Format}}</td><td>{{.Rows}} / {{.Parsed}} / {{.Skipped}}</td><td>{{if .Limited}}Limited. {{end}}{{.Error}}{{range $reason, $count := .SkipReasons}}<br>{{$reason}}: {{$count}}{{end}}</td></tr>{{end}}
</tbody></table></details>
{{end}}
<ul>
<li>Literal matches and activity rows are not verified findings and are not attribution.</li>
<li>Clock offset was not measured. Timestamps follow the source host clock, shown in UTC.</li>
<li>{{if eq .SkipCount 0}}No per-file skip notes were recorded.{{else if eq .SkipCount 1}}1 file was skipped or only partly read. The note is below.{{else}}{{.SkipCount}} files were skipped or only partly read. The first notes are below; the rest are in analysis.json.{{end}}</li>
{{if .ParseCounts}}<li>Parse coverage: {{range .ParseCounts}}{{.Count}} {{.Type}}; {{end}}per-file rows remain in analysis.json.</li>{{end}}
</ul>
{{range .SkipSample}}<p class="muted">{{.}}</p>{{end}}
{{range .MethodNotes}}<p>{{.}}</p>{{end}}
{{if .Issues}}
<h3>Collection issues</h3>
{{range .Issues}}<p class="note"><strong>{{.Source}}</strong><br>{{.Reason}}</p>{{end}}
{{else}}<p>No collection issue was recorded. That statement covers only the selected scope.</p>{{end}}
</section>

<footer>
<p>k957 · traceable examination · this document is not a final expert opinion. Confirm a row against the evidence id, source path and SHA-256 before relying on it.</p>
` + developerHTML + `</footer>
</main>
<script>
window.k957Report = {findings: {{.FindingsJSON}}, inventory: {{.InventoryJSON}}};
(function(){
function read(name){var rows=window.k957Report&&window.k957Report[name];return Array.isArray(rows)?rows:[]}
function cell(text){var td=document.createElement("td");td.textContent=text==null?"":String(text);return td}
function page(rows,query,pageNo,size){
  var q=(query||"").toLocaleLowerCase();
  var matched=rows.filter(function(row){return !q||JSON.stringify(row).toLocaleLowerCase().indexOf(q)>=0});
  var pages=Math.max(1,Math.ceil(matched.length/size));
  if(pageNo>=pages)pageNo=pages-1;
  if(pageNo<0)pageNo=0;
  return {rows:matched.slice(pageNo*size,pageNo*size+size),page:pageNo,pages:pages,total:matched.length};
}
var renderInventory=function(){};
function bind(prefix,rows,draw){
  var q=document.getElementById(prefix+"-search");
  var label=document.getElementById(prefix+"-page");
  var body=document.getElementById(prefix+"-rows");
  var state=0;
  function render(printing){
    var view=printing?{rows:rows,page:0,pages:1,total:rows.length}:page(rows,q&&q.value,state,25);
    if(!printing)state=view.page;
    body.textContent="";
    view.rows.forEach(function(row){draw(body,row)});
    label.textContent=(view.total?state+1:0)+" / "+view.pages+" · "+view.total;
  }
  window.addEventListener("beforeprint",function(){render(true)});
  window.addEventListener("afterprint",function(){render(false)});
  if(q)q.addEventListener("input",function(){state=0;render()});
  document.getElementById(prefix+"-prev").addEventListener("click",function(){state--;render()});
  document.getElementById(prefix+"-next").addEventListener("click",function(){state++;render()});
  render();
  return function(query){if(q){q.value=query}state=0;render();document.getElementById("inventory").scrollIntoView()};
}
bind("finding",read("findings"),function(body,row){
  var tr=document.createElement("tr");
  tr.appendChild(cell(row.Rule));
  var src=document.createElement("td");
  var a=document.createElement("a");
  a.href="#inventory";
  a.textContent=row.Evidence||"";
  a.addEventListener("click",function(ev){ev.preventDefault();renderInventory(row.Evidence||"")});
  src.appendChild(a);
  src.appendChild(document.createTextNode(" "+(row.Source||"")+(row.Line?" · line "+row.Line:"")));
  tr.appendChild(src);
  tr.appendChild(cell(row.Excerpt));
  var review=document.createElement("td");
  var pill=document.createElement("span");
  pill.className="pill pill-"+(row.Review||"");
  pill.textContent=row.Review||"";
  review.appendChild(pill);
  tr.appendChild(review);
  body.appendChild(tr);
});
renderInventory=bind("inventory",read("inventory"),function(body,row){
  var tr=document.createElement("tr");
  tr.id="inv-"+row.ID;
  var id=document.createElement("td");
  id.appendChild(document.createTextNode(row.ID||""));
  id.appendChild(document.createElement("br"));
  id.appendChild(document.createTextNode(row.Source||""));
  tr.appendChild(id);
  tr.appendChild(cell(row.Size));
  var hash=cell(row.SHA256);
  hash.className="mono";
  tr.appendChild(hash);
  tr.appendChild(cell((row.Kind||"")+(row.Changed?" · changed during acquisition":"")));
  body.appendChild(tr);
});
document.querySelectorAll('a[href^="#inv-"]').forEach(function(link){
  link.addEventListener("click",function(ev){
    ev.preventDefault();
    renderInventory(link.getAttribute("href").slice(5));
  });
});
})();
</script>
</body>
</html>
`
