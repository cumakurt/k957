package core

import (
	"bytes"
	"encoding/csv"
	"errors"
	"html/template"
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
	var b bytes.Buffer
	w := csv.NewWriter(&b)
	if e := w.Write(header); e != nil {
		return e
	}
	for _, r := range rows {
		for i := range r {
			r[i] = csvSafe(r[i])
		}
		if e := w.Write(r); e != nil {
			return e
		}
	}
	w.Flush()
	if e := w.Error(); e != nil {
		return e
	}
	return WriteNew(path, b.Bytes())
}
func ExportShared(s SharedReport, out string) (err error) {
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
	if err = WriteNew(filepath.Join(out, "shared.json"), JSON(s)); err != nil {
		return err
	}
	rows := [][]string{}
	for _, x := range s.Items {
		rows = append(rows, []string{x.ID, x.Source, x.Kind, strconv.FormatInt(x.Size, 10), sharedTime(x.Modified), sharedTime(x.Collected), strconv.FormatBool(x.Changed)})
	}
	if err = sharedCSV(filepath.Join(out, "evidence.csv"), []string{"id", "source", "kind", "size", "modified", "collected", "changed"}, rows); err != nil {
		return err
	}
	rows = [][]string{}
	for _, x := range s.Findings {
		rows = append(rows, []string{x.ID, x.Rule, x.Evidence, x.Source, strconv.Itoa(x.Line), x.Review, x.Reviewer})
	}
	if err = sharedCSV(filepath.Join(out, "findings.csv"), []string{"id", "rule", "evidence", "source", "line", "review", "reviewer"}, rows); err != nil {
		return err
	}
	rows = [][]string{}
	for _, x := range s.Timeline {
		rows = append(rows, []string{sharedTime(x.Time), x.Type, x.Evidence, x.Source, strconv.Itoa(x.Line), strconv.FormatInt(x.ByteOffset, 10), x.User, x.Host, x.SourceIP, x.DestinationIP, strconv.Itoa(x.Packet), x.Protocol, strconv.Itoa(int(x.SourcePort)), strconv.Itoa(int(x.DestinationPort)), strconv.FormatInt(x.CapturedLength, 10), strconv.FormatInt(x.OriginalLength, 10), strconv.Itoa(int(x.TCPFlags)), strconv.Itoa(x.Section), strconv.FormatUint(uint64(x.InterfaceID), 10)})
	}
	if err = sharedCSV(filepath.Join(out, "timeline.csv"), []string{"time", "type", "evidence", "source", "line", "byte_offset", "user", "host", "source_ip", "destination_ip", "packet", "protocol", "source_port", "destination_port", "captured_length", "original_length", "tcp_flags", "section", "interface_id"}, rows); err != nil {
		return err
	}
	rows = [][]string{}
	for _, x := range s.Correlations {
		rows = append(rows, []string{x.Kind, x.Value, strconv.Itoa(x.Events), strconv.Itoa(x.Sources), sharedTime(x.First), sharedTime(x.Last), strconv.FormatBool(x.Truncated)})
	}
	if err = sharedCSV(filepath.Join(out, "correlations.csv"), []string{"kind", "value", "events", "sources", "first", "last", "references_truncated"}, rows); err != nil {
		return err
	}
	rows = [][]string{}
	for _, x := range s.Reviews {
		rows = append(rows, []string{strconv.Itoa(x.Sequence), x.Finding, x.Decision, x.Analyst, sharedTime(x.Created)})
	}
	if err = sharedCSV(filepath.Join(out, "reviews.csv"), []string{"sequence", "finding", "decision", "analyst", "created"}, rows); err != nil {
		return err
	}
	if len(s.Custody) > 0 {
		rows = [][]string{}
		for _, x := range s.Custody {
			rows = append(rows, []string{strconv.Itoa(x.Sequence), x.Action, x.Actor, x.From, x.To, x.Location, sharedTime(x.OccurredAt), sharedTime(x.RecordedAt)})
		}
		if err = sharedCSV(filepath.Join(out, "custody.csv"), []string{"sequence", "action", "actor", "from", "to", "location", "occurred_at", "recorded_at"}, rows); err != nil {
			return err
		}
	}
	if e := exportSharedNetwork(s, out); e != nil {
		return e
	}
	t, e := template.New("shared").Funcs(template.FuncMap{"stamp": sharedTime, "endpoint": networkEndpoint}).Parse(sharedTemplate)
	if e != nil {
		return e
	}
	var b bytes.Buffer
	if e = t.Execute(&b, s); e != nil {
		return e
	}
	if err = WriteNew(filepath.Join(out, "report.html"), b.Bytes()); err != nil {
		return err
	}
	ok = true
	return nil
}

const sharedTemplate = `<!doctype html><html lang="tr"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>k957 · Maskelenmiş paylaşım</title><style>
:root{color-scheme:dark}body{font:15px system-ui;background:#0a1220;color:#dce6f4;margin:0}main{max-width:1200px;margin:auto;padding:36px}header{border-bottom:1px solid #334155;padding-bottom:22px}h1{font-size:36px;color:#62e3b7}h2{margin-top:34px}small{color:#b4bfd1}.notice{padding:18px;border-left:4px solid #e6b566;background:#242434}.grid{display:flex;gap:16px;flex-wrap:wrap}.card{padding:18px;background:#142236;border-radius:10px;flex:1}table{border-collapse:collapse;width:100%;background:#111e30}td,th{border-bottom:1px solid #304158;padding:10px;text-align:left;vertical-align:top;overflow-wrap:anywhere}.scroll{overflow:auto;max-height:550px}a{color:#62e3b7}input{padding:12px;background:#17273d;color:white;border:1px solid #536b88;width:90%;margin:20px 0}@media print{body{background:white;color:black}main{padding:0}.card,table,.notice{background:white;color:black}.scroll{max-height:none;overflow:visible}input{display:none}tr{break-inside:avoid}}
</style><main><header><small>k957 v{{.Version}} · TÜREV RAPOR</small><h1>Maskelenmiş paylaşım raporu</h1><p>Vaka: {{.Case}} · Cihaz: {{.Host}} · Operatör: {{.Operator}}</p><small>Paylaşım kimliği: {{.ID}} · Üretim: {{.Created}}</small></header>
<p class="notice">Bu çıktı özgün delil veya dijital imzalı kayıt değildir. Kaynak doğrulaması ve incelemesinden türetilmiştir. Serbest metinler çıkarılmıştır; anonimlik garantisi verilmez.</p>
<section class="grid"><p class="card">Delil nesnesi: <b>{{len .Items}}</b></p><p class="card">Bulgu: <b>{{len .Findings}}</b></p><p class="card">Toplama sorunu: <b>{{.SourceIssueCount}}</b></p><p class="card">Toplama durumu: <b>{{.CollectionStatus}}</b></p></section>
<h2>Paylaşım kapsamı</h2><p>Açık bırakılması istenen alanlar: {{range .Policy.Keep}}{{.}} · {{else}}Yok{{end}}<br>Ek maskeleme ifadesi sayısı: {{.Policy.LiteralCount}}. Özgün rapordan çıkarılan yöntem/sınırlama notu sayısı: {{.SourceNoteCount}}.</p>
<input id="search" placeholder="Paylaşım raporunda ara…" aria-label="Paylaşım raporunda ara">
<h2>Bulgular</h2><div class="scroll"><table><thead><tr><th>Bulgu / Kural</th><th>Delil / Kaynak</th><th>Satır</th><th>Değerlendirme</th></tr></thead><tbody>{{range .Findings}}<tr><td>{{.ID}} / {{.Rule}}</td><td><a href="#{{.Evidence}}">{{.Evidence}}</a><br>{{.Source}}</td><td>{{.Line}}</td><td>{{.Review}}<br>{{.Reviewer}}</td></tr>{{else}}<tr><td colspan="4">Gösterilecek bulgu yok.</td></tr>{{end}}</tbody></table></div>
<h2>Delil envanteri</h2><div class="scroll"><table><thead><tr><th>Kimlik / Kaynak</th><th>Tür / Bayt</th><th>Değiştirilme / Toplanma</th><th>Edinim sırasında değişim</th></tr></thead><tbody>{{range .Items}}<tr id="{{.ID}}"><td>{{.ID}}<br>{{.Source}}</td><td>{{.Kind}} / {{.Size}}</td><td>{{stamp .Modified}}<br>{{stamp .Collected}}</td><td>{{.Changed}}</td></tr>{{end}}</tbody></table></div>
<h2>Zaman çizelgesi</h2><p>Zamanlar yalnızca politika açık bırakmışsa gösterilir; kaynak olay sırası korunur.</p><div class="scroll"><table><thead><tr><th>Zaman / Olay</th><th>Delil / Konum</th><th>Kullanıcı / Cihaz</th><th>IP</th></tr></thead><tbody>{{range .Timeline}}<tr><td>{{stamp .Time}}<br>{{.Type}}</td><td>{{.Evidence}} · {{.Source}}<br>Satır {{.Line}} / Byte {{.ByteOffset}} {{if .Packet}} / Paket {{.Packet}}{{if .Section}} / Bölüm {{.Section}} / Arayüz {{.InterfaceID}}{{end}}<br>{{.Protocol}} {{.SourcePort}} → {{.DestinationPort}}{{end}}</td><td>{{.User}}<br>{{.Host}}</td><td>{{.SourceIP}} → {{.DestinationIP}}</td></tr>{{end}}</tbody></table></div>
<h2>Ortak değerler</h2><div class="scroll"><table><thead><tr><th>Tür / Değer</th><th>Olay / Delil sayısı</th><th>Referanslar</th></tr></thead><tbody>{{range .Correlations}}<tr><td>{{.Kind}} / {{.Value}}</td><td>{{.Events}} / {{.Sources}}</td><td>{{range .References}}{{.Evidence}}:{{.Line}} {{if .Packet}}paket {{.Packet}}{{if .Section}} / Bölüm {{.Section}} / Arayüz {{.InterfaceID}}{{end}}{{end}} ({{.Role}})<br>{{end}}{{if .Truncated}}Liste sınırlandı.{{end}}</td></tr>{{end}}</tbody></table></div>
{{if .Reviews}}<h2>Analist kararları</h2><div class="scroll"><table><thead><tr><th>Sıra / Bulgu</th><th>Karar / Analist</th><th>Zaman</th></tr></thead><tbody>{{range .Reviews}}<tr><td>{{.Sequence}} / {{.Finding}}</td><td>{{.Decision}} / {{.Analyst}}</td><td>{{stamp .Created}}</td></tr>{{end}}</tbody></table></div>{{end}}
{{if .Custody}}<h2>Devir geçmişinin maskelenmiş özeti</h2><p>Kayda göre sorumlu: {{.CurrentHolder}}. {{if .PendingTo}}Bekleyen alıcı: {{.PendingTo}}{{end}} İmzalar ve doğrulama özetleri bu paylaşım kopyasına aktarılmamıştır.</p><div class="scroll"><table><thead><tr><th>Sıra / İşlem</th><th>İmzalayan / Taraflar</th><th>Konum</th><th>Beyan / Kayıt zamanı</th></tr></thead><tbody>{{range .Custody}}<tr><td>{{.Sequence}} / {{.Action}}</td><td>{{.Actor}}<br>{{.From}} → {{.To}}</td><td>{{.Location}}</td><td>{{stamp .OccurredAt}}<br>{{stamp .RecordedAt}}</td></tr>{{end}}</tbody></table></div>{{end}}
{{if .CaptureSummaries}}<h2>PCAP / PCAPNG kapsamı</h2><div class="scroll"><table><thead><tr><th>Delil / Biçim</th><th>Kayıt / Ayrıştırılan / Atlanan</th><th>Eksik yakalama / Akış dışı</th><th>Atlama nedenleri / Sınır / Hata</th></tr></thead><tbody>{{range .CaptureSummaries}}<tr><td>{{.Evidence}} / {{.Format}}{{if .Sections}}<br>Bölüm: {{.Sections}} / Arayüz: {{.InterfaceCount}} / Blok: {{.Blocks}} / İncelenmeyen blok: {{.IgnoredBlocks}}{{end}}</td><td>{{.Records}} / {{.Parsed}} / {{.Skipped}}</td><td>{{.TruncatedPackets}} / {{.FlowOmittedPackets}}</td><td>{{range $key,$value := .SkipReasons}}{{$key}}: {{$value}}<br>{{end}}{{.Limited}} / {{.HasError}}</td></tr>{{end}}</tbody></table></div>{{end}}
{{if .NetworkFlows}}<h2>Yönlü ağ akışları</h2><div class="scroll"><table><thead><tr><th>Delil / Protokol</th><th>Kaynak → Hedef</th><th>Paket / Yakalanan / Bildirilen bayt</th><th>İlk / Son</th><th>Paket referansları</th></tr></thead><tbody>{{range .NetworkFlows}}<tr><td>{{.Evidence}} / {{.Protocol}}{{if .Section}}<br>Bölüm {{.Section}} / Arayüz {{.InterfaceID}}{{end}}</td><td>{{endpoint .SourceIP .SourcePort}} → {{endpoint .DestinationIP .DestinationPort}}</td><td>{{.Packets}} / {{.CapturedBytes}} / {{.OriginalBytes}}</td><td>{{stamp .First}}<br>{{stamp .Last}}</td><td>{{range .References}}Paket {{.Packet}}{{if .Section}} / Bölüm {{.Section}} / Arayüz {{.InterfaceID}}{{end}}, byte {{.ByteOffset}}<br>{{end}}{{if .ReferencesTruncated}}Referans listesi sınırlandı.{{end}}</td></tr>{{end}}</tbody></table></div>{{end}}
<h2>Ayrıştırma kapsamı</h2><div class="scroll"><table><thead><tr><th>Delil / Biçim</th><th>Okunan / Olay / Atlanan</th><th>Sınır / Hata</th></tr></thead><tbody>{{range .ParseSummaries}}<tr><td>{{.Evidence}} / {{.Format}}</td><td>{{.Rows}} / {{.Parsed}} / {{.Skipped}}</td><td>{{.Limited}} / {{.HasError}}</td></tr>{{end}}</tbody></table></div>
<h2>Sınırlamalar</h2>{{range .Notes}}<p>{{.}}</p>{{end}}<footer><small>k957 · Paylaşım kopyası · Özgün rapora dönüş eşlemesi içermez.</small></footer></main><script>document.getElementById('search').addEventListener('input',function(){const q=this.value.toLocaleLowerCase();document.querySelectorAll('tbody tr').forEach(r=>{r.hidden=!r.textContent.toLocaleLowerCase().includes(q)})})</script></html>`
