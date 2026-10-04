package core

import (
	"archive/zip"
	"bytes"
	"context"
	_ "embed"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
)

//go:embed fonts/DejaVuSans.ttf
var reportFont []byte

const documentRowLimit = 500

type documentParagraph struct {
	Text    string
	Heading bool
}
type DocumentReceipt struct {
	PDFPages             int        `json:"pdf_pages,omitempty"`
	GlyphEscapes         []string   `json:"glyph_escapes,omitempty"`
	Schema               string     `json:"schema"`
	EvidenceDigest       string     `json:"evidence_digest"`
	SourceAnalysisDigest string     `json:"source_analysis_digest"`
	Formats              []string   `json:"formats"`
	Coverage             []Coverage `json:"coverage"`
	Note                 string     `json:"note"`
}

func documentText(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return '\uFFFD'
		}
		if r == 0xfffe || r == 0xffff {
			return '\uFFFD'
		}
		return r
	}, s)
}

func documentProjection(a Analysis) ([]documentParagraph, []Coverage) {
	usnGroups := usnFileGroups(a.Timeline)
	rows := []documentParagraph{{"k957 examination report", true}, {"Case: " + a.Manifest.Case + " · host: " + a.Manifest.Host, false}, {"Evidence SHA-256: " + a.EvidenceDigest, false}, {"Analysis run: " + a.Run + " · created: " + a.Created.UTC().Format(time.RFC3339Nano), false}, {"Derived examination document. Verify the original signed evidence and each referenced object before adopting a conclusion. Literal/structured matches require analyst review; timestamps and common identifiers do not establish causality or attribution.", false}, {"Evidence integrity and acquisition", true}, {"Signature: " + a.Signature + " · collection status: " + a.CollectionStatus + " · manifest status: " + a.Manifest.Status, false}}
	if a.Manifest.Acquisition != nil {
		rows = append(rows, documentParagraph{"Acquisition method: " + a.Manifest.Acquisition.Method + " · origin: " + a.Manifest.Acquisition.Origin, false})
	}
	if a.Adaptive != nil {
		s := a.Adaptive
		rows = append(rows, documentParagraph{fmt.Sprintf("Adaptive executable collection: processes=%d selected paths=%d collected paths=%d unavailable processes=%d mapped-file references=%d unavailable mapping references=%d. The signed %s artifact in the original collection binds process, Linux executable mapping and Windows loaded module references to later acquired object hashes; this is not an atomic process snapshot.", s.Processes, s.Selected, s.Collected, s.Unavailable, s.MappedFiles, s.MappingIssues, s.Record), false})
	}
	issues := append(append([]Issue(nil), a.CollectionIssues[:min(len(a.CollectionIssues), 200)]...), a.Manifest.Issues[:min(len(a.Manifest.Issues), 200)]...)
	for _, issue := range issues {
		rows = append(rows, documentParagraph{"Issue: " + issue.Source + " — " + issue.Reason, false})
	}
	if len(a.Memories) > 0 {
		rows = append(rows, documentParagraph{"Memory examination", true})
		for _, m := range a.Memories {
			rows = append(rows, documentParagraph{fmt.Sprintf("%s · %s · %s · bytes=%d · SHA-256=%s", m.Evidence, m.Source, m.Format, m.Bytes, m.SHA256), false})
			if m.Results != nil {
				rows = append(rows, documentParagraph{fmt.Sprintf("Complete results: %s · rows=%d · hits=%d · observations=%d · URLs=%d · SHA-256=%s. Visual rows are previews.", m.Results.Name, m.Results.Rows, m.Results.Hits, m.Results.Observations, m.Results.URLs, m.Results.SHA256), false})
			}
			if m.Kernel != nil {
				rows = append(rows, documentParagraph{fmt.Sprintf("Kernel examination: %s · %d plugin receipts · offline symbol digest=%s", m.Kernel.Status, len(m.Kernel.Examinations), m.Kernel.SymbolsDigest), false})
				for _, run := range m.Kernel.Examinations {
					rows = append(rows, documentParagraph{run.Plugin + " · " + run.Status + " · rows=" + fmt.Sprint(run.Rows) + " · " + run.Error, false})
				}
				for _, name := range m.Kernel.Unavailable {
					rows = append(rows, documentParagraph{"Unavailable installed plugin module: " + name + ". Inspect discovery output and install its required dependencies in the trusted examiner environment.", false})
				}
			}
			for _, note := range m.Notes {
				rows = append(rows, documentParagraph{note, false})
			}
			for _, o := range m.Observations[:min(30, len(m.Observations))] {
				rows = append(rows, documentParagraph{fmt.Sprintf("%s at %#x · %s", o.Kind, o.Physical, o.Detail), false})
			}
		}
	}
	rows = append(rows, documentParagraph{"Coverage and limitations", true})
	allCoverage := analysisCoverage(a)
	for _, c := range allCoverage[:min(len(allCoverage), 200)] {
		rows = append(rows, documentParagraph{fmt.Sprintf("%s %s [%s]: emitted=%d, eligible observed=%d, omitted lower bound=%d, total known=%t, status=%s", c.Stage, c.Format, c.Unit, c.Emitted, c.Eligible, c.Omitted, c.TotalKnown, c.Status), false})
	}
	for _, note := range a.Notes[:min(len(a.Notes), 200)] {
		rows = append(rows, documentParagraph{note, false})
	}
	if a.Indicators != nil {
		rows = append(rows, documentParagraph{"Offline indicator matches", true}, documentParagraph{fmt.Sprintf("%s · source=%s · list SHA-256=%s · indicators=%d matches=%d", a.Indicators.Name, a.Indicators.Source, a.Indicators.SHA256, a.Indicators.Entries, len(a.Indicators.Matches)), false}, documentParagraph{"Exact matches observe supplied indicator values in supported fields and hashes. They are not provider verification, a malware verdict or analyst confirmation.", false})
		for _, m := range a.Indicators.Matches[:min(documentRowLimit, len(a.Indicators.Matches))] {
			rows = append(rows, documentParagraph{fmt.Sprintf("%s · %s=%s · evidence=%s source=%s · %s", m.Indicator, m.Kind, m.Value, m.Evidence, m.Source, m.Basis), false})
		}
	}
	rows = append(rows, usnGroupParagraphs(usnGroups)...)
	rows = append(rows, documentParagraph{fmt.Sprintf("Findings: %d total; first %d shown", len(a.Findings), min(len(a.Findings), documentRowLimit)), true})
	for _, f := range a.Findings[:min(len(a.Findings), documentRowLimit)] {
		rows = append(rows, documentParagraph{f.ID + " · " + f.Rule + " · review: " + f.Review, true}, documentParagraph{f.Description, false}, documentParagraph{fmt.Sprintf("Reference: evidence=%s source=%s line=%d", f.Evidence, f.Source, f.Line), false})
		if f.Event != nil {
			rows = append(rows, documentParagraph{fmt.Sprintf("Event: %s UTC=%s byte_offset=%d packet=%d table=%s record=%s Windows record=%s", f.Event.Type, f.Event.Time.UTC().Format(time.RFC3339Nano), f.Event.ByteOffset, f.Event.Packet, f.Event.Table, f.Event.Record, f.Event.WindowsRecord), false})
		}
		if f.Excerpt != "" {
			rows = append(rows, documentParagraph{"Excerpt: " + f.Excerpt, false})
		}
		if f.Reviewer != "" {
			rows = append(rows, documentParagraph{"Analyst: " + f.Reviewer + " · reason: " + f.ReviewNote, false})
		}
	}
	rows = append(rows, documentParagraph{fmt.Sprintf("Timeline: %d total; first %d shown", len(a.Timeline), min(len(a.Timeline), documentRowLimit)), true})
	for _, ev := range a.Timeline[:min(len(a.Timeline), documentRowLimit)] {
		rows = append(rows, documentParagraph{fmt.Sprintf("%s %s · evidence=%s source=%s line=%d offset=%d packet=%d · raw time=%s · %s", ev.Time.UTC().Format(time.RFC3339Nano), ev.Type, ev.Evidence, ev.Source, ev.Line, ev.ByteOffset, ev.Packet, ev.OriginalTime, ev.Detail), false})
		if ev.Native != nil {
			rows = append(rows, documentParagraph{fmt.Sprintf("Native reference: parser=%s table=%s record=%s time field=%s encoding=%s", ev.Native.Parser, ev.Native.Table, ev.Native.Record, ev.Native.TimeField, ev.Native.TimeEncoding), false})
		}
		if ev.USN != nil {
			rows = append(rows, documentParagraph{fmt.Sprintf("USN %s: file ID (raw LE hex)=%s parent ID=%s reason mask=0x%08x source flags=0x%08x. A journal filename is not a resolved full path; changes may be accumulated in one record.", ev.USN.USN, ev.USN.FileID, ev.USN.ParentID, ev.USN.Reason, ev.USN.SourceInfo), false})
		}
	}
	if len(a.ActivityCounts) > 0 {
		rows = append(rows, documentParagraph{"Interpreted activity", true})
		for _, v := range a.ActivityCounts {
			rows = append(rows, documentParagraph{fmt.Sprintf("%s · %s · %d rows", v.Platform, v.Action, v.Count), false})
		}
	}
	if len(a.ReviewHistory) > 0 {
		rows = append(rows, documentParagraph{"Examiner decisions", true})
		for _, review := range a.ReviewHistory[:min(documentRowLimit, len(a.ReviewHistory))] {
			rows = append(rows, documentParagraph{fmt.Sprintf("%s · finding=%s · %s · analyst=%s · %s", review.Created.UTC().Format(time.RFC3339Nano), review.Finding, review.Decision, review.Analyst, review.Note), false})
		}
	}
	rows = append(rows, documentParagraph{"Evidence inventory", true})
	for _, item := range a.Manifest.Items[:min(documentRowLimit, len(a.Manifest.Items))] {
		rows = append(rows, documentParagraph{fmt.Sprintf("%s · %s · %d bytes · SHA-256=%s", item.ID, item.Source, item.Size, item.SHA256), false})
	}
	rows, textCoverage := boundDocumentRows(rows)

	coverageRows := []Coverage{coverage("document_findings", "findings", int64(len(a.Findings)), int64(min(len(a.Findings), documentRowLimit)), documentRowLimit, true), coverage("document_timeline", "events", int64(len(a.Timeline)), int64(min(len(a.Timeline), documentRowLimit)), documentRowLimit, true)}
	coverageRows = append(coverageRows, usnGroupDocumentCoverage(usnGroups)...)
	coverageRows = append(coverageRows,
		coverage("document_issues", "issues", int64(len(a.CollectionIssues)+len(a.Manifest.Issues)), int64(len(issues)), 400, true),
		coverage("document_notes", "notes", int64(len(a.Notes)), int64(min(len(a.Notes), 200)), 200, true),
		coverage("document_coverage", "rows", int64(len(allCoverage)), int64(min(len(allCoverage), 200)), 200, true),
		coverage("document_inventory", "objects", int64(len(a.Manifest.Items)), int64(min(documentRowLimit, len(a.Manifest.Items))), documentRowLimit, true),
		coverage("document_indicator_matches", "matches", int64(indicatorMatchCount(a)), int64(min(documentRowLimit, indicatorMatchCount(a))), documentRowLimit, true),
		coverage("document_reviews", "records", int64(len(a.ReviewHistory)), int64(min(documentRowLimit, len(a.ReviewHistory))), documentRowLimit, true),
		textCoverage)
	for _, m := range a.Memories {
		eligible := int64(len(m.Observations))
		if m.Results != nil {
			eligible = m.Results.Observations
		}
		coverageRows = append(coverageRows, coverage("document_memory_observations", "observations", eligible, int64(min(30, len(m.Observations))), 30, true))
	}
	if textCoverage.Omitted > 0 {
		rows = append(rows, documentParagraph{"Document text was truncated by paragraph/aggregate limits. Full analysis.json remains the source projection; documents.json records omissions.", false})
	}
	return rows, coverageRows
}

func writeDOCX(ctx context.Context, path string, rows []documentParagraph) error {
	rows = append(append([]documentParagraph(nil), rows...), developerDocumentRows()...)
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	z := zip.NewWriter(f)
	parts := [][2]string{
		{"[Content_Types].xml", `<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>`},
		{"_rels/.rels", `<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>`},
	}
	for _, part := range parts {
		w, err := z.Create(part[0])
		if err != nil {
			z.Close()
			f.Close()
			return err
		}
		if _, err = io.WriteString(w, part[1]); err != nil {
			z.Close()
			f.Close()
			return err
		}
	}
	w, e := z.Create("word/document.xml")
	if e != nil {
		z.Close()
		f.Close()
		return e
	}
	if _, e = io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>`); e != nil {
		z.Close()
		f.Close()
		return e
	}
	for _, p := range rows {
		if e = ctx.Err(); e != nil {
			break
		}
		var escaped bytes.Buffer
		if e = xml.EscapeText(&escaped, []byte(p.Text)); e != nil {
			break
		}
		format := `<w:p><w:r>`
		if p.Heading {
			format = `<w:p><w:pPr><w:keepNext/></w:pPr><w:r><w:rPr><w:b/><w:sz w:val="28"/></w:rPr>`
		}
		_, e = io.WriteString(w, format+`<w:t xml:space="preserve">`+escaped.String()+`</w:t></w:r></w:p>`)
		if e != nil {
			break
		}
	}
	if e == nil {
		_, e = io.WriteString(w, `<w:sectPr><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1134" w:right="1134" w:bottom="1134" w:left="1134"/></w:sectPr></w:body></w:document>`)
	}
	closeZip := z.Close()
	closeFile := f.Close()
	if e != nil {
		return e
	}
	if closeZip != nil {
		return closeZip
	}
	return closeFile
}

func ExportDocuments(ctx context.Context, a Analysis, out, format string) (receipt DocumentReceipt, err error) {
	if format != "both" && format != "pdf" && format != "docx" {
		return receipt, errors.New("document format must be both, pdf or docx")
	}
	if e := os.Mkdir(out, 0700); e != nil {
		return receipt, e
	}
	ok := false
	defer func() {
		if !ok {
			os.RemoveAll(out)
		}
	}()
	rows, covers := documentProjection(a)
	if format == "both" || format == "docx" {
		if e := writeDOCX(ctx, filepath.Join(out, "report.docx"), rows); e != nil {
			return receipt, e
		}
		receipt.Formats = append(receipt.Formats, "docx")
	}
	if format == "both" || format == "pdf" {
		rendered, e := writePortfolioPDF(ctx, filepath.Join(out, "report.pdf"), rows, reportBrief(a))
		if e != nil {
			return receipt, e
		}
		receipt.PDFPages = rendered.Pages
		receipt.GlyphEscapes = rendered.GlyphEscapes
		receipt.Formats = append(receipt.Formats, "pdf")
	}
	if e := ctx.Err(); e != nil {
		return receipt, e
	}
	if e := WriteJSONNew(filepath.Join(out, "analysis.json"), a); e != nil {
		return receipt, e
	}
	receipt.Schema = "k957-report-documents/1"
	receipt.EvidenceDigest = a.EvidenceDigest
	receipt.SourceAnalysisDigest = digestJSON(a)
	receipt.Coverage = covers
	receipt.Note = "PDF/DOCX are derived examination documents. Each finding and timeline row retains evidence references. Sections are capped at 500 findings/events; analysis.json retains the complete input projection. The input analysis is an examiner assertion; source evidence must be verified separately. No PDF/A or accessibility conformance is asserted."
	if e := WriteJSONNew(filepath.Join(out, "documents.json"), receipt); e != nil {
		return receipt, e
	}
	ok = true
	return receipt, nil
}
