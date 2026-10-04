package core

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/signintech/gopdf"
)

//go:embed fonts/DejaVuSerif.ttf
var reportSerifFont []byte

//go:embed fonts/DejaVuSans-Bold.ttf
var reportBoldFont []byte

type pdfRender struct {
	Pages        int
	GlyphEscapes []string
}

func writePDF(ctx context.Context, path string, rows []documentParagraph) error {
	_, e := writePortfolioPDF(ctx, path, rows, ReportBrief{})
	return e
}
func writePortfolioPDF(ctx context.Context, path string, rows []documentParagraph, brief ReportBrief) (receipt pdfRender, err error) {
	rows = append(append([]documentParagraph(nil), rows...), developerDocumentRows()...)
	var pdf gopdf.GoPdf
	pdf.Start(gopdf.Config{PageSize: *gopdf.PageSizeA4})
	missing := map[rune]bool{}
	option := gopdf.TtfOption{OnGlyphNotFound: func(r rune) { missing[r] = true }}
	for _, font := range []struct {
		name string
		body []byte
	}{{"Report", reportFont}, {"Serif", reportSerifFont}, {"Bold", reportBoldFont}} {
		if e := pdf.AddTTFFontDataWithOption(font.name, font.body, option); e != nil {
			return receipt, e
		}
	}
	// Font omissions are visible code-point escapes, never silently dropped text.
	for _, family := range []string{"Report", "Bold", "Serif"} {
		if e := pdf.SetFont(family, "", 10); e != nil {
			return receipt, e
		}
		for _, row := range rows {
			if e := ctx.Err(); e != nil {
				return receipt, e
			}
			if strings.TrimSpace(row.Text) == "" {
				continue
			}
			if _, e := pdf.MeasureTextWidth(documentText(row.Text)); e != nil {
				return receipt, e
			}
		}
	}
	text := func(value string) string {
		var b strings.Builder
		for _, r := range documentText(value) {
			if missing[r] {
				fmt.Fprintf(&b, "[U+%04X]", r)
			} else {
				b.WriteRune(r)
			}
		}
		return b.String()
	}
	cell := func(x, y, w, h float64, value, family string, size int) error {
		if e := pdf.SetFont(family, "", size); e != nil {
			return e
		}
		pdf.SetXY(x, y)
		return pdf.Cell(&gopdf.Rect{W: w, H: h}, text(value))
	}
	newPage := func() error {
		pdf.AddPage()
		pdf.SetTextColor(31, 43, 44)
		pdf.SetStrokeColor(197, 202, 193)
		pdf.SetLineWidth(.5)
		pdf.Line(44, 58, 551, 58)
		if e := cell(44, 31, 110, 18, "k957", "Bold", 12); e != nil {
			return e
		}
		return cell(330, 33, 221, 15, "FORENSIC EXAMINATION / RECORD", "Report", 8)
	}
	if e := newPage(); e != nil {
		return receipt, e
	}
	pdf.SetTextColor(32, 45, 44)
	if e := cell(44, 115, 507, 48, "Examination", "Serif", 34); e != nil {
		return receipt, e
	}
	if e := cell(44, 156, 507, 48, "record", "Serif", 34); e != nil {
		return receipt, e
	}
	pdf.SetFillColor(155, 104, 46)
	pdf.RectFromUpperLeftWithStyle(44, 215, 62, 3, "F")
	y := float64(258)
	if len(brief.Cover) > 0 {
		for i, m := range brief.Cover {
			x := 44 + float64(i)*127
			pdf.SetTextColor(32, 45, 44)
			if e := cell(x, y, 118, 30, fmt.Sprint(m.Count), "Serif", 25); e != nil {
				return receipt, e
			}
			pdf.SetTextColor(91, 100, 92)
			if e := cell(x, y+35, 118, 18, m.Label, "Report", 8); e != nil {
				return receipt, e
			}
			pdf.SetFillColor(224, 226, 218)
			pdf.RectFromUpperLeftWithStyle(x, y+60, 110, 1, "F")
		}
		y += 100
	}
	section := 0
	major := func(value string) bool {
		for _, prefix := range []string{"Evidence integrity", "Coverage and", "Findings:", "Timeline:", "Memory examination", "Evidence inventory", "Examiner decisions", "Incident overview", "Selected records", "Sharing scope", "Acquisition and", "Interpreted activity", "Network observations", "Offline indicator matches"} {
			if strings.HasPrefix(value, prefix) {
				return true
			}
		}
		return false
	}
	for i, row := range rows {
		if i == 0 {
			continue
		}
		if e := ctx.Err(); e != nil {
			return receipt, e
		}
		size, family, height := 9, "Report", float64(14)
		if row.Heading {
			size, family, height = 11, "Bold", 18
		}
		isMajor := row.Heading && major(row.Text)
		if isMajor {
			section++
			if e := newPage(); e != nil {
				return receipt, e
			}
			y = 93
			pdf.SetTextColor(155, 104, 46)
			if e := cell(44, y, 40, 24, fmt.Sprintf("%02d", section), "Bold", 11); e != nil {
				return receipt, e
			}
			y += 28
		} else if row.Heading {
			y += 8
		}
		if e := pdf.SetFont(family, "", size); e != nil {
			return receipt, e
		}
		for _, paragraph := range strings.Split(strings.ReplaceAll(text(row.Text), "\t", "    "), "\n") {
			if paragraph == "" {
				y += height
				continue
			}
			lines, e := pdf.SplitTextWithWordWrap(paragraph, 507)
			if e != nil {
				return receipt, e
			}
			if row.Heading && y+float64(len(lines))*height+32 > 774 {
				if e = newPage(); e != nil {
					return receipt, e
				}
				y = 90
			}
			for _, line := range lines {
				if y+height > 774 {
					if e = newPage(); e != nil {
						return receipt, e
					}
					y = 90
				}
				pdf.SetTextColor(32, 45, 44)
				if strings.HasPrefix(row.Text, "Reference:") || strings.HasPrefix(row.Text, "Native reference:") {
					pdf.SetTextColor(91, 100, 92)
				}
				if e = cell(44, y, 507, height, line, family, size); e != nil {
					return receipt, e
				}
				y += height
			}
		}
		y += 7
		if row.Heading {
			pdf.SetStrokeColor(218, 220, 212)
			pdf.Line(44, y, 551, y)
			y += 9
		}
	}
	if len(missing) > 0 {
		if e := newPage(); e != nil {
			return receipt, e
		}
		pdf.SetTextColor(32, 45, 44)
		if e := cell(44, 94, 507, 24, "Character rendering record", "Bold", 12); e != nil {
			return receipt, e
		}
		if e := cell(44, 130, 507, 20, "Unsupported glyphs appear as Unicode code points. Original text is retained in JSON/HTML.", "Report", 8); e != nil {
			return receipt, e
		}
		for r := range missing {
			receipt.GlyphEscapes = append(receipt.GlyphEscapes, fmt.Sprintf("U+%04X", r))
		}
		sort.Strings(receipt.GlyphEscapes)
		y = 166
		for _, code := range receipt.GlyphEscapes {
			if y > 774 {
				if e := newPage(); e != nil {
					return receipt, e
				}
				y = 90
			}
			if e := cell(44, y, 507, 16, code, "Report", 9); e != nil {
				return receipt, e
			}
			y += 16
		}
	}
	receipt.Pages = pdf.GetNumberOfPages()
	for page := 1; page <= receipt.Pages; page++ {
		if e := ctx.Err(); e != nil {
			return receipt, e
		}
		if e := pdf.SetPage(page); e != nil {
			return receipt, e
		}
		pdf.SetStrokeColor(197, 202, 193)
		pdf.Line(44, 793, 551, 793)
		pdf.SetTextColor(91, 100, 92)
		if e := cell(44, 803, 405, 15, "DERIVED RECORD / Verify signed evidence and source references", "Report", 7); e != nil {
			return receipt, e
		}
		if e := cell(473, 803, 78, 15, fmt.Sprintf("%03d / %03d", page, receipt.Pages), "Report", 8); e != nil {
			return receipt, e
		}
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return receipt, e
	}
	good := false
	defer func() {
		f.Close()
		if !good {
			os.Remove(path)
		}
	}()
	if e = pdf.Write(f); e != nil {
		return receipt, e
	}
	if e = f.Sync(); e != nil {
		return receipt, e
	}
	if e = f.Close(); e != nil {
		return receipt, e
	}
	good = true
	return receipt, nil
}
func exportDefaultPDF(ctx context.Context, a Analysis, out string) error {
	rows, covers := documentProjection(a)
	rendered, e := writePortfolioPDF(ctx, filepath.Join(out, "report.pdf"), rows, reportBrief(a))
	if e != nil {
		return e
	}
	receipt := DocumentReceipt{Schema: "k957-report-documents/1", EvidenceDigest: a.EvidenceDigest, SourceAnalysisDigest: digestJSON(a), Formats: []string{"pdf"}, Coverage: covers, PDFPages: rendered.Pages, GlyphEscapes: rendered.GlyphEscapes, Note: "PDF is the default derived reading edition. Tables and text have explicit projection limits; full JSON, CSV and disk-backed memory results remain alongside it. Glyph escapes preserve unsupported characters as code points. Source evidence and examiner decisions require independent verification."}
	return WriteJSONNew(filepath.Join(out, "documents.json"), receipt)
}

func boundDocumentRows(rows []documentParagraph) ([]documentParagraph, Coverage) {
	var eligible, emitted int64
	bounded := make([]documentParagraph, 0, len(rows))
	for _, row := range rows {
		row.Text = documentText(row.Text)
		eligible += int64(len(row.Text))
		remaining := min(16384, (1<<20)-int(emitted))
		if remaining <= 0 {
			continue
		}
		if len(row.Text) > remaining {
			end := remaining
			for end > 0 && !utf8.RuneStart(row.Text[end]) {
				end--
			}
			row.Text = row.Text[:end]
		}
		emitted += int64(len(row.Text))
		bounded = append(bounded, row)
	}
	return bounded, coverage("document_text", "bytes", eligible, emitted, 1<<20, true)
}
