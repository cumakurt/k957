package core

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

func sharedDocumentProjection(s SharedReport) ([]documentParagraph, []Coverage) {
	rows := []documentParagraph{{"Masked sharing record", true}, {"Case: " + s.Case + " · host: " + s.Host, false}, {"Sharing ID: " + s.ID + " · created: " + s.Created.UTC().Format(time.RFC3339Nano), false}, {"Derived masked record. This document contains only the sharing projection. Original free text, hashes, rules, signatures and reverse mappings are omitted. Anonymity is not guaranteed.", false}, {"Sharing scope", true}, {fmt.Sprintf("Collection status: %s · source issues: %d · objects: %d · findings: %d", s.CollectionStatus, s.SourceIssueCount, len(s.Items), len(s.Findings)), false}, {"Retained fields: " + strings.Join(s.Policy.Keep, ", "), false}}
	for _, c := range s.Coverage {
		rows = append(rows, documentParagraph{fmt.Sprintf("%s [%s] · %s · eligible=%d emitted=%d omitted=%d total known=%t", c.Stage, c.Unit, c.Status, c.Eligible, c.Emitted, c.Omitted, c.TotalKnown), false})
	}
	rows = append(rows, documentParagraph{"Findings: masked references and decisions", true})
	for _, f := range s.Findings[:min(documentRowLimit, len(s.Findings))] {
		rows = append(rows, documentParagraph{fmt.Sprintf("%s · %s · %s · reference: %s %s line %d · reviewer: %s", f.ID, f.Rule, f.Review, f.Evidence, f.Source, f.Line, f.Reviewer), false})
	}
	rows = append(rows, documentParagraph{"Timeline: masked source references", true})
	for _, e := range s.Timeline[:min(documentRowLimit, len(s.Timeline))] {
		rows = append(rows, documentParagraph{fmt.Sprintf("%s · %s · %s %s line %d offset %d · %s %s", sharedTime(e.Time), e.Type, e.Evidence, e.Source, e.Line, e.ByteOffset, e.SourceIP, e.DestinationIP), false})
	}
	rows = append(rows, documentParagraph{"Evidence inventory", true})
	for _, item := range s.Items[:min(documentRowLimit, len(s.Items))] {
		rows = append(rows, documentParagraph{fmt.Sprintf("%s · %s · %s · %d bytes", item.ID, item.Source, item.Kind, item.Size), false})
	}
	rows = append(rows, documentParagraph{"Examiner decisions", true})
	for _, r := range s.Reviews[:min(documentRowLimit, len(s.Reviews))] {
		rows = append(rows, documentParagraph{fmt.Sprintf("%d · %s · %s · %s · %s", r.Sequence, r.Finding, r.Decision, r.Analyst, sharedTime(r.Created)), false})
	}
	covers := []Coverage{coverage("document_findings", "findings", int64(len(s.Findings)), int64(min(documentRowLimit, len(s.Findings))), documentRowLimit, true), coverage("document_timeline", "events", int64(len(s.Timeline)), int64(min(documentRowLimit, len(s.Timeline))), documentRowLimit, true), coverage("document_inventory", "objects", int64(len(s.Items)), int64(min(documentRowLimit, len(s.Items))), documentRowLimit, true), coverage("document_reviews", "records", int64(len(s.Reviews)), int64(min(documentRowLimit, len(s.Reviews))), documentRowLimit, true)}
	rows, textCoverage := boundDocumentRows(rows)
	covers = append(covers, textCoverage)
	return rows, covers
}
func exportSharedPDF(ctx context.Context, s SharedReport, out string) error {
	rows, covers := sharedDocumentProjection(s)
	a := Analysis{Manifest: Manifest{Items: make([]Item, len(s.Items)), Issues: make([]Issue, s.SourceIssueCount)}, Timeline: make([]Event, len(s.Timeline))}
	for _, f := range s.Findings {
		a.Findings = append(a.Findings, Finding{Review: f.Review})
	}
	rendered, e := writePortfolioPDF(ctx, filepath.Join(out, "report.pdf"), rows, reportBrief(a))
	if e != nil {
		return e
	}
	receipt := DocumentReceipt{Schema: "k957-report-documents/1", SourceAnalysisDigest: digestJSON(s), Formats: []string{"pdf"}, Coverage: covers, PDFPages: rendered.Pages, GlyphEscapes: rendered.GlyphEscapes, Note: "PDF is generated exclusively from shared.json. The digest binds that masked projection, not the original analysis. Source hashes and reverse mappings are absent. Every table preview has explicit coverage; shared.json and CSV retain the full sharing projection."}
	return WriteJSONNew(filepath.Join(out, "documents.json"), receipt)
}
func exportCasePDF(ctx context.Context, d CaseDossier, out string) error {
	rows := []documentParagraph{{"Incident examination record", true}, {"Case dossier: " + d.ID, false}, {"Created: " + d.Created.UTC().Format(time.RFC3339Nano), false}, {"Scope: " + d.Root, false}, {"Derived incident record. Original signed collections remain the evidence. Index rows scope identifiers by collection digest and host; matching names and timestamps do not establish causality.", false}, {"Incident overview", true}, {fmt.Sprintf("Collections=%d verified=%d failed=%d · objects=%d · events=%d · findings=%d · reviews=%d", d.Collections, d.Verified, d.Failed, d.Items, d.Events, d.Findings, d.Reviews), false}, {"Hosts: " + strings.Join(d.Hosts, ", "), false}}
	if len(d.Memories) > 0 {
		rows = append(rows, documentParagraph{"Memory examination", true})
		for _, m := range d.Memories {
			for _, note := range m.Notes {
				rows = append(rows, documentParagraph{note, false})
			}
			rows = append(rows, documentParagraph{fmt.Sprintf("%s · collection=%s · source=%s · bytes=%d · SHA-256=%s", m.Host, m.Digest, m.Source, m.Bytes, m.SHA256), false})
			if m.Results != nil {
				rows = append(rows, documentParagraph{fmt.Sprintf("Full scan: %s · %d records · SHA-256=%s", m.Results.Name, m.Results.Rows, m.Results.SHA256), false})
			}
			if m.Kernel != nil {
				rows = append(rows, documentParagraph{fmt.Sprintf("Kernel methods: %s · %d plugin receipts · %s", m.Kernel.Status, len(m.Kernel.Examinations), m.Kernel.Directory), false})
			} else {
				rows = append(rows, documentParagraph{"Kernel examination not run: supply a trusted executable and matching offline symbols.", false})
			}
		}
	}
	for _, note := range d.Notes {
		rows = append(rows, documentParagraph{note, false})
	}
	rows = append(rows, documentParagraph{"Coverage and limitations", true})
	for _, c := range d.Coverage {
		rows = append(rows, documentParagraph{fmt.Sprintf("%s [%s] · %s · emitted=%d eligible=%d omitted=%d total known=%t", c.Stage, c.Unit, c.Status, c.Emitted, c.Eligible, c.Omitted, c.TotalKnown), false})
	}
	covers := []Coverage{}
	for _, kind := range []string{"finding", "event", "memory_observation", "review"} {
		page, e := QueryCase(ctx, filepath.Join(out, d.Index), CaseQuery{Kind: kind, Limit: 200})
		if e != nil {
			return e
		}
		if len(page.Rows) == 0 {
			continue
		}
		title := map[string]string{"finding": "Findings: incident source references", "event": "Timeline: incident source references", "memory_observation": "Memory examination", "review": "Examiner decisions"}[kind]
		rows = append(rows, documentParagraph{title, true})
		for _, r := range page.Rows {
			rows = append(rows, documentParagraph{fmt.Sprintf("Collection=%s · host=%s · evidence=%s · source=%s · row=%d", r.Digest, r.Host, r.Evidence, r.Source, r.ID), false}, documentParagraph{string(r.Payload), false})
		}
		eligible := int64(len(page.Rows))
		if kind == "finding" {
			eligible = d.Findings
		}
		if kind == "event" {
			eligible = d.Events
		}
		if kind == "review" {
			eligible = d.Reviews
		}
		covers = append(covers, coverage("document_case_"+kind, "rows", eligible, int64(len(page.Rows)), 200, !page.More || kind != "memory_observation"))
	}
	rows, textCoverage := boundDocumentRows(rows)
	covers = append(covers, textCoverage)
	rendered, e := writePortfolioPDF(ctx, filepath.Join(out, "report.pdf"), rows, ReportBrief{})
	if e != nil {
		return e
	}
	return WriteJSONNew(filepath.Join(out, "documents.json"), DocumentReceipt{Schema: "k957-report-documents/1", SourceAnalysisDigest: digestJSON(d), Formats: []string{"pdf"}, Coverage: covers, PDFPages: rendered.Pages, GlyphEscapes: rendered.GlyphEscapes, Note: "Incident reading edition samples up to 200 index rows per kind. The complete case-index.sqlite and examination.csv remain alongside it. Memory sidecars retain complete scans even when the general case index has reached its own documented capacity."})
}

func exportSelectionDocuments(ctx context.Context, s CaseSelection, out string) error {
	rows := []documentParagraph{{"Selected examination record", true}, {s.Title, false}, {"Analyst: " + s.Analyst + " · created: " + s.Created.UTC().Format(time.RFC3339Nano), false}, {"Index SHA-256: " + s.IndexSHA256, false}, {s.Note, false}, {"Selected records", true}}
	for _, r := range s.Page.Rows {
		rows = append(rows, documentParagraph{fmt.Sprintf("Collection=%s · host=%s · evidence=%s · source=%s · index row=%d", r.Digest, r.Host, r.Evidence, r.Source, r.ID), true}, documentParagraph{string(r.Payload), false})
	}
	rows = append(rows, documentParagraph{"Coverage and limitations", true})
	for _, note := range s.Limits {
		rows = append(rows, documentParagraph{note, false})
	}
	rows, textCoverage := boundDocumentRows(rows)
	rendered, e := writePortfolioPDF(ctx, filepath.Join(out, "report.pdf"), rows, ReportBrief{})
	if e != nil {
		return e
	}
	if e = WriteJSONNew(filepath.Join(out, "documents.json"), DocumentReceipt{Schema: "k957-report-documents/1", SourceAnalysisDigest: digestJSON(s), Formats: []string{"pdf"}, Coverage: []Coverage{s.Coverage, textCoverage}, PDFPages: rendered.Pages, GlyphEscapes: rendered.GlyphEscapes, Note: "The reading edition contains this explicit query page only. selection.json retains the full selected payloads; the signed bundle binds the bookmark, PDF and HTML."}); e != nil {
		return e
	}
	return writeSelectionHTML(s, rows, filepath.Join(out, "report.html"))
}
