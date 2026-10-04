package core

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/xml"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeDocumentsReferencesUnicodeAndLimits(t *testing.T) {
	a := Analysis{EvidenceDigest: strings.Repeat("a", 64), Version: Version, Manifest: Manifest{Case: "Café & <case>"}, Findings: []Finding{{ID: "F1", Evidence: "E1", Source: "Café", Description: "Review required", Event: &EventReference{Table: "visits", Record: "7"}}}, Timeline: make([]Event, 501)}
	dir := filepath.Join(t.TempDir(), "docs")
	r, e := ExportDocuments(context.Background(), a, dir, "both")
	if e != nil {
		t.Fatal(e)
	}
	if r.Coverage[1].Omitted != 1 || r.Coverage[1].Status != "partial" {
		t.Fatal("render limit concealed", r)
	}
	z, e := zip.OpenReader(filepath.Join(dir, "report.docx"))
	if e != nil {
		t.Fatal(e)
	}
	defer z.Close()
	found := false
	for _, f := range z.File {
		if f.Name == "word/document.xml" {
			found = true
			reader, e := f.Open()
			if e != nil {
				t.Fatal(e)
			}
			body, e := io.ReadAll(reader)
			reader.Close()
			if e != nil {
				t.Fatal(e)
			}
			d := xml.NewDecoder(bytes.NewReader(body))
			for {
				_, e = d.Token()
				if e == io.EOF {
					break
				}
				if e != nil {
					t.Fatal(e)
				}
			}
			if !bytes.Contains(body, []byte("Café &amp; &lt;case&gt;")) || !bytes.Contains(body, []byte("record=7")) {
				t.Fatal("document lost references or Unicode")
			}
		}
	}
	if !found {
		t.Fatal("missing Word document")
	}
	pdf, e := os.ReadFile(filepath.Join(dir, "report.pdf"))
	if e != nil || !bytes.HasPrefix(pdf, []byte("%PDF-")) || !bytes.Contains(pdf, []byte("/ToUnicode")) {
		t.Fatal("PDF missing Unicode mapping", e)
	}
}

func TestDocumentCancellationDoesNotPublish(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dir := filepath.Join(t.TempDir(), "out")
	if _, e := ExportDocuments(ctx, Analysis{}, dir, "both"); e == nil {
		t.Fatal("cancelled documents published")
	}
	if _, e := os.Stat(dir); !os.IsNotExist(e) {
		t.Fatal("partial document output remains")
	}
}

func TestDocumentTextAndNotesAreBounded(t *testing.T) {
	a := Analysis{Notes: make([]string, 300), Findings: make([]Finding, 500)}
	for i := range a.Notes {
		a.Notes[i] = strings.Repeat("É", 10000)
	}
	for i := range a.Findings {
		a.Findings[i].Description = strings.Repeat("A", 10000)
	}
	rows, c := documentProjection(a)
	var bytes int
	for _, row := range rows {
		bytes += len(row.Text)
	}
	var notesOmitted, textOmitted int64
	for _, coverage := range c {
		switch coverage.Stage {
		case "document_notes":
			notesOmitted = coverage.Omitted
		case "document_text":
			textOmitted = coverage.Omitted
		}
	}
	if bytes > (1<<20)+512 || textOmitted == 0 || notesOmitted != 100 {
		t.Fatalf("document bounds concealed: %d %+v", bytes, c)
	}
}
