package core

import (
	"strings"
	"testing"
)

func TestCoverageUnknownTotalsAndSafeSharing(t *testing.T) {
	a := Analysis{FindingsTruncated: true, ParseSummaries: []ParseSummary{
		{Format: "JSONL", Rows: 12, Parsed: 10, Skipped: 2, Limited: true},
		{Format: "private-stage-name", Error: "sensitive failure"},
	}}
	rows := analysisCoverage(a)
	var parser, findings bool
	for _, c := range rows {
		if c.Format == "JSONL" {
			parser = true
			if c.TotalKnown || c.Omitted != 2 || c.Emitted != 10 || c.Status != "partial" {
				t.Fatalf("incorrect parser coverage: %+v", c)
			}
		}
		if c.Stage == "findings" {
			findings = true
			if c.TotalKnown || c.Status != "partial" {
				t.Fatalf("truncated findings claimed an exact total: %+v", c)
			}
		}
	}
	if !parser || !findings {
		t.Fatal("required coverage rows are absent")
	}
	shared := string(JSON(sharedCoverage(rows)))
	if strings.Contains(shared, "private-stage-name") || strings.Contains(shared, "sensitive failure") {
		t.Fatal("coverage leaked unapproved text")
	}
}

func TestCoverageKnownBoundary(t *testing.T) {
	for _, n := range []int64{1999, 2000, 2001} {
		c := coverage("duplicates", "groups", n, min(n, 2000), 2000, true)
		if c.Omitted != max(n-2000, 0) || !c.TotalKnown {
			t.Fatalf("incorrect boundary count: %+v", c)
		}
		if (c.Status == "partial") != (n > 2000) {
			t.Fatalf("incorrect boundary status: %+v", c)
		}
	}
}
