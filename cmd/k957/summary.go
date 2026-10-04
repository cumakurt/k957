package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"k957/internal/core"
)

// writeCollectionSummary prints a grouped operator view. The signed
// collection.json in the output directory remains the full record.
func writeCollectionSummary(w io.Writer, rec core.CollectionRecord) {
	color := supportsANSI(w) && os.Getenv("NO_COLOR") == ""
	section := func(title string) {
		fmt.Fprintln(w)
		fmt.Fprintln(w, tint(color, "1", title))
	}
	row := func(label, value string) {
		fmt.Fprintf(w, "  %s %s\n", tint(color, "2", fmt.Sprintf("%-12s", label)), value)
	}
	section("Collection")
	row("status", tintStatus(color, rec.Status))
	row("host", rec.Host)
	system := rec.OS + "/" + rec.Arch
	if rec.Privileged {
		system += "  privileged"
	}
	row("system", system)
	row("case", rec.Case)
	row("operator", rec.Operator)
	if !rec.Started.IsZero() && !rec.Finished.Before(rec.Started) {
		row("duration", formatDuration(rec.Finished.Sub(rec.Started)))
	}
	section("Output")
	row("directory", rec.Directory)
	row("fingerprint", tint(color, "36", rec.Fingerprint))
	if rec.GeneratedKey {
		row("signing", "private key discarded; record the fingerprint independently")
	}
	section("Acquired")
	if rec.Memory != nil {
		row("memory", fmt.Sprintf("%s  %s  %s", tintStatus(color, rec.Memory.Status), formatBytes(int64(rec.Memory.Bytes)), rec.Memory.Format))
		if rec.Memory.SHA256 != "" {
			row("memory hash", shortID(rec.Memory.SHA256))
		}
	} else {
		row("memory", "not acquired")
	}
	if rec.Evidence != "" {
		row("evidence", evidenceLine(rec))
	}
	row("artifacts", fmt.Sprintf("%d", len(rec.Artifacts)))
	section("Review")
	row("absent", fmt.Sprintf("%d paths were not present", len(rec.Absent)))
	if len(rec.Issues) == 0 {
		row("issues", tint(color, "32", "none"))
	} else {
		row("issues", tint(color, "33", fmt.Sprintf("%d  see collection.json", len(rec.Issues))))
	}
	row("record", filepath.Join(rec.Directory, "collection.json"))
	fmt.Fprintln(w)
}

func writeStoreVerificationSummary(w io.Writer, result core.StoreVerification) {
	color := summaryColor(w)
	section, row, _ := summaryLayout(w, color)
	section("Verification")
	row("root", result.Root)
	row("result", countLine(color, "verified", result.Verified, result.Failed))
	section("Collections")
	writeVerificationList(w, color, result.Collections)
	fmt.Fprintln(w)
}

func writeStoreAnalysisSummary(w io.Writer, result core.StoreAnalysis) {
	color := summaryColor(w)
	section, row, note := summaryLayout(w, color)
	section("Analysis")
	row("root", result.Root)
	row("result", countLine(color, "analyzed", result.Analyzed, result.Failed))
	section("Collections")
	if len(result.Collections) == 0 {
		row("collections", "none")
		fmt.Fprintln(w)
		return
	}
	for _, c := range result.Collections {
		fmt.Fprintf(w, "  %s %s\n", tintStatus(color, fmt.Sprintf("%-12s", c.Status)), c.Directory)
		if c.Status == "failed" {
			for _, msg := range briefErrors(c.Directory, c.Errors) {
				note(msg)
			}
			continue
		}
		note(fmt.Sprintf("findings %d  memory hits %d", c.Findings, c.MemoryHits))
		if c.Report != "" {
			note(filepath.Join(c.Report, "report.html"))
			note(filepath.Join(c.Report, "report.pdf"))
		}
	}
	fmt.Fprintln(w)
}

func writeCaseSummary(w io.Writer, d core.CaseDossier) {
	color := summaryColor(w)
	section, row, _ := summaryLayout(w, color)
	section("Case")
	row("directory", d.Directory)
	if d.Directory != "" {
		row("report", filepath.Join(d.Directory, "report.html"))
		row("pdf", filepath.Join(d.Directory, "report.pdf"))
	}
	row("result", countLine(color, "verified", d.Verified, d.Failed))
	row("items", fmt.Sprintf("%d", d.Items))
	row("duplicates", fmt.Sprintf("%d", len(d.Duplicates)))
	row("hash matches", fmt.Sprintf("%d", len(d.HashMatches)))
	row("mismatches", fmt.Sprintf("%d", len(d.Mismatches)))
	if len(d.Failures) > 0 {
		section("Failures")
		writeVerificationList(w, color, d.Failures)
	}
	fmt.Fprintln(w)
}

func writePackageVerificationSummary(w io.Writer, path, signature, status string, items, issues int) {
	color := summaryColor(w)
	section, row, _ := summaryLayout(w, color)
	section("Package")
	row("path", path)
	row("integrity", tint(color, "32", "verified"))
	row("signature", signature)
	row("status", tintStatus(color, status))
	row("items", fmt.Sprintf("%d", items))
	if issues == 0 {
		row("issues", tint(color, "32", "none"))
	} else {
		row("issues", tint(color, "33", fmt.Sprintf("%d", issues)))
	}
	fmt.Fprintln(w)
}

func writeVerificationList(w io.Writer, color bool, list []core.CollectionVerification) {
	note := func(value string) {
		fmt.Fprintf(w, "  %s %s\n", strings.Repeat(" ", 12), value)
	}
	if len(list) == 0 {
		fmt.Fprintf(w, "  %s %s\n", tint(color, "2", fmt.Sprintf("%-12s", "collections")), "none")
		return
	}
	for _, c := range list {
		fmt.Fprintf(w, "  %s %s\n", tintStatus(color, fmt.Sprintf("%-12s", c.Status)), c.Directory)
		if c.Status != "failed" {
			var bits []string
			if c.CollectionStatus != "" {
				bits = append(bits, c.CollectionStatus)
			}
			if c.Evidence != "" {
				bits = append(bits, c.Evidence)
			}
			if c.Memory != "" {
				bits = append(bits, c.Memory)
			}
			if len(bits) > 0 {
				note(strings.Join(bits, "  "))
			}
		}
		if c.Signature != "" {
			note(signatureLine(c.Signature))
		}
		for _, msg := range briefErrors(c.Directory, c.Errors) {
			note(msg)
		}
	}
}

func emitStoreVerification(result core.StoreVerification) error {
	if isTerminal(os.Stdout) {
		writeStoreVerificationSummary(os.Stderr, result)
		return nil
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}

func emitStoreAnalysis(result core.StoreAnalysis) error {
	if isTerminal(os.Stdout) {
		writeStoreAnalysisSummary(os.Stderr, result)
		return nil
	}
	if e := json.NewEncoder(os.Stdout).Encode(result); e != nil {
		return e
	}
	for _, c := range result.Collections {
		if c.Report != "" {
			fmt.Fprintf(os.Stderr, "Report: %s/report.html\n", c.Report)
		}
	}
	return nil
}

func emitCase(d core.CaseDossier) error {
	if isTerminal(os.Stdout) {
		writeCaseSummary(os.Stderr, d)
		return nil
	}
	fmt.Fprintln(os.Stderr, "Case:", filepath.Join(d.Directory, "report.html"))
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"directory": d.Directory, "collections": d.Collections, "verified": d.Verified,
		"failed": d.Failed, "items": d.Items, "duplicates": len(d.Duplicates),
		"hash_matches": len(d.HashMatches), "mismatches": len(d.Mismatches),
	})
}

func emitPackageVerification(path, signature, status string, items int, issues []core.Issue) error {
	if isTerminal(os.Stdout) {
		writePackageVerificationSummary(os.Stderr, path, signature, status, items, len(issues))
		return nil
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"integrity": "verified", "signature": signature, "collection_status": status,
		"items": items, "issues": issues,
	})
}

func summaryColor(w io.Writer) bool {
	return supportsANSI(w) && os.Getenv("NO_COLOR") == ""
}

func summaryLayout(w io.Writer, color bool) (func(string), func(string, string), func(string)) {
	section := func(title string) {
		fmt.Fprintln(w)
		fmt.Fprintln(w, tint(color, "1", title))
	}
	row := func(label, value string) {
		fmt.Fprintf(w, "  %s %s\n", tint(color, "2", fmt.Sprintf("%-12s", label)), value)
	}
	note := func(value string) {
		fmt.Fprintf(w, "  %s %s\n", strings.Repeat(" ", 12), value)
	}
	return section, row, note
}

func countLine(color bool, okLabel string, ok, bad int) string {
	left := fmt.Sprintf("%d %s", ok, okLabel)
	if ok > 0 {
		left = tint(color, "32", left)
	}
	right := fmt.Sprintf("%d failed", bad)
	if bad > 0 {
		right = tint(color, "31", right)
	}
	return left + "  " + right
}

func signatureLine(sig string) string {
	switch sig {
	case "absent":
		return "signature absent"
	case "invalid", "failed":
		return "signature " + sig
	case "verified against embedded key; not an external trust anchor":
		return "embedded key; not an external trust anchor"
	case "verified against supplied trusted key":
		return "supplied trusted key"
	default:
		return sig
	}
}

func briefErrors(dir string, errs []string) []string {
	if len(errs) == 0 {
		return nil
	}
	const limit = 2
	n := len(errs)
	if n > limit {
		n = limit
	}
	out := make([]string, 0, n+1)
	for _, msg := range errs[:n] {
		if dir != "" {
			msg = strings.ReplaceAll(msg, dir, ".")
		}
		msg = strings.Join(strings.Fields(msg), " ")
		if len(msg) > 120 {
			msg = msg[:117] + "..."
		}
		out = append(out, msg)
	}
	if extra := len(errs) - limit; extra > 0 {
		out = append(out, fmt.Sprintf("%d more errors", extra))
	}
	return out
}

func evidenceLine(rec core.CollectionRecord) string {
	for _, artifact := range rec.Artifacts {
		if artifact.Name == rec.Evidence {
			return formatBytes(artifact.Size) + "  " + artifact.Name
		}
	}
	return rec.Evidence
}

func shortID(id string) string {
	if len(id) <= 16 {
		return id
	}
	return id[:16] + "..."
}

func tint(enabled bool, code, text string) string {
	if !enabled || text == "" {
		return text
	}
	return "\x1b[" + code + "m" + text + "\x1b[0m"
}

func tintStatus(enabled bool, status string) string {
	switch status {
	case "complete", "verified", "analyzed":
		return tint(enabled, "32", status)
	case "partial":
		return tint(enabled, "33", status)
	case "failed":
		return tint(enabled, "31", status)
	default:
		return status
	}
}
