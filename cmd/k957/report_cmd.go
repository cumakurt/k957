package main

import (
	"context"
	"encoding/json"
	"flag"
	"k957/internal/core"
	"os"
	"os/signal"
)

func runReportCommand(command string, args []string) error {
	f := flag.NewFlagSet(command, flag.ContinueOnError)
	dir := f.String("report", "", "report directory")
	key := f.String("key", "", "Ed25519 report signing key (report-seal)")
	trusted := f.String("trusted-key", "", "external trusted report public key (report-verify)")
	analysis := f.String("analysis", "", "derived analysis JSON for report-documents")
	out := f.String("out", "", "new document directory")
	format := f.String("format", "both", "pdf, docx or both")
	if stop, e := parseFlags(f, args); stop || e != nil {
		return e
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if command == "report-documents" {
		a, e := core.LoadAnalysis(*analysis)
		if e != nil {
			return e
		}
		receipt, e := core.ExportDocuments(ctx, a, *out, *format)
		if e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(receipt)
	}
	if command == "report-seal" {
		seal, e := core.SealReport(ctx, *dir, *key)
		if e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(seal)
	}
	status, e := core.VerifyReport(ctx, *dir, *trusted)
	if e != nil {
		return e
	}
	return json.NewEncoder(os.Stdout).Encode(status)
}
