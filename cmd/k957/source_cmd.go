package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"k957/internal/core"
	"os"
	"os/signal"
)

func runSourceImport(args []string) error {
	f := flag.NewFlagSet("source-import", flag.ContinueOnError)
	kind := f.String("kind", "cloudtrail", "authorized offline export kind")
	source := f.String("in", "", "directory containing only selected JSON/JSON.gz exports")
	var opts core.Options
	f.StringVar(&opts.Out, "out", "", "new evidence package")
	f.StringVar(&opts.Case, "case", "", "case identifier")
	f.StringVar(&opts.Operator, "operator", "", "examiner")
	f.StringVar(&opts.Scope, "scope", "", "authorized exported scope")
	f.StringVar(&opts.SignKey, "sign-key", "", "optional package signer")
	if stop, err := parseFlags(f, args); stop || err != nil {
		return err
	}
	if *kind != "cloudtrail" {
		return fmt.Errorf("supported offline source kind: cloudtrail")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	m, err := core.ImportCloudTrail(ctx, *source, opts)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(m)
}
