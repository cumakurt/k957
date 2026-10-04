package main

import (
	"context"
	"encoding/json"
	"flag"
	"k957/internal/core"
	"os"
	"os/signal"
)

func runSQLiteAcquire(args []string) error {
	f := flag.NewFlagSet("sqlite-acquire", flag.ContinueOnError)
	source := f.String("in", "", "live SQLite main file; original/WAL bytes are not substituted")
	var opts core.Options
	f.StringVar(&opts.Out, "out", "", "new evidence package of a logical backup and provenance")
	f.StringVar(&opts.Case, "case", "", "case identifier")
	f.StringVar(&opts.Operator, "operator", "", "examiner")
	f.StringVar(&opts.Scope, "scope", "", "authorized source scope")
	f.StringVar(&opts.SignKey, "sign-key", "", "optional package signing key")
	if stop, e := parseFlags(f, args); stop || e != nil {
		return e
	}
	exe, e := os.Executable()
	if e != nil {
		return e
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	m, e := core.AcquireSQLite(ctx, *source, exe, opts)
	if e != nil {
		return e
	}
	return json.NewEncoder(os.Stdout).Encode(m)
}
