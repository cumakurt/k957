package main

import (
	"context"
	"encoding/json"
	"flag"
	"k957/internal/core"
	"os"
	"os/signal"
	"time"
)

func runTemporal(args []string) error {
	f := flag.NewFlagSet("case-correlate", flag.ContinueOnError)
	dir := f.String("case", "", "derived case directory")
	field := f.String("field", "user", "user, host, source_ip or destination_ip")
	window := f.Duration("window", 5*time.Minute, "candidate time window, at most 24h")
	policy := f.String("policy", "", "clock and explicit identity estimates JSON")
	out := f.String("out", "", "new derived result JSON; default stdout")
	if stop, e := parseFlags(f, args); stop || e != nil {
		return e
	}
	p, e := core.LoadTemporalPolicy(*policy)
	if e != nil {
		return e
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	result, e := core.CorrelateCase(ctx, *dir, *field, *window, p)
	if e != nil {
		return e
	}
	if *out != "" {
		return core.WriteJSONNew(*out, result)
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}
