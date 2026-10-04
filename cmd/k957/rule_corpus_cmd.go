package main

import (
	"context"
	"encoding/json"
	"flag"
	"k957/internal/core"
	"os"
	"os/signal"
)

func runRuleCorpus(args []string) error {
	f := flag.NewFlagSet("rules-evaluate", flag.ContinueOnError)
	rules := f.String("rules", "", "structured rules JSON")
	corpus := f.String("corpus", "", "labelled event corpus JSON")
	out := f.String("out", "", "new evaluation JSON; default stdout")
	if stop, err := parseFlags(f, args); stop || err != nil {
		return err
	}
	pack, err := core.LoadRules(*rules)
	if err != nil {
		return err
	}
	labels, err := core.LoadRuleCorpus(*corpus)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	result, err := core.EvaluateRuleCorpus(ctx, pack, labels)
	if err != nil {
		return err
	}
	if *out != "" {
		return core.WriteJSONNew(*out, result)
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}
