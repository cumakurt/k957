package main

import (
	"context"
	"encoding/json"
	"flag"
	"k957/internal/core"
	"os"
	"os/signal"
)

func runAssistant(command string, args []string) error {
	f := flag.NewFlagSet(command, flag.ContinueOnError)
	dir := f.String("case", "", "derived case directory")
	out := f.String("out", "", "new assistant JSON, or signed review directory")
	if command == "assistant-review" {
		input := f.String("in", "", "assistant JSON proposal")
		analyst := f.String("analyst", "", "examiner identifier")
		decision := f.String("decision", "", "accept or reject proposal")
		note := f.String("note", "", "required review reason")
		key := f.String("sign-key", "", "Ed25519 review signer")
		if stop, err := parseFlags(f, args); stop || err != nil {
			return err
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		return core.ReviewAssistant(ctx, *input, *dir, *out, *analyst, *decision, *note, *key)
	}
	endpoint := f.String("endpoint", "http://127.0.0.1:11434", "explicit loopback Ollama runtime")
	model := f.String("model", "", "already cached local model tag, including :tag")
	digest := f.String("model-digest", "", "optional required cached model digest")
	question := f.String("question", "", "bounded examiner question")
	var query core.CaseQuery
	f.StringVar(&query.Text, "text", "", "literal retrieval filter, independent of question")
	f.StringVar(&query.Kind, "kind", "event", "event, finding, activity or other indexed kind")
	f.StringVar(&query.Digest, "digest", "", "scope retrieval to exact collection digest")
	f.StringVar(&query.Evidence, "evidence", "", "scope retrieval to evidence ID")
	f.IntVar(&query.Limit, "limit", 20, "selected source rows, 1..20")
	f.IntVar(&query.Offset, "offset", 0, "selected query page offset")
	if stop, err := parseFlags(f, args); stop || err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	result, err := core.AskCaseAssistant(ctx, *dir, *endpoint, *model, *digest, *question, query)
	if err != nil {
		return err
	}
	if *out != "" {
		return core.WriteJSONNew(*out, result)
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}
