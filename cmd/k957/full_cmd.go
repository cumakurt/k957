package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"k957/internal/core"
	"os"
	"os/signal"
	"time"
)

func runFullCollect(args []string) error {
	f := flag.NewFlagSet("collect", flag.ContinueOnError)
	var o core.FullOptions
	var toolArgs stringList
	f.Bool("full", true, "collect memory, live system state and the OS artifact profile")
	f.StringVar(&o.OutputDir, "output-dir", "output", "collection root; host and timestamp directories are created inside it")
	f.StringVar(&o.Root, "root", "", "additional directory to collect")
	f.StringVar(&o.Case, "case", "", "case identifier; default AUTO-<host>-<timestamp>")
	f.StringVar(&o.Operator, "operator", "", "operator; default is the current user")
	f.StringVar(&o.Scope, "scope", "", "scope; default describes a full triage of this host")
	f.StringVar(&o.SignKey, "sign-key", "", "Ed25519 private key; omit to generate and discard a per-run key")
	f.BoolVar(&o.System, "system", true, "collect live system snapshots")
	f.BoolVar(&o.Artifacts, "artifacts", true, "collect the built-in OS artifact profile")
	f.BoolVar(&o.Memory, "memory", true, "acquire a physical memory image")
	f.StringVar(&o.MemoryTool, "memory-tool", "", "external acquisition tool; {output} is required in --memory-tool-arg")
	f.Var(&toolArgs, "memory-tool-arg", "one argument for --memory-tool; repeat the flag and include {output}")
	f.Int64Var(&o.MemoryLimit, "memory-limit", 0, "maximum stored physical bytes; 0 means the mapped RAM")
	f.Int64Var(&o.Reserve, "reserve", 256<<20, "free-space reserve kept on the destination filesystem")
	f.Int64Var(&o.MaxFile, "max-file", 256<<20, "maximum bytes per source file")
	f.Int64Var(&o.MaxTotal, "max-total", 8<<30, "maximum acquired filesystem bytes")
	f.IntVar(&o.MaxFiles, "max-files", 100000, "maximum source file count")
	timeout := f.Duration("timeout", 4*time.Hour, "collection deadline")
	if stop, e := parseFlags(f, args); stop || e != nil {
		return e
	}
	o.MemoryArgs = toolArgs
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	phases := []progressPhase{{ID: "prepare", Weight: 1}}
	if o.Memory {
		phases = append(phases, progressPhase{ID: "memory", Weight: 6})
	}
	if o.System {
		phases = append(phases, progressPhase{ID: "live-system", Weight: 2})
	}
	if o.Artifacts || o.Root != "" {
		phases = append(phases, progressPhase{ID: "files", Weight: 4})
	}
	if o.System || o.Artifacts || o.Root != "" {
		phases = append(phases, progressPhase{ID: "package", Weight: 1})
	}
	phases = append(phases, progressPhase{ID: "seal", Weight: 1})
	ctx, progress := attachProgress(ctx, "collect", phases)
	defer progress.finish()
	rec, e := core.CollectFull(ctx, o)
	if rec.Directory != "" {
		progress.done()
		if e := emitCollection(rec); e != nil {
			return e
		}
	}
	if e != nil {
		return e
	}
	if rec.Status != "complete" {
		return fmt.Errorf("partial collection saved at %s; review collection.json", rec.Directory)
	}
	return nil
}

// emitCollection shows a grouped summary on a terminal. Piped stdout still
// receives the record JSON; the signed file is collection.json either way.
func emitCollection(rec core.CollectionRecord) error {
	if isTerminal(os.Stdout) {
		writeCollectionSummary(os.Stderr, rec)
		return nil
	}
	fmt.Fprintf(os.Stderr, "collection: %s\nsigning fingerprint: %s\n", rec.Directory, rec.Fingerprint)
	if rec.GeneratedKey {
		fmt.Fprintln(os.Stderr, "private signing key was discarded; record the fingerprint independently")
	}
	return json.NewEncoder(os.Stdout).Encode(rec)
}
