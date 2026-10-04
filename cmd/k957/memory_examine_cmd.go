package main

import (
	"context"
	"encoding/json"
	"flag"
	"k957/internal/core"
	"os"
	"os/signal"
	"runtime"
)

func runMemoryExamine(args []string) error {
	f := flag.NewFlagSet("memory-examine", flag.ContinueOnError)
	image := f.String("image", "", "raw/LiME memory image")
	out := f.String("out", "", "new external examination directory")
	expected := f.String("sha256", "", "expected acquired image SHA-256")
	tool := f.String("tool", "", "trusted installed Volatility 3 executable")
	symbols := f.String("symbols", "", "offline JSON/compressed symbol directory; no plugin code")
	plugin := f.String("plugin", "all", "all installed platform plugins, or one plugin name")
	platform := f.String("platform", runtime.GOOS, "image platform: linux, windows or mac")
	workDir := f.String("work-dir", "", "private staging directory; defaults to temporary/output filesystem with sufficient free space")
	if stop, e := parseFlags(f, args); stop || e != nil {
		return e
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx = core.WithMemoryExamination(ctx, *tool, *symbols, *workDir)
	if *plugin == "all" {
		result, e := core.ExamineMemorySuite(ctx, *image, *out, *expected, *tool, *symbols, *platform, *workDir)
		if result.Schema != "" {
			if ee := json.NewEncoder(os.Stdout).Encode(result); ee != nil {
				return ee
			}
		}
		return e
	}
	result, e := core.ExamineMemory(ctx, *image, *out, *expected, *tool, *symbols, *plugin)
	if result.Schema != "" {
		if ee := json.NewEncoder(os.Stdout).Encode(result); ee != nil {
			return ee
		}
	}
	return e
}
