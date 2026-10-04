package main

import (
	"context"
	"encoding/json"
	"flag"
	"k957/internal/core"
	"os"
	"os/signal"
)

func runDisk(command string, args []string) error {
	f := flag.NewFlagSet(command, flag.ContinueOnError)
	image := f.String("image", "", "raw disk/filesystem image")
	out := f.String("out", "", "new examination/recovery directory")
	expected := f.String("sha256", "", "expected image digest; required for recovery")
	tool := f.String("tool", "", "examiner-selected fls/icat executable")
	inode := f.String("inode", "", "image-scoped inode reference (disk-recover)")
	offset := f.Int64("offset", 0, "filesystem offset in sectors")
	sector := f.Int64("sector-size", 512, "sector bytes, 512..4096 power of two")
	if stop, e := parseFlags(f, args); stop || e != nil {
		return e
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if command == "disk-examine" {
		result, e := core.ExamineDisk(ctx, *image, *out, *expected, *tool, *offset, *sector)
		if e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(result)
	}
	result, e := core.RecoverDiskEntry(ctx, *image, *out, *expected, *tool, *inode, *offset, *sector)
	if e != nil {
		return e
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}
