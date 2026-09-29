package core

import (
	"context"
	"os"
	"path/filepath"
)

type WorkStatus struct {
	Encrypted     bool    `json:"encrypted"`
	Case          string  `json:"case"`
	Source        string  `json:"source"`
	Files         int     `json:"files"`
	Completed     int     `json:"completed_files"`
	AcquiredBytes int64   `json:"acquired_bytes"`
	PlannedBytes  int64   `json:"planned_bytes"`
	Parts         int     `json:"parts"`
	PartsVerified bool    `json:"parts_verified"`
	LockPresent   bool    `json:"lock_present"`
	Epochs        []Epoch `json:"epochs"`
}

// InspectWork is read-only. A lock can be live or stale; its existence alone
// does not identify whether a collection process is still running.
func InspectWork(ctx context.Context, work string, verify bool, keyPaths ...string) (out WorkStatus, err error) {
	var c *workCrypto
	if len(keyPaths) > 0 {
		c, err = newWorkCrypto(keyPaths[0])
		if err != nil {
			return
		}
	}
	out.Encrypted = c != nil
	if err = regularDirectory(work); err != nil {
		return
	}
	if err = regularDirectory(filepath.Join(work, "chunks")); err != nil {
		return
	}
	var s WorkState
	if err = readWork(work, &s, c); err != nil {
		return
	}
	out.Case = s.Manifest.Case
	out.Source = s.Root
	out.Files = len(s.Files)
	out.Epochs = s.Manifest.Epochs
	_, e := os.Lstat(filepath.Join(work, "active.lock"))
	out.LockPresent = e == nil
	for _, wf := range s.Files {
		if err = ctx.Err(); err != nil {
			return
		}
		out.PlannedBytes += wf.ExpectedSize
		if wf.Complete {
			out.Completed++
		}
		out.Parts += len(wf.Item.Parts)
		for _, p := range wf.Item.Parts {
			out.AcquiredBytes += p.Size
		}
		if verify {
			if err = validateParts(ctx, work, wf.Item, c); err != nil {
				return
			}
		}
	}
	out.PartsVerified = verify
	return
}
