//go:build darwin

package core

import (
	"context"
	"path/filepath"
	"strconv"
	"strings"
)

func platformProcessExecutables(ctx context.Context) ([]ExecutableReference, string, error) {
	method := "macOS ps -axo pid=,comm= (absolute command paths only)"
	b, _, e := snapshot(ctx, source{Name: "adaptive-executables", Command: "ps", Args: []string{"-axo", "pid=,comm="}})
	if e != nil {
		return nil, method, e
	}
	refs := []ExecutableReference{}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		pidText, path, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		pid, e := strconv.Atoi(pidText)
		if e != nil {
			continue
		}
		ref := ExecutableReference{PID: pid, Path: strings.TrimSpace(path), Status: "observed"}
		if !filepath.IsAbs(ref.Path) {
			ref.Status, ref.Reason = "unavailable", "ps did not provide an absolute executable path"
		}
		refs = append(refs, ref)
	}
	return refs, method, nil
}
