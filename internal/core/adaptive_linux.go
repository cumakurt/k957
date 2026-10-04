//go:build linux

package core

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func platformProcessExecutables(ctx context.Context) ([]ExecutableReference, string, error) {
	refs, e := linuxProcessExecutables(ctx, "/proc")
	return refs, "Linux /proc/<pid>/exe readlink and executable /proc/<pid>/maps file mappings", e
}
func linuxProcessExecutables(ctx context.Context, root string) ([]ExecutableReference, error) {
	entries, e := os.ReadDir(root)
	if e != nil {
		return nil, e
	}
	refs := []ExecutableReference{}
	for _, entry := range entries {
		if e = ctx.Err(); e != nil {
			return refs, e
		}
		pid, e := strconv.Atoi(entry.Name())
		if e != nil || pid <= 0 || !entry.IsDir() {
			continue
		}
		ref := ExecutableReference{PID: pid, Status: "observed"}
		ref.Path, e = os.Readlink(filepath.Join(root, entry.Name(), "exe"))
		if e != nil {
			ref.Status, ref.Reason = "unavailable", e.Error()
		}
		if strings.HasSuffix(ref.Path, " (deleted)") {
			ref.Status, ref.Reason = "unavailable", "executable was deleted; retain this path for memory examination"
		}
		refs = append(refs, ref)
		mapped, mapErr := linuxProcessMappings(ctx, root, pid)
		refs = append(refs, mapped...)
		if mapErr != nil {
			if ctx.Err() != nil {
				return refs, ctx.Err()
			}
			refs = append(refs, ExecutableReference{PID: pid, Kind: "executable_mapping", Status: "unavailable", Reason: mapErr.Error()})
		}
	}
	return refs, nil
}
