//go:build darwin

package core

import (
	"os"
	"path/filepath"
)

func artifactCandidates() []string {
	var homes []string
	if entries, e := os.ReadDir("/Users"); e == nil {
		for _, entry := range entries {
			if entry.IsDir() && entry.Name() != "Shared" {
				homes = append(homes, filepath.Join("/Users", entry.Name()))
			}
		}
	}
	return append(darwinArtifactPaths(homes), discoverBrowserHistories(homes, "darwin")...)
}
