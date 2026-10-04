//go:build windows

package core

import (
	"os"
	"path/filepath"
)

func artifactCandidates() []string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	var homes []string
	if dir := os.Getenv("USERPROFILE"); dir != "" {
		homes = append(homes, dir)
	}
	if dir := os.Getenv("PUBLIC"); dir != "" {
		homes = append(homes, dir)
	}
	drive := os.Getenv("SystemDrive")
	if drive == "" {
		drive = `C:`
	}
	if entries, e := os.ReadDir(filepath.Join(drive, "Users")); e == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				homes = append(homes, filepath.Join(drive, "Users", entry.Name()))
			}
		}
	}
	homes = uniqueStrings(homes)
	return append(windowsArtifactPaths(root, homes), discoverBrowserHistories(homes, "windows")...)
}
