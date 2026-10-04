//go:build linux

package core

import (
	"os"
	"path/filepath"
)

// profileHome is the directory whose user homes are added to the artifact
// profile. Tests point it at a fixture.
var profileHome = "/home"

// artifactCandidates is the Linux full-mode profile: logs, persistence,
// account names, package metadata and per-user shell histories.
// Password hashes and private keys are intentionally absent.
func artifactCandidates() []string {
	var users []string
	homes, e := os.ReadDir(profileHome)
	if e == nil {
		for _, home := range homes {
			if home.IsDir() {
				users = append(users, home.Name())
			}
		}
	}
	paths := linuxArtifactPaths(profileHome, users)
	homesFull := make([]string, 0, len(users))
	for _, user := range users {
		homesFull = append(homesFull, filepath.Join(profileHome, user))
	}
	return append(paths, discoverBrowserHistories(homesFull, "linux")...)
}
