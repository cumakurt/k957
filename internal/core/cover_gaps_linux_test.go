//go:build linux

package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLinuxProfileHomeEdges(t *testing.T) {
	oldHome := profileHome
	t.Cleanup(func() { profileHome = oldHome })
	home := t.TempDir()
	os.WriteFile(filepath.Join(home, "not-a-dir"), []byte("x"), 0600)
	os.Mkdir(filepath.Join(home, "alice"), 0700)
	profileHome = home
	paths := artifactCandidates()
	found := false
	for _, p := range paths {
		if strings.Contains(p, filepath.Join("alice", ".bash_history")) {
			found = true
		}
		if strings.Contains(p, "not-a-dir") {
			t.Fatal("file treated as home")
		}
	}
	if !found {
		t.Fatal("home history missing")
	}
	profileHome = filepath.Join(home, "missing")
	if len(artifactCandidates()) == 0 {
		t.Fatal("expected static paths")
	}

}
