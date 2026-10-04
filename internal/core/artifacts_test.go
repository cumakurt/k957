package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPlatformArtifactPaths(t *testing.T) {
	linux := linuxArtifactPaths("/home", []string{"ada"})
	if !hasPath(linux, "/etc/sudoers") || !hasPath(linux, "/etc/ld.so.preload") || !hasPath(linux, filepath.Join("/home", "ada", ".config", "autostart")) {
		t.Fatalf("linux profile missing triage paths: %v", linux)
	}
	for _, path := range linux {
		if strings.Contains(path, "shadow") || strings.Contains(path, "id_rsa") {
			t.Fatal(path)
		}
	}
	root := filepath.Join("C:", "Windows")
	home := filepath.Join("C:", "Users", "ada")
	windows := windowsArtifactPaths(root, []string{home})
	if !hasPath(windows, filepath.Join(root, "AppCompat", "Programs", "Amcache.hve")) || !hasPath(windows, filepath.Join(root, "System32", "config", "SYSTEM")) || !hasPath(windows, filepath.Join(home, "NTUSER.DAT")) {
		t.Fatalf("windows profile: %v", windows)
	}
	for _, path := range windows {
		base := strings.ToUpper(filepath.Base(path))
		if base == "SAM" || base == "SECURITY" || base == "NTDS.DIT" {
			t.Fatal(path)
		}
	}
	darwin := darwinArtifactPaths([]string{"/Users/ada"})
	if !hasPath(darwin, "/etc/sudoers") || !hasPath(darwin, filepath.Join("/Users/ada", "Library", "Safari", "History.db")) || !hasPath(darwin, filepath.Join("/Users/ada", "Library", "Preferences", "com.apple.LaunchServices.QuarantineEventsV2")) {
		t.Fatalf("darwin profile: %v", darwin)
	}
}

func TestBrowserHistoryDiscovery(t *testing.T) {
	home := t.TempDir()
	chrome := filepath.Join(home, ".config", "google-chrome", "Default")
	if e := os.MkdirAll(chrome, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(chrome, "History"), []byte("sqlite"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(chrome, "Login Data"), []byte("secret"), 0600); e != nil {
		t.Fatal(e)
	}
	firefox := filepath.Join(home, ".mozilla", "firefox", "abc.default-release")
	if e := os.MkdirAll(firefox, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(firefox, "places.sqlite"), []byte("sqlite"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(firefox, "logins.json"), []byte("{}"), 0600); e != nil {
		t.Fatal(e)
	}
	got := discoverBrowserHistories([]string{home}, "linux")
	joined := strings.Join(got, "\n")
	if !strings.Contains(joined, "History") || !strings.Contains(joined, "places.sqlite") || strings.Contains(joined, "Login Data") || strings.Contains(joined, "logins.json") {
		t.Fatal(got)
	}
}

func hasPath(paths []string, want string) bool {
	for _, path := range paths {
		if path == want {
			return true
		}
	}
	return false
}
