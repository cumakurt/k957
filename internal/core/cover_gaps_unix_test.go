//go:build linux || darwin

package core

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// These fixtures require POSIX limits, permissions, FIFOs and statfs.
func TestUnixVolumeFailureEdges(t *testing.T) {
	dir := t.TempDir()
	signal.Ignore(syscall.SIGXFSZ)
	t.Cleanup(func() { signal.Reset(syscall.SIGXFSZ) })
	var old syscall.Rlimit
	if e := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &old); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { syscall.Setrlimit(syscall.RLIMIT_FSIZE, &old) })
	if e := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &syscall.Rlimit{Cur: 0, Max: old.Max}); e != nil {
		t.Fatal(e)
	}
	if e := WriteNew(filepath.Join(dir, "limited"), []byte("x")); e == nil {
		t.Fatal("expected write failure")
	}
	if e := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &old); e != nil {
		t.Fatal(e)
	}

	oldStat := statFilesystem
	t.Cleanup(func() { statFilesystem = oldStat })
	statFilesystem = func(path string, stat *syscall.Statfs_t) error {
		stat.Bsize = 0
		stat.Bavail = 1
		return nil
	}
	if _, e := probeVolume(dir); e == nil {
		t.Fatal("expected capacity error")
	}
	statFilesystem = func(path string, stat *syscall.Statfs_t) error { return nil }
	if _, e := probeVolume(filepath.Join(dir, "missing")); e == nil {
		t.Fatal("expected stat error")
	}
	statFilesystem = oldStat
}

func TestCollectionHelpers(t *testing.T) {
	if sanitizeHost(strings.Repeat("a", 80)) == "" || sanitizeHost("...") != "unknown" || sanitizeHost("é") != "_" {
		t.Fatal(sanitizeHost("..."), sanitizeHost("é"))
	}
	base := t.TempDir()
	fileBase := filepath.Join(base, "file")
	os.WriteFile(fileBase, []byte("x"), 0600)
	if _, e := newCollectionDir(fileBase, "host", time.Now()); e == nil {
		t.Fatal("expected mkdir failure")
	}
	parent := filepath.Join(base, "locked", sanitizeHost("host"))
	os.MkdirAll(parent, 0700)
	os.Chmod(parent, 0500)
	t.Cleanup(func() { os.Chmod(parent, 0700) })
	if _, e := newCollectionDir(filepath.Join(base, "locked"), "host", time.Now()); e == nil {
		t.Fatal("expected child mkdir failure")
	}
	os.Chmod(parent, 0700)
	when := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	stamp := when.Format("20060102T150405Z")
	os.Mkdir(filepath.Join(parent, stamp), 0700)
	for i := 1; i < 100; i++ {
		if e := os.Mkdir(filepath.Join(parent, fmt.Sprintf("%s-%d", stamp, i+1)), 0700); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := newCollectionDir(filepath.Join(base, "locked"), "host", when); e == nil {
		t.Fatal("expected collision")
	}

	dest := filepath.Join(base, "dest")
	os.Mkdir(dest, 0700)
	fifo := filepath.Join(base, "fifo")
	if e := syscall.Mkfifo(fifo, 0600); e != nil {
		t.Fatal(e)
	}
	os.Symlink(filepath.Join(base, "missing-target"), filepath.Join(base, "broken"))
	present, absent, notes := filterCandidates([]string{filepath.Join(base, "missing"), fifo, dest, filepath.Join(base, "broken"), dest}, dest)
	if len(present) != 0 || len(absent) == 0 || len(notes) == 0 {
		t.Fatalf("present %v absent %v notes %v", present, absent, notes)
	}

	pub, priv, e := ed25519.GenerateKey(nil)
	if e != nil {
		t.Fatal(e)
	}
	_ = pub
	os.WriteFile(filepath.Join(base, "goodkey"), []byte(fmt.Sprintf("%x\n", priv)), 0600)
	useRand(t, failReader{})
	if _, _, _, e := collectionKey(""); e == nil {
		t.Fatal("expected generate failure")
	}
	if _, _, _, e := collectionKey(filepath.Join(base, "missing")); e == nil {
		t.Fatal("expected missing key")
	}
	os.WriteFile(filepath.Join(base, "badkey"), []byte("nope"), 0600)
	if _, _, _, e := collectionKey(filepath.Join(base, "badkey")); e == nil {
		t.Fatal("expected bad key")
	}
	if _, _, generated, e := collectionKey(filepath.Join(base, "goodkey")); e != nil || generated {
		t.Fatal(e, generated)
	}
}

func TestUnixSnapshotTruncation(t *testing.T) {
	if _, _, e := snapshot(context.Background(), source{Command: "head", Args: []string{"-c", "5000000", "/dev/zero"}}); e == nil || !strings.Contains(e.Error(), "truncated") {
		t.Fatal(e)
	}
}
