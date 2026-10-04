//go:build linux || darwin

package core

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestVerifiedMemoryScanWithNoStagingCapacity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "memory.raw")
	image := []byte("failed password in a synthetic memory image\n")
	if err := os.WriteFile(path, image, 0600); err != nil {
		t.Fatal(err)
	}
	previous := statFilesystem
	t.Cleanup(func() { statFilesystem = previous })
	statFilesystem = func(_ string, stat *syscall.Statfs_t) error {
		stat.Bsize = 4096
		stat.Bavail = 0
		return nil
	}
	if capacity, err := probeVolume(filepath.Dir(path)); err != nil || capacity.Available != 0 {
		t.Fatal("controlled zero-capacity filesystem failed", capacity, err)
	}
	m, err := scanVerifiedMemoryFile(context.Background(), path, digestBytes(image), BuiltinRules(), nil)
	if err != nil || m.SHA256 != digestBytes(image) || len(m.Hits) == 0 {
		t.Fatal("analysis unnecessarily requires image-sized staging space", err)
	}
}
