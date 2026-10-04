package core

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
)

func examinePackageMemory(ctx context.Context, f *zip.File, it Item, platform string, m *MemoryAnalysis) error {
	options, _ := ctx.Value(memoryExaminationKey{}).(memoryExaminationOptions)
	workspace, _ := ctx.Value(memoryWorkspaceKey{}).(string)
	if options.tool == "" || options.symbols == "" || workspace == "" {
		return examineConfiguredMemory(ctx, "", platform, m)
	}
	candidates := []string{options.workDir}
	if options.workDir == "" {
		candidates = []string{os.TempDir(), filepath.Dir(workspace)}
	}
	var dir string
	for _, candidate := range candidates {
		volume, e := probeVolume(candidate)
		// Both the verified archive extraction and the examiner's private copy
		// coexist. No arbitrary reserve or image-size limit is imposed.
		if e != nil || it.Size < 0 || volume.Available/2 < it.Size {
			continue
		}
		if p, e := os.MkdirTemp(candidate, "k957-memory-object-"); e == nil {
			dir = p
			break
		}
	}
	if dir == "" {
		m.Notes = append(m.Notes, "Kernel examination unavailable: no filesystem has space for archive extraction and the private examiner image. Choose K957_MEMORY_WORK_DIR.")
		return nil
	}
	defer os.RemoveAll(dir)
	r, e := f.Open()
	if e != nil {
		return e
	}
	defer r.Close()
	image := filepath.Join(dir, "memory.bin")
	w, e := os.OpenFile(image, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	h := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(w, h), contextReader{ctx: ctx, r: r})
	if copyErr == nil {
		copyErr = w.Sync()
	}
	closeErr := w.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if n != it.Size || hex.EncodeToString(h.Sum(nil)) != it.SHA256 {
		return errors.New("memory archive extraction differs from verified object")
	}
	ctx = WithMemoryExamination(ctx, options.tool, options.symbols, dir)
	return examineConfiguredMemory(ctx, image, platform, m)
}
