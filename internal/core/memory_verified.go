package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
)

func scanVerifiedMemoryFile(ctx context.Context, path, expected string, rules []Rule, meter *verifyMeter) (MemoryAnalysis, error) {
	if !validHash(expected) {
		return MemoryAnalysis{}, errors.New("verified memory SHA-256 required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return MemoryAnalysis{}, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return MemoryAnalysis{}, err
	}
	if !info.Mode().IsRegular() || info.Size() < 0 {
		return MemoryAnalysis{}, errors.New("memory image must be a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return MemoryAnalysis{}, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return MemoryAnalysis{}, err
	}
	if !os.SameFile(info, opened) || info.Size() != opened.Size() || !info.ModTime().Equal(opened.ModTime()) {
		return MemoryAnalysis{}, errors.New("memory image changed before open")
	}
	// Hash the same stream the in-process scanner consumes. A separate hash
	// pass could authenticate different bytes during concurrent modification.
	// External tools still receive private staged images through stageRawImage.
	bounded := &io.LimitedReader{R: f, N: opened.Size() + 1}
	var reader io.Reader = contextReader{ctx: ctx, r: bounded}
	if meter != nil {
		reader = meter.reader(reader, filepath.Base(path), opened.Size())
	}
	h := sha256.New()
	result, err := scanMemoryContext(ctx, io.TeeReader(reader, h), rules)
	if err != nil {
		return MemoryAnalysis{}, err
	}
	if err = ctx.Err(); err != nil {
		return MemoryAnalysis{}, err
	}
	after, err := os.Lstat(path)
	if err != nil {
		return MemoryAnalysis{}, err
	}
	if opened.Size()+1-bounded.N != opened.Size() || !os.SameFile(opened, after) ||
		opened.Size() != after.Size() || !opened.ModTime().Equal(after.ModTime()) {
		return MemoryAnalysis{}, errors.New("memory image changed while scanning")
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if sum != expected {
		return MemoryAnalysis{}, errors.New("memory scan input differs from signed image SHA-256")
	}
	result.SHA256 = sum
	result.Notes = append(result.Notes, "Memory was scanned through one read-only file descriptor. SHA-256 of exactly the consumed bytes matched the signed image hash before results were accepted. File identity, size and modification time were rechecked; no temporary image copy was created.")
	if meter != nil {
		meter.finish(opened.Size())
	}
	return result, nil
}
