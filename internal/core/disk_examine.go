package core

import (
	"bufio"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type DiskEntry struct {
	Name        string `json:"name"`
	Inode       string `json:"inode"`
	Type        string `json:"type"`
	Deleted     bool   `json:"deleted_directory_entry"`
	Line        int    `json:"source_line"`
	Reallocated bool   `json:"metadata_reallocated,omitempty"`
}
type DiskExamination struct {
	Schema       string         `json:"schema"`
	Status       string         `json:"status"`
	Error        string         `json:"error,omitempty"`
	Source       string         `json:"source"`
	ImageSHA256  string         `json:"image_sha256"`
	ImageSize    int64          `json:"image_bytes"`
	SectorSize   int64          `json:"sector_bytes"`
	SectorOffset int64          `json:"filesystem_sector_offset"`
	Tool         ToolInvocation `json:"tool"`
	Entries      []DiskEntry    `json:"entries"`
	Coverage     Coverage       `json:"coverage"`
	Notes        []string       `json:"notes"`
}

var diskListingLine = regexp.MustCompile(`^([a-zA-Z-]+/[a-zA-Z-]+) (\* )?([0-9]+(?:-[0-9]+)*)(\(realloc\))?:\s?(.*)$`)
var diskInode = regexp.MustCompile(`^[0-9]+(?:-[0-9]+){0,2}$`)

func ExamineDisk(ctx context.Context, source, out, expected, tool string, offset, sectorSize int64) (result DiskExamination, err error) {
	if offset < 0 || sectorSize < 512 || sectorSize > 4096 || sectorSize&(sectorSize-1) != 0 {
		return result, errors.New("invalid filesystem sector offset/size")
	}
	if e := os.Mkdir(out, 0700); e != nil {
		return result, e
	}
	ok := false
	defer func() {
		if !ok {
			os.RemoveAll(out)
		}
	}()
	dir, e := os.MkdirTemp("", "k957-disk-")
	if e != nil {
		return result, e
	}
	defer os.RemoveAll(dir)
	sum, size, e := stageRawImage(ctx, source, filepath.Join(dir, "image.raw"), expected, 8<<30)
	if e != nil {
		return result, e
	}
	if offset >= size/sectorSize {
		return result, errors.New("filesystem sector offset is outside image")
	}
	if tool == "" {
		tool = "fls"
	}
	args := []string{"-r", "-p", "-i", "raw", "-b", strconv.FormatInt(sectorSize, 10), "-o", strconv.FormatInt(offset, 10), filepath.Join(dir, "image.raw")}
	invocation, runErr := runDerivedTool(ctx, tool, args, dir, "listing.txt", "tool.stderr", 32<<20, 2*time.Minute)
	result = DiskExamination{Schema: "k957-disk-examination/1", Status: "interpreted", Source: source, ImageSHA256: sum, ImageSize: size, SectorSize: sectorSize, SectorOffset: offset, Tool: invocation, Entries: []DiskEntry{}, Notes: []string{"This is a derived Sleuth Kit raw-image directory examination, not physical disk acquisition or a filesystem mount.", "Deleted marks are tool-reported directory entries. Recovery availability and overwritten content are filesystem-dependent. Recursive fls does not descend into deleted directories.", "Only a caller-selected filesystem offset is examined. Partition enumeration, encrypted volumes, disk carving and bad-sector recovery are not asserted.", "Image identity binds raw bytes. Inode references are scoped by image SHA-256, filesystem offset and sector size. The external executable hash does not bind every shared-library dependency."}}
	if runErr != nil {
		if invocation.Finished.IsZero() {
			return result, runErr
		}
		result.Status, result.Error = "failed", runErr.Error()
		result.Coverage = coverage("disk_entries", "entries", 0, 0, 100000, false)
		result.Coverage.Status = "failed"
		result.Coverage.Reasons = map[string]int{"external_tool_failed": 1}
		result.Notes = append(result.Notes, "Failed tool output is retained only for diagnosis. No entries are interpreted and staged-image integrity after this failed invocation is not established.")
		if e = retainFailedDiskOutput(dir, out, "listing.txt", "listing.partial.txt", 32<<20, &result.Tool); e != nil {
			return result, errors.Join(runErr, e)
		}
		if e = WriteJSONNew(filepath.Join(out, "disk.json"), result); e != nil {
			return result, errors.Join(runErr, e)
		}
		ok = true
		return result, runErr
	}
	file, e := os.Open(filepath.Join(dir, "listing.txt"))
	if e != nil {
		return result, e
	}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 65536), 1<<20)
	line, seen, skipped := 0, 0, 0
	for scanner.Scan() {
		if e = ctx.Err(); e != nil {
			file.Close()
			return result, e
		}
		line++
		text := scanner.Text()
		if strings.TrimSpace(text) == "" {
			continue
		}
		seen++
		m := diskListingLine.FindStringSubmatch(text)
		if m == nil || len(m[5]) > 4096 || !utf8.ValidString(m[5]) {
			skipped++
			continue
		}
		if len(result.Entries) >= 100000 {
			skipped++
			continue
		}
		result.Entries = append(result.Entries, DiskEntry{Name: m[5], Inode: m[3], Type: m[1], Deleted: m[2] != "", Reallocated: m[4] != "", Line: line})
	}
	scanErr := scanner.Err()
	file.Close()
	if scanErr != nil {
		return result, scanErr
	}
	result.Coverage = coverage("disk_entries", "entries", int64(seen), int64(len(result.Entries)), 100000, true)
	if skipped > 0 {
		result.Coverage.Reasons = map[string]int{"unsupported_or_limited_listing": skipped}
	}
	after, e := fileSHA256Progress(filepath.Join(dir, "image.raw"), "", 0, &verifyMeter{ctx: ctx})
	if e != nil {
		return result, e
	}
	if after != sum {
		return result, errors.New("disk tool changed staged image")
	}
	for _, name := range []string{"listing.txt", "tool.stderr"} {
		b, e := ReadLimited(filepath.Join(dir, name), 32<<20)
		if e != nil {
			return result, e
		}
		if e = WriteNew(filepath.Join(out, name), b); e != nil {
			return result, e
		}
	}
	if e = WriteJSONNew(filepath.Join(out, "disk.json"), result); e != nil {
		return result, e
	}
	ok = true
	return result, nil
}

type DiskRecovery struct {
	Schema       string         `json:"schema"`
	Status       string         `json:"status"`
	Error        string         `json:"error,omitempty"`
	ImageSHA256  string         `json:"image_sha256"`
	Inode        string         `json:"inode"`
	SectorOffset int64          `json:"filesystem_sector_offset"`
	SectorSize   int64          `json:"sector_bytes"`
	SHA256       string         `json:"recovered_sha256"`
	Bytes        int64          `json:"recovered_bytes"`
	Tool         ToolInvocation `json:"tool"`
	Note         string         `json:"note"`
}

func RecoverDiskEntry(ctx context.Context, source, out, expected, tool, inode string, offset, sectorSize int64) (result DiskRecovery, err error) {
	if !validHash(expected) || !diskInode.MatchString(inode) || offset < 0 || sectorSize < 512 || sectorSize > 4096 || sectorSize&(sectorSize-1) != 0 {
		return result, errors.New("recovery needs an exact image SHA-256 and bounded inode/offset/sector values")
	}
	if e := os.Mkdir(out, 0700); e != nil {
		return result, e
	}
	ok := false
	defer func() {
		if !ok {
			os.RemoveAll(out)
		}
	}()
	dir, e := os.MkdirTemp("", "k957-recover-")
	if e != nil {
		return result, e
	}
	defer os.RemoveAll(dir)
	sum, size, e := stageRawImage(ctx, source, filepath.Join(dir, "image.raw"), expected, 8<<30)
	if e != nil {
		return result, e
	}
	if offset >= size/sectorSize {
		return result, errors.New("filesystem offset outside image")
	}
	if tool == "" {
		tool = "icat"
	}
	args := []string{"-r", "-i", "raw", "-b", strconv.FormatInt(sectorSize, 10), "-o", strconv.FormatInt(offset, 10), filepath.Join(dir, "image.raw"), inode}
	invocation, runErr := runDerivedTool(ctx, tool, args, dir, "recovered.bin", "tool.stderr", 128<<20, 2*time.Minute)
	if runErr != nil {
		result = DiskRecovery{Schema: "k957-disk-recovery/1", Status: "failed", Error: runErr.Error(), ImageSHA256: sum, Inode: inode, SectorOffset: offset, SectorSize: sectorSize, Tool: invocation, Note: "Failed tool output is retained as recovered.partial.bin only for diagnosis. No successful recovered-content hash/size is asserted, and staged-image integrity after this failed invocation is not established."}
		if invocation.Finished.IsZero() {
			return result, runErr
		}
		if e = retainFailedDiskOutput(dir, out, "recovered.bin", "recovered.partial.bin", 128<<20, &result.Tool); e != nil {
			return result, errors.Join(runErr, e)
		}
		if e = WriteJSONNew(filepath.Join(out, "recovery.json"), result); e != nil {
			return result, errors.Join(runErr, e)
		}
		ok = true
		return result, runErr
	}
	after, e := fileSHA256Progress(filepath.Join(dir, "image.raw"), "", 0, &verifyMeter{ctx: ctx})
	if e != nil {
		return result, e
	}
	if after != sum {
		return result, errors.New("recovery tool changed staged image")
	}
	info, e := os.Stat(filepath.Join(dir, "recovered.bin"))
	if e != nil {
		return result, e
	}
	result = DiskRecovery{Schema: "k957-disk-recovery/1", Status: "interpreted", ImageSHA256: sum, Inode: inode, SectorOffset: offset, SectorSize: sectorSize, SHA256: invocation.StdoutSHA256, Bytes: info.Size(), Tool: invocation, Note: "Recovery is a derived tool interpretation scoped to this image/offset/inode. Zero-length or overwritten output is not proof of original content. No original directory or source image is modified."}
	for _, name := range []string{"recovered.bin", "tool.stderr"} {
		src, e := os.Open(filepath.Join(dir, name))
		if e != nil {
			return result, e
		}
		dst, e := os.OpenFile(filepath.Join(out, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			src.Close()
			return result, e
		}
		_, e = io.Copy(dst, &contextReader{ctx: ctx, r: src})
		src.Close()
		closeErr := dst.Close()
		if e != nil {
			return result, e
		}
		if closeErr != nil {
			return result, closeErr
		}
	}
	if e = WriteJSONNew(filepath.Join(out, "recovery.json"), result); e != nil {
		return result, e
	}
	ok = true
	return result, nil
}

// Failed outputs remain bounded even when the caller context was canceled.
// They are diagnostic bytes, never promoted to interpreted/recovered content.
func retainFailedDiskOutput(dir, out, stdout, partial string, limit int64, tool *ToolInvocation) error {
	for _, file := range []struct {
		source, target string
		limit          int64
		digest         *string
	}{{stdout, partial, limit, &tool.StdoutSHA256}, {"tool.stderr", "tool.stderr", 64 << 10, &tool.StderrSHA256}} {
		path := filepath.Join(dir, file.source)
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Size() > file.limit {
			return errors.New("failed disk output is not a bounded regular file")
		}
		source, err := os.Open(path)
		if err != nil {
			return err
		}
		opened, err := source.Stat()
		if err != nil || !os.SameFile(info, opened) {
			source.Close()
			return errors.New("failed disk output changed before open")
		}
		target, err := os.OpenFile(filepath.Join(out, file.target), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			source.Close()
			return err
		}
		digest := sha256.New()
		n, copyErr := io.Copy(io.MultiWriter(target, digest), io.LimitReader(source, file.limit+1))
		sourceErr := source.Close()
		syncErr := target.Sync()
		closeErr := target.Close()
		if err = errors.Join(copyErr, sourceErr, syncErr, closeErr); err != nil {
			return err
		}
		if n > file.limit || n != info.Size() {
			return errors.New("failed disk output changed size while copying")
		}
		sum := fmt.Sprintf("%x", digest.Sum(nil))
		if *file.digest != "" && *file.digest != sum {
			return errors.New("failed disk output differs from invocation digest")
		}
		*file.digest = sum
	}
	return nil
}
