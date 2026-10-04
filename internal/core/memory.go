package core

import (
	"bufio"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

const MemorySchema = "k957-memory/1"

// LiME ("Linux Memory Extractor") range header: magic, version, first and
// last (inclusive) physical address, 8 reserved bytes. All little-endian.
const (
	limeMagic      uint32 = 0x4C694D45
	limeVersion    uint32 = 1
	limeHeaderSize        = 32
	limeRecordMax         = 1 << 20
	memoryPage            = 4096
	memoryBlock           = 1 << 20
	toolOutputMax         = 64 << 10
)

var errMemoryPrivilege = errors.New("physical memory acquisition requires root/administrator privileges")

// MemoryRange is a physical address range stored in the image. Size is in bytes.
type MemoryRange struct {
	Start           uint64 `json:"start"`
	Size            uint64 `json:"size"`
	UnreadablePages int    `json:"unreadable_pages,omitempty"`
}

type MemoryRecord struct {
	Schema        string        `json:"schema"`
	ID            string        `json:"id"`
	Tool          string        `json:"tool"`
	Version       string        `json:"version"`
	Case          string        `json:"case"`
	Operator      string        `json:"operator"`
	Host          string        `json:"host"`
	OS            string        `json:"os"`
	Arch          string        `json:"arch"`
	KernelRelease string        `json:"kernel_release,omitempty"`
	Method        string        `json:"method"`
	Source        string        `json:"source"`
	ToolSHA256    string        `json:"tool_sha256,omitempty"`
	ToolOutput    string        `json:"tool_output,omitempty"`
	Format        string        `json:"format"`
	Image         string        `json:"image"`
	Started       time.Time     `json:"started"`
	Finished      time.Time     `json:"finished"`
	Status        string        `json:"status"`
	PageSize      int           `json:"page_size"`
	Ranges        []MemoryRange `json:"ranges"`
	Gaps          []MemoryRange `json:"unmapped_gaps"`
	Bytes         uint64        `json:"bytes"`
	ImageSize     int64         `json:"image_size"`
	SHA256        string        `json:"sha256"`
	SHA1          string        `json:"sha1"`
	MD5           string        `json:"md5"`
	Issues        []Issue       `json:"issues"`
	Notes         []string      `json:"notes"`
}

type MemoryOptions struct {
	Dir, Case, Operator string
	// Tool is an external acquisition program; "{output}" in ToolArgs is
	// replaced with the destination path.
	Tool     string
	ToolArgs []string
	// Limit caps stored physical bytes; zero means no limit.
	Limit   int64
	Reserve int64
	// iomem and kcore override the Linux sources in tests.
	iomem, kcore string
}

// AcquireMemory writes memory.lime or memory.raw plus memory.json into Dir.
// The image is created exclusively and never rewritten.
func AcquireMemory(ctx context.Context, o MemoryOptions) (MemoryRecord, error) {
	host, _ := os.Hostname()
	r := MemoryRecord{Schema: MemorySchema, ID: ID(), Tool: "k957", Version: Version, Case: o.Case, Operator: o.Operator, Host: host, OS: runtime.GOOS, Arch: runtime.GOARCH, Started: time.Now().UTC(), Status: "complete", PageSize: memoryPage, Ranges: []MemoryRange{}, Gaps: []MemoryRange{}, Issues: []Issue{}, Notes: []string{
		"Acquired from a running system: memory changes while it is read, so the image is not an atomic snapshot and the collector's own activity is present.",
	}}
	if o.Limit < 0 || o.Reserve < 0 {
		return r, errors.New("memory limit and reserve must not be negative")
	}
	if systemGOOS == "linux" {
		if b, e := os.ReadFile("/proc/sys/kernel/osrelease"); e == nil {
			r.KernelRelease = strings.TrimSpace(string(b))
		}
	}
	tool := o.Tool
	if tool == "" && systemGOOS == "windows" {
		tool = findBundledWinPmem()
	}
	var e error
	switch {
	case tool != "":
		ReportProgress(ctx, Progress{Phase: "memory", Detail: "external acquisition tool"})
		e = acquireExternal(ctx, o, tool, &r)
	case systemGOOS == "linux" || o.kcore != "":
		e = acquireKcore(ctx, o, &r)
	default:
		e = fmt.Errorf("no native physical memory acquisition on %s; supply --memory-tool", systemGOOS)
	}
	if e != nil {
		return r, e
	}
	r.Finished = time.Now().UTC()
	if len(r.Issues) > 0 {
		r.Status = "partial"
	}
	if e = WriteJSONNew(filepath.Join(o.Dir, "memory.json"), r); e != nil {
		os.Remove(filepath.Join(o.Dir, r.Image))
		return r, e
	}
	return r, nil
}

type physRange struct{ start, end uint64 } // end is exclusive

// parseIOMem returns merged "System RAM" ranges. Unprivileged readers see
// zeroed addresses, which is reported as a privilege error.
func parseIOMem(rd io.Reader) ([]physRange, error) {
	var ranges []physRange
	hidden := false
	s := bufio.NewScanner(rd)
	for s.Scan() {
		addr, name, ok := strings.Cut(strings.TrimSpace(s.Text()), " : ")
		if !ok || strings.TrimSpace(name) != "System RAM" {
			continue
		}
		a, b, ok := strings.Cut(addr, "-")
		if !ok {
			return nil, fmt.Errorf("malformed iomem line %q", s.Text())
		}
		start, e1 := strconv.ParseUint(a, 16, 64)
		last, e2 := strconv.ParseUint(b, 16, 64)
		if e1 != nil || e2 != nil || last < start || last == ^uint64(0) {
			return nil, fmt.Errorf("malformed iomem line %q", s.Text())
		}
		if start == 0 && last == 0 {
			hidden = true
			continue
		}
		ranges = append(ranges, physRange{start, last + 1})
	}
	if e := s.Err(); e != nil {
		return nil, e
	}
	if len(ranges) == 0 {
		if hidden {
			return nil, errMemoryPrivilege
		}
		return nil, errors.New("no System RAM ranges in iomem")
	}
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].start < ranges[j].start })
	merged := ranges[:1]
	for _, r := range ranges[1:] {
		last := &merged[len(merged)-1]
		if r.start <= last.end {
			last.end = max(last.end, r.end)
		} else {
			merged = append(merged, r)
		}
	}
	return merged, nil
}

type kcoreSegment struct{ paddr, size, offset uint64 }

type plannedRange struct{ phys, size, offset uint64 }

// kcoreSegments lists PT_LOAD segments with a physical address. The kernel
// sets p_paddr to all-bits-one for vmalloc, module and user mappings.
func kcoreSegments(f *elf.File) []kcoreSegment {
	var out []kcoreSegment
	for _, p := range f.Progs {
		if p.Type != elf.PT_LOAD || p.Paddr == ^uint64(0) || p.Filesz == 0 {
			continue
		}
		out = append(out, kcoreSegment{paddr: p.Paddr, size: p.Filesz, offset: p.Off})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].paddr < out[j].paddr })
	return out
}

// planPhysical intersects System RAM ranges with kcore segments. Bytes inside
// a System RAM range but outside every segment are recorded as gaps and are
// not stored; each stored range stays physically contiguous.
func planPhysical(ranges []physRange, segs []kcoreSegment) ([]plannedRange, []MemoryRange) {
	var planned []plannedRange
	var gaps []MemoryRange
	for _, r := range ranges {
		pos := r.start
		for _, s := range segs {
			if s.paddr+s.size <= pos {
				continue
			}
			if s.paddr >= r.end {
				break
			}
			if s.paddr > pos {
				gaps = append(gaps, MemoryRange{Start: pos, Size: s.paddr - pos})
				pos = s.paddr
			}
			end := min(r.end, s.paddr+s.size)
			planned = append(planned, plannedRange{phys: pos, size: end - pos, offset: s.offset + (pos - s.paddr)})
			pos = end
			if pos >= r.end {
				break
			}
		}
		if pos < r.end {
			gaps = append(gaps, MemoryRange{Start: pos, Size: r.end - pos})
		}
	}
	return planned, gaps
}

type limeWriter struct {
	w         io.Writer
	sha256    hash.Hash
	sha1      hash.Hash
	md5       hash.Hash
	imageSize int64
	onBlock   func(int)
}

func newLimeWriter(w io.Writer) *limeWriter {
	return &limeWriter{w: w, sha256: sha256.New(), sha1: sha1.New(), md5: md5.New()}
}

func (l *limeWriter) write(p []byte) error {
	n, e := l.w.Write(p)
	_, _ = l.sha256.Write(p[:n])
	_, _ = l.sha1.Write(p[:n])
	_, _ = l.md5.Write(p[:n])
	l.imageSize += int64(n)
	if e != nil {
		return e
	}
	if n != len(p) {
		return io.ErrShortWrite
	}
	return nil
}

func (l *limeWriter) sums() (string, string, string) {
	return hex.EncodeToString(l.sha256.Sum(nil)), hex.EncodeToString(l.sha1.Sum(nil)), hex.EncodeToString(l.md5.Sum(nil))
}

// copyRange writes one LiME range. A failed read is retried per page; pages
// that still fail are stored as zeros and counted.
func (l *limeWriter) copyRange(ctx context.Context, start, size uint64, src io.ReaderAt, fileOff uint64) (int, error) {
	if size == 0 || start > ^uint64(0)-size {
		return 0, errors.New("invalid memory range")
	}
	hdr := make([]byte, limeHeaderSize)
	binary.LittleEndian.PutUint32(hdr[0:4], limeMagic)
	binary.LittleEndian.PutUint32(hdr[4:8], limeVersion)
	binary.LittleEndian.PutUint64(hdr[8:16], start)
	binary.LittleEndian.PutUint64(hdr[16:24], start+size-1)
	if e := l.write(hdr); e != nil {
		return 0, e
	}
	buf := make([]byte, memoryBlock)
	unread := 0
	var done uint64
	for done < size {
		if e := ctx.Err(); e != nil {
			return unread, e
		}
		n := int(min(uint64(len(buf)), size-done))
		chunk := buf[:n]
		if e := readFullAt(src, chunk, int64(fileOff+done)); e != nil {
			for off := 0; off < n; off += memoryPage {
				pn := min(memoryPage, n-off)
				page := chunk[off : off+pn]
				clear(page)
				if e := readFullAt(src, page, int64(fileOff+done)+int64(off)); e != nil {
					clear(page)
					unread++
				}
			}
		}
		if e := l.write(chunk); e != nil {
			return unread, e
		}
		done += uint64(n)
		if l.onBlock != nil {
			l.onBlock(n)
		}
	}
	return unread, nil
}

func readFullAt(src io.ReaderAt, p []byte, off int64) error {
	for len(p) > 0 {
		n, e := src.ReadAt(p, off)
		if n > 0 {
			p = p[n:]
			off += int64(n)
		}
		if len(p) == 0 {
			return nil
		}
		if e != nil {
			return e
		}
		if n == 0 {
			return io.ErrUnexpectedEOF
		}
	}
	return nil
}

func acquireKcore(ctx context.Context, o MemoryOptions, r *MemoryRecord) error {
	iomemPath := o.iomem
	if iomemPath == "" {
		iomemPath = "/proc/iomem"
	}
	kcorePath := o.kcore
	if kcorePath == "" {
		kcorePath = "/proc/kcore"
	}
	mf, e := os.Open(iomemPath)
	if e != nil {
		if os.IsPermission(e) {
			return errMemoryPrivilege
		}
		return e
	}
	ranges, e := parseIOMem(mf)
	mf.Close()
	if e != nil {
		return e
	}
	kf, e := os.Open(kcorePath)
	if e != nil {
		if os.IsPermission(e) {
			return errMemoryPrivilege
		}
		return e
	}
	defer kf.Close()
	ef, e := elf.NewFile(kf)
	if e != nil {
		return fmt.Errorf("kcore is not an ELF core: %w", e)
	}
	planned, gaps := planPhysical(ranges, kcoreSegments(ef))
	if len(planned) == 0 {
		return errors.New("no physical memory mapped by kcore")
	}
	var total uint64
	for _, p := range planned {
		if p.size > ^uint64(0)-total {
			return errors.New("physical memory size overflow")
		}
		total += p.size
	}
	if o.Limit > 0 && total > uint64(o.Limit) {
		return fmt.Errorf("physical memory %d bytes exceeds --memory-limit %d", total, o.Limit)
	}
	estimate := int64(total) + int64(len(planned))*limeHeaderSize
	if estimate < 0 {
		return errors.New("memory image size exceeds supported range")
	}
	if e = ensureSpace(o.Dir, estimate, o.Reserve); e != nil {
		return e
	}
	path := filepath.Join(o.Dir, "memory.lime")
	out, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	ok := false
	defer func() {
		out.Close()
		if !ok {
			os.Remove(path)
		}
	}()
	w := newLimeWriter(out)
	var copied int64
	totalBytes := int64(0)
	if total <= uint64(^uint64(0)>>1) {
		totalBytes = int64(total)
	}
	report := progressEnabled(ctx)
	if report {
		ReportProgress(ctx, Progress{Phase: "memory", Detail: "physical memory", TotalBytes: totalBytes})
	}
	for _, p := range planned {
		if report {
			phys := p.phys
			w.onBlock = func(n int) {
				copied += int64(n)
				ReportProgress(ctx, Progress{Phase: "memory", Detail: fmt.Sprintf("physical %#x", phys), Bytes: copied, TotalBytes: totalBytes})
			}
		}
		unread, e := w.copyRange(ctx, p.phys, p.size, kf, p.offset)
		if e != nil {
			return e
		}
		r.Ranges = append(r.Ranges, MemoryRange{Start: p.phys, Size: p.size, UnreadablePages: unread})
		if unread > 0 {
			r.Issues = append(r.Issues, Issue{Source: fmt.Sprintf("physical:%#x", p.phys), Reason: fmt.Sprintf("%d pages unreadable; stored as zeros", unread)})
		}
		r.Bytes += p.size
	}
	if e = out.Sync(); e != nil {
		return e
	}
	if e = out.Close(); e != nil {
		return e
	}
	ok = true
	r.SHA256, r.SHA1, r.MD5 = w.sums()
	r.ImageSize = w.imageSize
	r.Format = "lime"
	r.Image = "memory.lime"
	r.Method = "linux-proc-kcore"
	r.Source = kcorePath
	r.Gaps = gaps
	r.Notes = append(r.Notes,
		"LiME v1 image (magic 0x4C694D45, little-endian, 32-byte range headers). Readable by Volatility 3 LimeLayer, Volatility 2 and other LiME-compatible tools.",
		"Ranges come from /proc/iomem System RAM intersected with /proc/kcore PT_LOAD physical segments, the same method used by AVML. Unmapped gaps are recorded here and omitted from the image.",
		"SHA-256 is the authoritative hash. SHA-1 and MD5 are recorded only for interoperability with tools that still expect them.",
		"Order of volatility follows RFC 3227: memory is acquired before filesystem artifacts. ISO/IEC 27037 acquisition documentation is this record plus the signed collection record.",
	)
	return nil
}

func acquireExternal(ctx context.Context, o MemoryOptions, tool string, r *MemoryRecord) error {
	toolPath := tool
	if !filepath.IsAbs(tool) {
		p, e := exec.LookPath(tool)
		if e != nil {
			return fmt.Errorf("memory tool: %w", e)
		}
		toolPath = p
	}
	if sum, e := fileSHA256(toolPath); e == nil {
		r.ToolSHA256 = sum
	} else {
		r.Issues = append(r.Issues, Issue{Source: toolPath, Reason: "tool binary hash unavailable: " + e.Error()})
	}
	replaced := false
	args := make([]string, len(o.ToolArgs))
	dest := filepath.Join(o.Dir, "memory.bin")
	for i, a := range o.ToolArgs {
		if strings.Contains(a, "{output}") {
			args[i] = strings.ReplaceAll(a, "{output}", dest)
			replaced = true
		} else {
			args[i] = a
		}
	}
	if !replaced {
		return errors.New("memory tool arguments must include {output}")
	}
	need, extra := o.Limit, o.Reserve
	if need == 0 {
		need, extra = o.Reserve, 0
	}
	if e := ensureSpace(o.Dir, need, extra); e != nil {
		return e
	}
	cmd := exec.CommandContext(ctx, toolPath, args...)
	buf := &cappedBuffer{limit: toolOutputMax}
	cmd.Stdout = buf
	cmd.Stderr = buf
	if e := cmd.Run(); e != nil {
		os.Remove(dest)
		msg := strings.TrimSpace(buf.String())
		if msg != "" {
			return fmt.Errorf("memory tool failed: %w: %s", e, msg)
		}
		return fmt.Errorf("memory tool failed: %w", e)
	}
	r.ToolOutput = buf.String()
	format, ranges, bytes, e := inspectImage(dest)
	if e != nil {
		os.Remove(dest)
		return e
	}
	name := "memory.raw"
	if format == "lime" {
		name = "memory.lime"
	}
	finalPath := filepath.Join(o.Dir, name)
	if e = os.Rename(dest, finalPath); e != nil {
		os.Remove(dest)
		return e
	}
	if o.Limit > 0 {
		st, e := os.Stat(finalPath)
		if e != nil {
			os.Remove(finalPath)
			return e
		}
		if st.Size() > o.Limit {
			os.Remove(finalPath)
			return fmt.Errorf("memory image exceeds --memory-limit")
		}
	}
	sha256sum, sha1sum, md5sum, size, e := hashFile(finalPath)
	if e != nil {
		os.Remove(finalPath)
		return e
	}
	r.SHA256, r.SHA1, r.MD5 = sha256sum, sha1sum, md5sum
	r.ImageSize = size
	r.Format = format
	r.Image = name
	r.Method = "external-tool"
	r.Source = toolPath
	r.Ranges = ranges
	r.Bytes = bytes
	r.Notes = append(r.Notes, "Image produced by an external acquisition tool. The tool binary hash is recorded; its behavior is outside k957. Raw images have no physical map: the single range starts at address 0.")
	return nil
}

var executablePath = os.Executable

func findBundledWinPmem() string {
	exe, e := executablePath()
	if e != nil {
		return ""
	}
	dir := filepath.Dir(exe)
	for _, d := range []string{dir, filepath.Join(dir, "tools")} {
		matches, _ := filepath.Glob(filepath.Join(d, "winpmem*.exe"))
		if len(matches) == 1 {
			return matches[0]
		}
	}
	return ""
}

func ensureSpace(dir string, need, reserve int64) error {
	if need < 0 || reserve < 0 || need > int64(^uint64(0)>>1)-reserve {
		return errors.New("capacity request outside supported range")
	}
	sample, e := probeVolume(dir)
	if e != nil {
		return fmt.Errorf("destination capacity unknown: %w", e)
	}
	if sample.Available < need+reserve {
		return fmt.Errorf("insufficient space: need %d bytes plus %d reserve, %d available", need, reserve, sample.Available)
	}
	return nil
}

func fileSHA256(path string) (string, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	return sha256Reader(f)
}

func sha256Reader(r io.Reader) (string, error) {
	h := sha256.New()
	if _, e := io.Copy(h, r); e != nil {
		return "", e
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func hashFile(path string) (string, string, string, int64, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", "", "", 0, e
	}
	defer f.Close()
	return hashReader(f)
}

func hashReader(r io.Reader) (string, string, string, int64, error) {
	h256, h1, hmd5 := sha256.New(), sha1.New(), md5.New()
	n, e := io.Copy(io.MultiWriter(h256, h1, hmd5), r)
	if e != nil {
		return "", "", "", 0, e
	}
	return hex.EncodeToString(h256.Sum(nil)), hex.EncodeToString(h1.Sum(nil)), hex.EncodeToString(hmd5.Sum(nil)), n, nil
}

// ParseLime walks a LiME image, checks every range header and length, and
// returns the stored ranges. Payload bytes are not retained.
func ParseLime(r io.Reader) ([]MemoryRange, error) {
	var ranges []MemoryRange
	var prev uint64
	have := false
	for {
		hdr := make([]byte, limeHeaderSize)
		_, e := io.ReadFull(r, hdr)
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, errors.New("truncated lime header")
		}
		if binary.LittleEndian.Uint32(hdr[0:4]) != limeMagic || binary.LittleEndian.Uint32(hdr[4:8]) != limeVersion {
			return nil, errors.New("invalid lime header")
		}
		start := binary.LittleEndian.Uint64(hdr[8:16])
		last := binary.LittleEndian.Uint64(hdr[16:24])
		if last < start {
			return nil, errors.New("invalid lime range")
		}
		size := last - start + 1
		if have && start < prev {
			return nil, errors.New("overlapping lime ranges")
		}
		if e = discardExact(r, size); e != nil {
			return nil, fmt.Errorf("truncated lime range at %#x: %w", start, e)
		}
		ranges = append(ranges, MemoryRange{Start: start, Size: size})
		prev = last + 1
		have = true
		if len(ranges) > 100000 {
			return nil, errors.New("too many lime ranges")
		}
	}
	if len(ranges) == 0 {
		return nil, errors.New("empty lime image")
	}
	return ranges, nil
}

func discardExact(r io.Reader, n uint64) error {
	buf := make([]byte, memoryBlock)
	var done uint64
	for done < n {
		chunk := buf[:min(uint64(len(buf)), n-done)]
		if _, e := io.ReadFull(r, chunk); e != nil {
			return e
		}
		done += uint64(len(chunk))
	}
	return nil
}

func inspectImage(path string) (format string, ranges []MemoryRange, bytes uint64, err error) {
	f, e := os.Open(path)
	if e != nil {
		return "", nil, 0, e
	}
	defer f.Close()
	hdr := make([]byte, 4)
	n, e := io.ReadFull(f, hdr)
	if e != nil && e != io.ErrUnexpectedEOF {
		return "", nil, 0, e
	}
	if n == 4 && binary.LittleEndian.Uint32(hdr) == limeMagic {
		if _, e = f.Seek(0, io.SeekStart); e != nil {
			return "", nil, 0, e
		}
		ranges, e = ParseLime(f)
		if e != nil {
			return "", nil, 0, e
		}
		var total uint64
		for _, rg := range ranges {
			total += rg.Size
		}
		return "lime", ranges, total, nil
	}
	st, e := f.Stat()
	if e != nil {
		return "", nil, 0, e
	}
	if st.Size() == 0 {
		return "", nil, 0, errors.New("memory tool wrote an empty image")
	}
	return "raw", []MemoryRange{{Start: 0, Size: uint64(st.Size())}}, uint64(st.Size()), nil
}
