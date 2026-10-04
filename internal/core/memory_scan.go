package core

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	memoryHitTotal = 500
	memoryURLLimit = 50
	memoryExcerpt  = 160
)

// memoryWindow is the scan block size. Tests may lower it.
var memoryWindow = 1 << 20

// MemoryHit is one literal match inside a memory image.
type MemoryHit struct {
	Rule        string `json:"rule"`
	Description string `json:"description"`
	Physical    uint64 `json:"physical"`
	Encoding    string `json:"encoding"`
	Excerpt     string `json:"excerpt"`
}

// MemoryAnalysis describes a full-image scan and its report preview.
type MemoryAnalysis struct {
	Kernel              *MemorySuite        `json:"kernel_examination,omitempty"`
	Results             *MemoryResults      `json:"results,omitempty"`
	Evidence            string              `json:"evidence,omitempty"`
	Source              string              `json:"source"`
	Format              string              `json:"format"`
	SHA256              string              `json:"sha256,omitempty"`
	Bytes               uint64              `json:"bytes"`
	Ranges              int                 `json:"ranges"`
	ZeroPages           int                 `json:"zero_pages"`
	UnreadablePages     int                 `json:"unreadable_pages,omitempty"`
	KernelBanner        string              `json:"kernel_banner,omitempty"`
	Hits                []MemoryHit         `json:"hits"`
	URLs                []string            `json:"urls,omitempty"`
	Observations        []MemoryObservation `json:"observations,omitempty"`
	ObservationsLimited bool                `json:"observations_limited,omitempty"`
	Limited             bool                `json:"limited"`
	Volatility          []string            `json:"volatility"`
	Notes               []string            `json:"notes"`
}

func limeCandidate(f *zip.File, source string) bool {
	if strings.EqualFold(filepath.Ext(source), ".lime") {
		return true
	}
	if f == nil {
		return false
	}
	r, e := f.Open()
	if e != nil {
		return false
	}
	defer r.Close()
	var b [4]byte
	n, _ := io.ReadFull(r, b[:])
	return n == 4 && binary.LittleEndian.Uint32(b[:]) == limeMagic
}

func scanPackageMemory(f *zip.File, it Item, rules []Rule) (MemoryAnalysis, error) {
	return scanPackageMemoryContext(context.Background(), f, it, rules)
}

func scanPackageMemoryContext(ctx context.Context, f *zip.File, it Item, rules []Rule) (MemoryAnalysis, error) {
	r, e := f.Open()
	if e != nil {
		return MemoryAnalysis{}, e
	}
	defer r.Close()
	h := sha256.New()
	m, e := scanMemoryContext(ctx, io.TeeReader(contextReader{ctx, r}, h), rules)
	if e != nil {
		return m, e
	}
	if hex.EncodeToString(h.Sum(nil)) != it.SHA256 {
		return MemoryAnalysis{}, errors.New("memory examination input differs from verified object SHA-256")
	}
	m.Evidence = it.ID
	m.Source = it.Source
	m.SHA256 = it.SHA256
	m.Volatility = volatilityCommands(m.Format, it.Source, runtime.GOOS, "")
	return m, nil
}

func scanMemoryFile(path string, rules []Rule) (MemoryAnalysis, error) {
	return scanMemoryFileProgress(path, rules, nil, 0)
}

func scanMemoryFileProgress(path string, rules []Rule, meter *verifyMeter, planned int64) (MemoryAnalysis, error) {
	f, e := os.Open(path)
	if e != nil {
		return MemoryAnalysis{}, e
	}
	defer f.Close()
	var r io.Reader = f
	if meter != nil {
		r = meter.reader(f, filepath.Base(path), planned)
	}
	m, e := scanMemory(r, rules)
	if e != nil {
		return m, e
	}
	if meter != nil {
		meter.finish(planned)
	}
	return m, nil
}

func scanMemory(r io.Reader, rules []Rule) (MemoryAnalysis, error) {
	hdr := make([]byte, 4)
	n, e := io.ReadFull(r, hdr)
	if e != nil && e != io.ErrUnexpectedEOF && e != io.EOF {
		return MemoryAnalysis{}, e
	}
	rest := io.MultiReader(bytes.NewReader(hdr[:n]), r)
	if n == 4 && binary.LittleEndian.Uint32(hdr) == limeMagic {
		return scanLime(rest, rules)
	}
	return scanRaw(rest, rules)
}

func scanLime(r io.Reader, rules []Rule) (MemoryAnalysis, error) {
	return scanLimeWithScanner(r, newMemScan(rules))
}

func scanLimeWithScanner(r io.Reader, s *memScan) (MemoryAnalysis, error) {
	ranges := 0
	var total uint64
	for {
		hdr := make([]byte, limeHeaderSize)
		_, e := io.ReadFull(r, hdr)
		if e == io.EOF {
			break
		}
		if e != nil {
			return MemoryAnalysis{}, errors.New("truncated lime header")
		}
		if binary.LittleEndian.Uint32(hdr[0:4]) != limeMagic || binary.LittleEndian.Uint32(hdr[4:8]) != limeVersion {
			return MemoryAnalysis{}, errors.New("invalid lime header")
		}
		start := binary.LittleEndian.Uint64(hdr[8:16])
		last := binary.LittleEndian.Uint64(hdr[16:24])
		if last < start || last-start == math.MaxUint64 {
			return MemoryAnalysis{}, errors.New("invalid lime range")
		}
		size := last - start + 1
		if e = s.scanRange(r, size, start); e != nil {
			return MemoryAnalysis{}, e
		}
		ranges++
		if total > math.MaxUint64-size {
			return MemoryAnalysis{}, errors.New("memory byte count overflow")
		}
		total += size
	}
	if ranges == 0 {
		return MemoryAnalysis{}, errors.New("empty lime image")
	}
	return s.finish(ranges, total, "lime"), nil
}

func scanRaw(r io.Reader, rules []Rule) (MemoryAnalysis, error) {
	return scanRawWithScanner(r, newMemScan(rules))
}

func scanRawWithScanner(r io.Reader, s *memScan) (MemoryAnalysis, error) {
	buf := make([]byte, memoryWindow)
	var off uint64
	for {
		n, e := r.Read(buf)
		if n > 0 {
			s.push(off, buf[:n])
			if s.writeErr != nil {
				return MemoryAnalysis{}, s.writeErr
			}
			off += uint64(n)
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return MemoryAnalysis{}, e
		}
	}
	if off == 0 {
		return MemoryAnalysis{}, errors.New("empty raw memory image")
	}
	s.finishStrings()
	m := s.finish(1, off, "raw")
	m.Notes = append(m.Notes, "Raw image: addresses are offsets from the start of the file, not proven physical addresses.")
	return m, nil
}

type preparedRule struct {
	id, description string
	ascii, utf16    []byte
}

type memScan struct {
	asciiURL        memoryURLState
	utf16URLs       [2]memoryURLState
	asciiString     memoryStringState
	utf16Strings    [2]memoryStringState
	previousByte    byte
	hasPreviousByte bool
	resultWriter    *memoryResultWriter
	writeErr        error
	fresh           uint64
	priorTail       int
	rules           []preparedRule
	hits            []MemoryHit
	seen            map[string]bool
	counts          map[string]int
	urls            []string
	urlSeen         map[string]bool
	banner          string
	zeroPages       int
	page            []byte
	pageN           int
	tail            []byte
	folded          []byte
	limited         bool
	obsLimited      bool
	overlap         int
	observations    []MemoryObservation
	obsSeen         map[string]uint64
	obsCounts       map[string]int
}

func newMemScan(rules []Rule) *memScan {
	s := &memScan{
		hits: []MemoryHit{}, seen: map[string]bool{}, counts: map[string]int{}, urlSeen: map[string]bool{},
		observations: []MemoryObservation{}, obsSeen: map[string]uint64{}, obsCounts: map[string]int{},
		page: make([]byte, memoryPage), overlap: 320,
	}
	for _, r := range rules {
		if r.Contains == "" {
			continue
		}
		ascii := []byte(strings.ToLower(r.Contains))
		s.rules = append(s.rules, preparedRule{id: r.ID, description: r.Description, ascii: ascii, utf16: utf16LE(ascii)})
		if len(ascii) > s.overlap {
			s.overlap = len(ascii)
		}
		if len(ascii)*2 > s.overlap {
			s.overlap = len(ascii) * 2
		}
	}
	// Headers and /proc text rows can sit across a chunk boundary.
	if s.overlap < 1024 {
		s.overlap = 1024
	}
	return s
}

func utf16LE(ascii []byte) []byte {
	out := make([]byte, len(ascii)*2)
	for i, b := range ascii {
		out[i*2] = b
	}
	return out
}

func (s *memScan) scanRange(r io.Reader, size, base uint64) error {
	s.finishStrings()
	defer s.finishStrings()
	s.tail = nil
	var consumed uint64
	buf := make([]byte, memoryWindow)
	for consumed < size {
		n := int(min(uint64(len(buf)), size-consumed))
		if _, e := io.ReadFull(r, buf[:n]); e != nil {
			return fmt.Errorf("truncated memory range at %#x: %w", base, e)
		}
		s.push(base+consumed, buf[:n])
		if s.writeErr != nil {
			return s.writeErr
		}
		consumed += uint64(n)
	}
	s.tail = nil
	return nil
}

// push scans one contiguous chunk. A short tail is retained so a match that
// crosses a chunk boundary is reported once, at the earlier address.
func (s *memScan) push(base uint64, p []byte) {
	s.scanStrings(base, p)
	s.addZeros(p)
	window := p
	phys := base
	if len(s.tail) > 0 {
		window = append(append([]byte{}, s.tail...), p...)
		phys = base - uint64(len(s.tail))
	}
	s.fresh = base
	s.priorTail = len(s.tail)
	s.seen = map[string]bool{}
	for key, address := range s.obsSeen {
		if address < phys {
			delete(s.obsSeen, key)
		}
	}
	s.search(phys, window)
	if s.overlap <= 0 || len(window) == 0 {
		s.tail = nil
		return
	}
	keep := window
	if len(keep) > s.overlap {
		keep = keep[len(keep)-s.overlap:]
	}
	s.tail = append([]byte{}, keep...)
}

func (s *memScan) addZeros(p []byte) {
	for len(p) > 0 {
		n := copy(s.page[s.pageN:], p)
		s.pageN += n
		p = p[n:]
		if s.pageN == memoryPage {
			if isZero(s.page) {
				s.zeroPages++
			}
			s.pageN = 0
		}
	}
}

func isZero(p []byte) bool {
	for _, b := range p {
		if b != 0 {
			return false
		}
	}
	return true
}

func (s *memScan) search(phys uint64, data []byte) {
	// bytes.ToLower is not usable here. Invalid UTF-8, which is normal in a
	// memory image, becomes U+FFFD and the copy is longer than the image, so
	// an index into it is not a physical offset.
	lower := s.asciiFold(data)
	if s.banner == "" {
		if b := findBannerFolded(data, lower); b != "" {
			s.banner = b
		}
	}
	if s.resultWriter == nil {
		s.collectURLsAt(phys, data, lower)
	}
	s.observe(phys, data)
	for _, rule := range s.rules {
		from := 0
		for {
			i := bytes.Index(lower[from:], rule.ascii)
			if i < 0 {
				break
			}
			i += from
			if i+len(rule.ascii) > s.priorTail {
				s.addHit(rule, phys+uint64(i), "ascii", excerptAt(data, i, len(rule.ascii)))
			}
			from = i + 1
		}
		from = 0
		for {
			i := indexUTF16Fold(data[from:], rule.utf16)
			if i < 0 {
				break
			}
			i += from
			if i+len(rule.utf16) > s.priorTail {
				s.addHit(rule, phys+uint64(i), "utf-16le", excerptAt(data, i, len(rule.utf16)))
			}
			from = i + 2
		}
	}
}

func (s *memScan) addHit(rule preparedRule, phys uint64, encoding, excerpt string) {
	key := rule.id + ":" + encoding + ":" + fmt.Sprintf("%x", phys)
	if s.seen[key] {
		return
	}
	s.seen[key] = true
	s.counts[rule.id]++
	h := MemoryHit{Rule: rule.id, Description: rule.description, Physical: phys, Encoding: encoding, Excerpt: excerpt}
	if s.resultWriter != nil {
		s.emit(MemoryResult{Kind: "literal", Physical: phys, Rule: rule.id, Encoding: encoding, Detail: excerpt})
		s.resultWriter.result.Hits++
	}
	if s.resultWriter == nil || len(s.hits) < memoryHitTotal {
		s.hits = append(s.hits, h)
	}
}

func excerptAt(data []byte, at, n int) string {
	if at < 0 || n < 0 || at > len(data) {
		return ""
	}
	end := at + n + 40
	if end > len(data) || end < at {
		end = len(data)
	}
	part := data[at:end]
	if !utf8.Valid(part) {
		part = []byte(strings.ToValidUTF8(string(part), "."))
	}
	out := strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return ' '
		}
		return r
	}, string(part))
	if len(out) > memoryExcerpt {
		out = out[:memoryExcerpt]
	}
	return out
}

func findBanner(data []byte) string {
	return findBannerFolded(data, asciiFoldInto(nil, data))
}

func findBannerFolded(data, lower []byte) string {
	if len(lower) != len(data) {
		return ""
	}
	needle := []byte("linux version ")
	from := 0
	for from < len(lower) {
		rel := bytes.Index(lower[from:], needle)
		if rel < 0 {
			return ""
		}
		i := from + rel
		if text := kernelBannerAt(data, i); text != "" {
			return text
		}
		from = i + len(needle)
	}
	return ""
}

// kernelBannerAt accepts "Linux version <digit>..." only. The collector's own
// strings can contain the words "linux version" beside scan notes; those are
// not a kernel banner.
func kernelBannerAt(data []byte, i int) string {
	end := i
	limit := len(data)
	if max := i + 300; max < limit {
		limit = max
	}
	for end < limit && data[end] != '\n' && data[end] != 0 {
		end++
	}
	if end < i || end > len(data) || !utf8.Valid(data[i:end]) {
		return ""
	}
	text := strings.TrimSpace(string(data[i:end]))
	const prefix = "linux version "
	if len(text) <= len(prefix) || !strings.HasPrefix(strings.ToLower(text), prefix) {
		return ""
	}
	version := text[len(prefix)]
	if version < '0' || version > '9' {
		return ""
	}
	return text
}

// asciiFold maps A-Z to a-z and leaves every other byte in place, so the
// result has the same indexes as src.
func (s *memScan) asciiFold(src []byte) []byte {
	s.folded = asciiFoldInto(s.folded, src)
	return s.folded
}

func asciiFoldInto(dst, src []byte) []byte {
	if cap(dst) < len(src) {
		dst = make([]byte, len(src))
	}
	dst = dst[:len(src)]
	for i, b := range src {
		if b >= 'A' && b <= 'Z' {
			b += 'a' - 'A'
		}
		dst[i] = b
	}
	return dst
}

func (s *memScan) collectURLs(data []byte) {
	s.collectURLsFolded(data, asciiFoldInto(nil, data))
}

func (s *memScan) collectURLsFolded(data, lower []byte) { s.collectURLsAt(0, data, lower) }

func (s *memScan) collectURLsAt(phys uint64, data, lower []byte) {
	if len(lower) != len(data) {
		return
	}
	for _, prefix := range []string{"https://", "http://"} {
		from := 0
		for {
			i := bytes.Index(lower[from:], []byte(prefix))
			if i < 0 {
				break
			}
			i += from
			if i > len(data) {
				break
			}
			j := i
			for j < len(data) && j-i < 200 && data[j] > 32 && data[j] < 127 {
				j++
			}
			if j-i > len(prefix)+3 {
				u := string(data[i:j])
				if s.resultWriter != nil && i >= s.priorTail {
					s.emit(MemoryResult{Kind: "url", Physical: phys + uint64(i), Detail: u})
					s.resultWriter.result.URLs++
				}
				if (s.resultWriter == nil || len(s.urls) < memoryURLLimit) && !s.urlSeen[u] {
					s.urlSeen[u] = true
					s.urls = append(s.urls, u)
				}
			}
			from = i + len(prefix)
		}
	}
}

func indexUTF16Fold(data, needle []byte) int {
	if len(needle) < 2 || len(needle)%2 != 0 || len(data) < len(needle) {
		return -1
	}
	for i := 0; i+len(needle) <= len(data); i++ {
		if matchUTF16Fold(data[i:i+len(needle)], needle) {
			return i
		}
	}
	return -1
}

func matchUTF16Fold(data, needle []byte) bool {
	for i := 0; i < len(needle); i += 2 {
		if data[i+1] != needle[i+1] {
			return false
		}
		b := data[i]
		if b >= 'A' && b <= 'Z' {
			b += 'a' - 'A'
		}
		if b != needle[i] {
			return false
		}
	}
	return true
}

func (s *memScan) finish(ranges int, total uint64, format string) MemoryAnalysis {
	m := MemoryAnalysis{
		Format: format, Bytes: total, Ranges: ranges, ZeroPages: s.zeroPages, KernelBanner: s.banner,
		Hits: s.hits, URLs: s.urls, Limited: s.limited,
		Observations: s.observations, ObservationsLimited: s.obsLimited,
		Notes: []string{
			"Symbol-free readings: executable headers, passwd-style accounts, /proc/net text rows, module vermagic, NUL-separated command lines, selected environment keys, and PEM headers. All image bytes are scanned; repeated observations at different addresses are retained in the complete results.",
			"These readings are presence in the image. They are not a kernel task list, socket-object walk, or proof that a program was running at acquisition.",
			"Structured observations omit password hashes, secret environment values, and PEM private-key bodies. Complete printable-string sidecars may contain sensitive material and are private examination outputs.",
			"Zero pages include memory that was unreadable at acquisition and stored as zeros.",
		},
	}
	m.Volatility = volatilityCommands(format, "memory-image", runtime.GOOS, "")
	return m
}

func volatilityCommands(format, image, osName, release string) []string {
	cmds := []string{}
	if format == "lime" {
		cmds = append(cmds, "LiME image: Volatility 3 selects LimeLayer from magic 0x4C694D45. Pass the file as-is; do not convert it to raw first.")
	}
	q := image
	cmds = append(cmds, "vol -f "+q+" banners")
	switch osName {
	case "linux":
		cmds = append(cmds,
			"vol -f "+q+" linux.pslist",
			"vol -f "+q+" linux.bash",
			"vol -f "+q+" linux.lsmod",
			"vol -f "+q+" linux.netstat",
		)
		if release != "" {
			cmds = append(cmds, "Symbol bundle required for kernel "+release+" (dwarf2json from the matching vmlinux).")
		}
	case "windows":
		cmds = append(cmds,
			"vol -f "+q+" windows.pslist",
			"vol -f "+q+" windows.cmdline",
			"vol -f "+q+" windows.netstat",
		)
	case "darwin":
		cmds = append(cmds, "vol -f "+q+" mac.pslist")
	}
	return cmds
}

func annotateMemory(m *MemoryAnalysis, rec *MemoryRecord) {
	if rec == nil {
		return
	}
	m.SHA256 = rec.SHA256
	for _, rg := range rec.Ranges {
		m.UnreadablePages += rg.UnreadablePages
	}
	m.Volatility = volatilityCommands(rec.Format, rec.Image, rec.OS, rec.KernelRelease)
}

func addMemoryFindings(a *Analysis, m MemoryAnalysis) {
	for _, h := range m.Hits {
		ev := m.Evidence
		if ev == "" {
			ev = "MEMORY"
		}
		excerpt := fmt.Sprintf("physical %#x %s: %s", h.Physical, h.Encoding, h.Excerpt)
		if len(excerpt) > 400 {
			excerpt = excerpt[:400]
		}
		appendFinding(a, Finding{Rule: h.Rule, Description: h.Description, Evidence: ev, Source: m.Source, Excerpt: excerpt, Review: "unreviewed"})
	}
}

const memoryNote = "Memory images are scanned without kernel symbols: literal rules, a Linux version banner, URL indicators, executable headers, passwd-style accounts, /proc/net text, module vermagic, command lines, and selected environment keys. This is not a kernel task or socket walk. Structured observations omit password hashes and secret values; complete printable-string sidecars can contain sensitive material. Zero pages include memory stored as zeros because it was unreadable."

func exportMemory(a Analysis, out string) error {
	return exportMemoryContext(context.Background(), a, out)
}
func exportMemoryContext(ctx context.Context, a Analysis, out string) error {
	if len(a.Memories) == 0 {
		return nil
	}
	rows := [][]string{}
	for _, m := range a.Memories {
		rows = append(rows, []string{m.Evidence, m.Source, m.Format, m.SHA256, strconv.FormatUint(m.Bytes, 10), strconv.Itoa(m.Ranges), strconv.Itoa(m.ZeroPages), strconv.Itoa(m.UnreadablePages), m.KernelBanner, strconv.FormatBool(m.Limited)})
		full := []string{"", "", "", "", ""}
		if m.Results != nil {
			full = []string{m.Results.Name, strconv.FormatInt(m.Results.Hits, 10), strconv.FormatInt(m.Results.Observations, 10), strconv.FormatInt(m.Results.URLs, 10), strconv.FormatInt(m.Results.Strings, 10)}
		}
		rows[len(rows)-1] = append(rows[len(rows)-1], full...)

	}
	if e := sharedCSV(filepath.Join(out, "memory.csv"), []string{"evidence", "source", "format", "sha256", "bytes", "ranges", "zero_pages", "unreadable_pages", "kernel_banner", "limited", "results_file", "full_hits", "full_observations", "full_url_tokens", "full_string_segments"}, rows); e != nil {
		return e
	}
	if e := writeCSVNew(filepath.Join(out, "memory-observations.csv"), func(c *csv.Writer) error {
		if e := c.Write([]string{"evidence", "source", "kind", "physical", "detail"}); e != nil {
			return e
		}
		for _, m := range a.Memories {
			if m.Results != nil && m.Results.path != "" {
				if e := visitMemoryResults(ctx, m.Results, func(r MemoryResult) error {
					if r.Kind == "literal" || r.Kind == "string" || r.Kind == "url" {
						return nil
					}
					return c.Write([]string{m.Evidence, m.Source, r.Kind, fmt.Sprintf("%#x", r.Physical), csvSafe(r.Detail)})
				}); e != nil {
					return e
				}
			} else {
				for _, o := range m.Observations {
					if e := c.Write([]string{m.Evidence, m.Source, o.Kind, fmt.Sprintf("%#x", o.Physical), csvSafe(o.Detail)}); e != nil {
						return e
					}
				}
			}
		}
		return nil
	}); e != nil {
		return e
	}
	return writeCSVNew(filepath.Join(out, "memory-hits.csv"), func(c *csv.Writer) error {
		if e := c.Write([]string{"evidence", "rule", "description", "physical", "encoding", "excerpt"}); e != nil {
			return e
		}
		descriptions := map[string]string{}
		for _, r := range a.Rules {
			descriptions[r.ID] = r.Description
		}
		for _, m := range a.Memories {
			if m.Results != nil && m.Results.path != "" {
				if e := visitMemoryResults(ctx, m.Results, func(r MemoryResult) error {
					if r.Kind != "literal" {
						return nil
					}
					return c.Write([]string{m.Evidence, csvSafe(r.Rule), csvSafe(descriptions[r.Rule]), fmt.Sprintf("%#x", r.Physical), r.Encoding, csvSafe(r.Detail)})
				}); e != nil {
					return e
				}
			} else {
				for _, h := range m.Hits {
					if e := c.Write([]string{m.Evidence, csvSafe(h.Rule), csvSafe(h.Description), fmt.Sprintf("%#x", h.Physical), h.Encoding, csvSafe(h.Excerpt)}); e != nil {
						return e
					}
				}
			}
		}
		return nil
	})
}

func rememberMemory(a *Analysis, m MemoryAnalysis) {
	a.Memories = append(a.Memories, m)
	before := len(a.Findings)
	addMemoryFindings(a, m)
	for i := before; i < len(a.Findings); i++ {
		a.Findings[i].ID = findingID(a.EvidenceDigest, a.Findings[i])
	}
	for _, n := range a.Notes {
		if n == memoryNote {
			return
		}
	}
	a.Notes = append(a.Notes, memoryNote)
}

func visitMemoryResults(ctx context.Context, result *MemoryResults, visit func(MemoryResult) error) error {
	f, e := os.Open(result.path)
	if e != nil {
		return e
	}
	defer f.Close()
	h := sha256.New()
	d := json.NewDecoder(io.TeeReader(contextReader{ctx: ctx, r: f}, h))
	for {
		var r MemoryResult
		e = d.Decode(&r)
		if e == io.EOF {
			break
		}
		if e != nil {
			return e
		}
		if e = visit(r); e != nil {
			return e
		}
	}
	if hex.EncodeToString(h.Sum(nil)) != result.SHA256 {
		return errors.New("complete memory result file changed")
	}
	return nil
}
