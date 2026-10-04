package core

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
)

// MemoryResults binds the complete disk-backed scan; slices in MemoryAnalysis
// are previews when this receipt exists. No row or image-size cap applies.
type MemoryResults struct {
	Strings      int64  `json:"strings"`
	Name         string `json:"name"`
	SHA256       string `json:"sha256"`
	Bytes        int64  `json:"bytes"`
	Rows         int64  `json:"rows"`
	Hits         int64  `json:"hits"`
	Observations int64  `json:"observations"`
	URLs         int64  `json:"urls"`
	path         string
}
type MemoryResult struct {
	Continuation bool   `json:"continuation,omitempty"`
	Continues    bool   `json:"continues,omitempty"`
	Kind         string `json:"kind"`
	Physical     uint64 `json:"physical"`
	Rule         string `json:"rule,omitempty"`
	Encoding     string `json:"encoding,omitempty"`
	Detail       string `json:"detail"`
}
type memoryWorkspaceKey struct{}

// WithMemoryWorkspace selects a private existing directory for complete results.
// The caller owns its lifetime through export. It never stages the image itself.
func WithMemoryWorkspace(ctx context.Context, dir string) context.Context {
	return context.WithValue(ctx, memoryWorkspaceKey{}, dir)
}

type memoryResultWriter struct {
	file    *os.File
	buffer  *bufio.Writer
	encoder *json.Encoder
	digest  hash.Hash
	result  MemoryResults
}

func (s *memScan) emit(row MemoryResult) {
	if s.writeErr != nil {
		return
	}
	s.writeErr = s.resultWriter.encoder.Encode(row)
	if s.writeErr == nil {
		s.resultWriter.result.Rows++
	}
}
func scanMemoryContext(ctx context.Context, reader io.Reader, rules []Rule) (m MemoryAnalysis, err error) {
	if e := ctx.Err(); e != nil {
		return m, e
	}
	reader = contextReader{ctx: ctx, r: reader}
	workspace, _ := ctx.Value(memoryWorkspaceKey{}).(string)
	if workspace == "" {
		return scanMemory(reader, rules)
	}
	f, e := os.CreateTemp(workspace, "memory-results-*.jsonl")
	if e != nil {
		return m, e
	}
	good := false
	defer func() {
		f.Close()
		if !good {
			os.Remove(f.Name())
		}
	}()
	digest := sha256.New()
	buffer := bufio.NewWriterSize(io.MultiWriter(f, digest), 256<<10)
	writer := &memoryResultWriter{file: f, buffer: buffer, encoder: json.NewEncoder(buffer), digest: digest,
		result: MemoryResults{Name: filepath.Base(f.Name()), path: f.Name()}}
	scanner := newMemScan(rules)
	scanner.resultWriter = writer
	var hdr [4]byte
	n, e := io.ReadFull(reader, hdr[:])
	if e != nil && e != io.EOF && e != io.ErrUnexpectedEOF {
		return m, e
	}
	r := io.MultiReader(bytes.NewReader(hdr[:n]), reader)
	if n == 4 && hdr == [4]byte{0x45, 0x4d, 0x69, 0x4c} {
		m, err = scanLimeWithScanner(r, scanner)
	} else {
		m, err = scanRawWithScanner(r, scanner)
	}
	if err != nil {
		return MemoryAnalysis{}, err
	}
	if err = scanner.writeErr; err != nil {
		return MemoryAnalysis{}, err
	}
	if err = ctx.Err(); err != nil {
		return MemoryAnalysis{}, err
	}
	if err = buffer.Flush(); err != nil {
		return MemoryAnalysis{}, err
	}
	if err = f.Sync(); err != nil {
		return MemoryAnalysis{}, err
	}
	st, err := f.Stat()
	if err != nil {
		return MemoryAnalysis{}, err
	}
	if err = f.Close(); err != nil {
		return MemoryAnalysis{}, err
	}
	writer.result.Bytes = st.Size()
	writer.result.SHA256 = hex.EncodeToString(digest.Sum(nil))
	m.Results = &writer.result
	m.Notes = append(m.Notes, "Complete memory results are in "+writer.result.Name+". Hits, observations and URLs in analysis.json and visual reports are previews; disk-backed results have no count cap. Source addresses are retained. Printable ASCII and UTF-16LE ASCII strings are retained in reconstructable segments, including potentially sensitive text. Private results must be reviewed before disclosure. Disk write errors fail analysis.")
	good = true
	return m, nil
}
func copyDerivedFile(ctx context.Context, source, target, expected string) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	good := false
	defer func() {
		out.Close()
		if !good {
			os.Remove(target)
		}
	}()
	h := sha256.New()
	if _, err = io.Copy(io.MultiWriter(out, h), contextReader{ctx: ctx, r: in}); err != nil {
		return err
	}
	if expected != "" && hex.EncodeToString(h.Sum(nil)) != expected {
		return fmt.Errorf("derived result differs from recorded SHA-256")
	}
	if err = out.Sync(); err != nil {
		return err
	}
	if err = out.Close(); err != nil {
		return err
	}
	good = true
	return nil
}
func exportMemoryResults(ctx context.Context, a Analysis, out string) error {
	for _, m := range a.Memories {
		if m.Results == nil {
			continue
		}
		r := m.Results
		if r.path == "" {
			continue
		} // Loaded analysis retains its receipt; it cannot recreate absent results.
		if !validReportName(r.Name) || filepath.Base(r.Name) != r.Name {
			return fmt.Errorf("invalid memory result name")
		}
		if err := copyDerivedFile(ctx, r.path, filepath.Join(out, r.Name), r.SHA256); err != nil {
			return err
		}
	}
	return nil
}
