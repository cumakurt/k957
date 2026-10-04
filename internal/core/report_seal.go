package core

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const ReportSealSchema = "k957-report-seal/1"
const reportSealManifest = "report.seal.json"
const reportSealSignature = "report.seal.sig"

type ReportFile struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type ReportBinding struct {
	Kind   string `json:"kind"`
	Digest string `json:"digest"`
}

type ReportSeal struct {
	Schema    string          `json:"schema"`
	Version   string          `json:"version"`
	Created   time.Time       `json:"created"`
	PublicKey string          `json:"public_key"`
	Bindings  []ReportBinding `json:"bindings"`
	Files     []ReportFile    `json:"files"`
}

type ReportSealStatus struct {
	Schema         string          `json:"schema"`
	Files          int             `json:"files"`
	ManifestDigest string          `json:"manifest_digest"`
	Signature      string          `json:"signature"`
	Bindings       []ReportBinding `json:"bindings"`
	Note           string          `json:"note"`
}

func reportFiles(ctx context.Context, dir string) ([]ReportFile, error) {
	return reportFilesExcept(ctx, dir, "")
}

func reportFilesExcept(ctx context.Context, dir, exclude string) ([]ReportFile, error) {
	root, e := os.Lstat(dir)
	if e != nil {
		return nil, e
	}
	if !root.IsDir() || root.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("report root must be a directory, not a symlink")
	}
	files := []ReportFile{}
	e = filepath.WalkDir(dir, func(file string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if e := ctx.Err(); e != nil {
			return e
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("symlink in report bundle")
		}
		if entry.IsDir() {
			if exclude != "" && filepath.Clean(file) == filepath.Clean(exclude) {
				return filepath.SkipDir
			}
			return nil
		}
		rel, e := filepath.Rel(dir, file)
		if e != nil {
			return e
		}
		name := filepath.ToSlash(rel)
		if name == reportSealManifest || name == reportSealSignature {
			return nil
		}
		if !validReportName(name) {
			return errors.New("invalid report bundle path")
		}
		info, e := entry.Info()
		if e != nil {
			return e
		}
		if !info.Mode().IsRegular() {
			return errors.New("special file in report bundle")
		}
		sum, e := fileSHA256Progress(file, "", 0, &verifyMeter{ctx: ctx})
		if e != nil {
			return e
		}
		after, e := os.Lstat(file)
		if e != nil {
			return e
		}
		if !os.SameFile(info, after) || info.Size() != after.Size() || !info.ModTime().Equal(after.ModTime()) {
			return errors.New("report changed during hashing")
		}
		files = append(files, ReportFile{Name: name, Size: info.Size(), SHA256: sum})
		return nil
	})
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	return files, e
}

func validReportName(name string) bool {
	return name != "" && len(name) <= 1024 && path.Clean(name) == name && !path.IsAbs(name) && name != "." && name != ".." && !strings.HasPrefix(name, "../") && !strings.ContainsAny(name, "\\\x00\r\n")
}

func reportBindings(dir string) ([]ReportBinding, error) {
	bindings := []ReportBinding{}
	if regularFile(filepath.Join(dir, "analysis.json")) {
		a, e := LoadAnalysis(filepath.Join(dir, "analysis.json"))
		if e != nil {
			return nil, e
		}
		bindings = append(bindings, ReportBinding{Kind: "evidence", Digest: a.EvidenceDigest})
		if a.PackageDigest != "" {
			bindings = append(bindings, ReportBinding{Kind: "package", Digest: a.PackageDigest})
		}
	}
	if regularFile(filepath.Join(dir, "case.json")) {
		var d CaseDossier
		if e := strictJSON(filepath.Join(dir, "case.json"), 32<<20, &d); e != nil {
			return nil, e
		}
		if d.Schema != CaseSchema {
			return nil, errors.New("unsupported case dossier")
		}
		seen := map[string]bool{}
		for _, c := range d.AnalysisCoverage {
			if !validHash(c.Digest) {
				return nil, errors.New("invalid case collection digest")
			}
			if !seen[c.Digest] {
				bindings = append(bindings, ReportBinding{Kind: "collection", Digest: c.Digest})
				seen[c.Digest] = true
			}
		}
	}
	if regularFile(filepath.Join(dir, "shared.json")) {
		body, e := ReadLimited(filepath.Join(dir, "shared.json"), 128<<20)
		if e != nil {
			return nil, e
		}
		var shared SharedReport
		if e := custodyJSON(body, &shared); e != nil {
			return nil, e
		}
		if shared.Schema != shareSchema || !shared.Policy.FreeTextOmitted {
			return nil, errors.New("invalid shared report")
		}
		bindings = append(bindings, ReportBinding{Kind: "shared_projection", Digest: digestJSON(shared)}, ReportBinding{Kind: "disclosure_policy_summary", Digest: digestJSON(shared.Policy)})
	}
	if regularFile(filepath.Join(dir, "assistant.json")) {
		a, e := LoadAssistantResult(filepath.Join(dir, "assistant.json"))
		if e != nil {
			return nil, e
		}
		bindings = append(bindings, ReportBinding{Kind: "case_index", Digest: a.IndexSHA256}, ReportBinding{Kind: "assistant_model", Digest: a.ModelDigest})
	}
	if regularFile(filepath.Join(dir, "selection.json")) {
		var selection CaseSelection
		if e := strictJSON(filepath.Join(dir, "selection.json"), 64<<20, &selection); e != nil {
			return nil, e
		}
		if selection.Schema != "k957-case-selection/1" || !validHash(selection.IndexSHA256) {
			return nil, errors.New("invalid signed selection")
		}
		bindings = append(bindings, ReportBinding{Kind: "case_index", Digest: selection.IndexSHA256})
	}
	return bindings, nil
}

func reportSignatureBytes(body []byte) []byte {
	return append([]byte(ReportSealSchema+"\x00"), body...)
}

// SealReport authenticates a derived report bundle. It does not replace the
// original package/collection signatures or certify the examiner's conclusions.
func SealReport(ctx context.Context, dir, keyPath string) (seal ReportSeal, err error) {
	keyBytes, e := ReadLimited(keyPath, 4096)
	if e != nil {
		return seal, e
	}
	key, e := decodePrivate(keyBytes)
	if e != nil {
		return seal, e
	}
	for _, name := range []string{reportSealManifest, reportSealSignature} {
		if _, e := os.Lstat(filepath.Join(dir, name)); !os.IsNotExist(e) {
			return seal, errors.New("report is already sealed or seal paths are unavailable")
		}
	}
	files, e := reportFiles(ctx, dir)
	if e != nil {
		return seal, e
	}
	if len(files) == 0 {
		return seal, errors.New("empty report bundle")
	}
	bindings, e := reportBindings(dir)
	if e != nil {
		return seal, e
	}
	seal = ReportSeal{Schema: ReportSealSchema, Version: Version, Created: time.Now().UTC(), PublicKey: hex.EncodeToString(key.Public().(ed25519.PublicKey)), Bindings: bindings, Files: files}
	body, e := MarshalJSON(seal)
	if e != nil {
		return seal, e
	}
	if e = ctx.Err(); e != nil {
		return seal, e
	}
	manifest := filepath.Join(dir, reportSealManifest)
	if e = writeReportSealFile(ctx, manifest, body); e != nil {
		return seal, e
	}
	ok := false
	defer func() {
		if !ok {
			os.Remove(manifest)
		}
	}()
	signature := ed25519.Sign(key, reportSignatureBytes(body))
	if e = ctx.Err(); e != nil {
		return seal, e
	}
	if e = writeReportSealFile(ctx, filepath.Join(dir, reportSealSignature), signature); e != nil {
		return seal, e
	}
	ok = true
	return seal, nil
}

func writeReportSealFile(ctx context.Context, name string, body []byte) error {
	return writeFileNew(name, func(out io.Writer) error {
		_, err := io.Copy(out, &contextReader{ctx: ctx, r: bytes.NewReader(body)})
		if err != nil {
			return err
		}
		return ctx.Err()
	})
}

func VerifyReport(ctx context.Context, dir, trustedPath string) (status ReportSealStatus, err error) {
	status.Schema = ReportSealSchema
	body, e := readReportSeal(ctx, filepath.Join(dir, reportSealManifest))
	if e != nil {
		return status, e
	}
	var seal ReportSeal
	if e = custodyJSON(body, &seal); e != nil {
		return status, e
	}
	if e = ctx.Err(); e != nil {
		return status, e
	}
	if seal.Schema != ReportSealSchema || seal.Created.IsZero() || len(seal.Files) == 0 {
		return status, errors.New("invalid report seal bounds")
	}
	pub, e := custodyHex(seal.PublicKey, ed25519.PublicKeySize)
	if e != nil {
		return status, e
	}
	for _, binding := range seal.Bindings {
		if !validHash(binding.Digest) {
			return status, errors.New("invalid report source digest")
		}
	}
	signature, e := ReadLimited(filepath.Join(dir, reportSealSignature), ed25519.SignatureSize)
	if e != nil {
		return status, e
	}
	if !ed25519.Verify(pub, reportSignatureBytes(body), signature) {
		return status, errors.New("report signature verification failed")
	}
	status.Signature = "valid embedded report key; signer not independently trusted"
	if trustedPath != "" {
		trusted, e := loadPublic(trustedPath)
		if e != nil {
			return status, e
		}
		if !ed25519.PublicKey(pub).Equal(trusted) {
			return status, errors.New("report key does not match supplied trusted key")
		}
		status.Signature = "verified against supplied trusted report key"
	}
	actual, e := reportFiles(ctx, dir)
	if e != nil {
		return status, e
	}
	if len(actual) != len(seal.Files) {
		return status, errors.New("report file list differs from seal")
	}
	for i, file := range seal.Files {
		if !validReportName(file.Name) || !validHash(file.SHA256) || file.Size < 0 || file != actual[i] {
			return status, fmt.Errorf("report file integrity failure at entry %d", i+1)
		}
	}
	sum := sha256.Sum256(body)
	status.ManifestDigest = hex.EncodeToString(sum[:])
	status.Files = len(actual)
	status.Bindings = seal.Bindings
	status.Note = "Derived report files are intact. Source bindings are examiner assertions in this report; verify the original signed evidence separately. No trusted timestamp or key revocation check was performed."
	return status, nil
}

// A manifest grows with the number and names of retained memory tool outputs.
// Bound the read to the opened regular file's size, not an arbitrary report cap.
// Version 1 signs the exact JSON bytes, so verification still retains them in RAM.
func readReportSeal(ctx context.Context, name string) ([]byte, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	before, e := os.Lstat(name)
	if e != nil {
		return nil, e
	}
	if !before.Mode().IsRegular() {
		return nil, errors.New("report seal must be a regular file")
	}
	f, e := os.Open(name)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	opened, e := f.Stat()
	if e != nil {
		return nil, e
	}
	unchanged := func(a, b os.FileInfo) bool {
		return b.Mode().IsRegular() && os.SameFile(a, b) && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
	}
	if !unchanged(before, opened) {
		return nil, errors.New("report seal changed before reading")
	}
	body, e := io.ReadAll(io.LimitReader(&contextReader{ctx: ctx, r: f}, opened.Size()))
	if e != nil {
		return nil, e
	}
	after, e := os.Lstat(name)
	if e != nil {
		return nil, e
	}
	if int64(len(body)) != opened.Size() || !unchanged(opened, after) {
		return nil, errors.New("report seal changed while reading")
	}
	if e = ctx.Err(); e != nil {
		return nil, e
	}
	return body, nil
}
