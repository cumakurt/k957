package core

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

type Package struct {
	VerifiedPrefixes map[string][]byte
	ManifestSHA256   string
	Zip              *zip.ReadCloser
	Manifest         Manifest
	Files            map[string]*zip.File
	Signature        string
	stagingDirectory string
}

// Close releases the ZIP and any collection-owned immutable staging copy.
// Ordinary Open/OpenContext callers may continue using Zip.Close as before.
func (p *Package) Close() error {
	err := p.Zip.Close()
	if p.stagingDirectory != "" {
		if cleanupErr := os.RemoveAll(p.stagingDirectory); err == nil {
			err = cleanupErr
		}
		p.stagingDirectory = ""
	}
	return err
}

func Open(path, publicKey string) (*Package, error) {
	return OpenContext(context.Background(), path, publicKey)
}

// OpenContext verifies package bytes and observes cancellation during hashing.
func OpenContext(ctx context.Context, path, publicKey string) (p *Package, err error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	z, e := zip.OpenReader(path)
	if e != nil {
		return nil, e
	}
	defer func() {
		if err != nil {
			z.Close()
		}
	}()
	p = &Package{Zip: z, Files: map[string]*zip.File{}, VerifiedPrefixes: map[string][]byte{}, Signature: "unsigned"}
	if len(z.File) > 100002 {
		return nil, errors.New("too many entries")
	}
	for _, f := range z.File {
		if _, ok := p.Files[f.Name]; ok {
			return nil, errors.New("duplicate zip entry")
		}
		p.Files[f.Name] = f
	}
	mf, ok := p.Files["manifest.json"]
	if !ok {
		return nil, errors.New("missing manifest")
	}
	b, e := readEntry(mf, manifestLimit)
	if e != nil {
		return nil, e
	}
	digest := sha256.Sum256(b)
	p.ManifestSHA256 = hex.EncodeToString(digest[:])
	if e = custodyJSON(b, &p.Manifest); e != nil {
		return nil, fmt.Errorf("manifest: %w", e)
	}
	m := p.Manifest
	if (m.Schema != Schema && m.Schema != ResumeSchema) || m.ID == "" || m.Case == "" {
		return nil, errors.New("unsupported or invalid manifest")
	}
	if m.Status != "complete" && m.Status != "partial" {
		return nil, errors.New("invalid status")
	}
	if sf, ok := p.Files["manifest.sig"]; ok {
		sig, e := readEntry(sf, ed25519.SignatureSize)
		if e != nil || len(sig) != ed25519.SignatureSize {
			return nil, errors.New("invalid signature size")
		}
		p.Signature = "present, not authenticated"
		if publicKey != "" {
			pub, e := loadPublic(publicKey)
			if e != nil {
				return nil, e
			}
			if !ed25519.Verify(pub, b, sig) {
				return nil, errors.New("signature verification failed")
			}
			p.Signature = "verified against supplied trusted key"
		}
	} else if publicKey != "" {
		return nil, errors.New("trusted key supplied but package unsigned")
	}
	if m.Schema == ResumeSchema {
		if !m.InventoryFrozen || len(m.Epochs) == 0 || len(m.Epochs) > 1000 {
			return nil, errors.New("invalid resumable acquisition metadata")
		}
		if e := validateEpochs(m.Epochs); e != nil {
			return nil, e
		}
		for _, it := range m.Items {
			if e := validatePartMetadata(it, m.Epochs, it.Size, true); e != nil {
				return nil, e
			}
		}
	} else if len(m.Epochs) > 0 || m.InventoryFrozen {
		return nil, errors.New("version 1 package cannot contain resume metadata")
	}
	seen := map[string]bool{"manifest.json": true}
	if _, ok := p.Files["manifest.sig"]; ok {
		seen["manifest.sig"] = true
	}
	ids := map[string]bool{}
	var total int64
	for _, it := range m.Items {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		if it.ID == "" || ids[it.ID] || seen[it.Object] || it.Object != "objects/"+it.ID || strings.ContainsAny(it.ID, "/\\.") {
			return nil, errors.New("invalid or duplicate object id")
		}
		ids[it.ID] = true
		seen[it.Object] = true
		f, ok := p.Files[it.Object]
		if !ok {
			return nil, fmt.Errorf("missing object %s", it.ID)
		}
		if it.Size < 0 || it.Size > 64<<30 || f.UncompressedSize64 != uint64(it.Size) {
			return nil, errors.New("object size invalid")
		}
		total += it.Size
		if total > 1<<40 {
			return nil, errors.New("package exceeds 1 TiB verification budget")
		}
		r, e := f.Open()
		if e != nil {
			return nil, e
		}
		h := sha256.New()
		prefix := &verifiedPrefixWriter{}
		var n int64
		if m.Schema == ResumeSchema {
			for _, part := range it.Parts {
				ph := sha256.New()
				var pn int64
				pn, e = io.Copy(io.MultiWriter(h, ph, prefix), io.LimitReader(contextReader{ctx, r}, part.Size))
				n += pn
				if e != nil {
					break
				}
				if pn != part.Size || hex.EncodeToString(ph.Sum(nil)) != part.SHA256 {
					e = errors.New("part integrity failure")
					break
				}
			}
			if e == nil {
				var extra [1]byte
				var nn int
				nn, e = r.Read(extra[:])
				if nn == 0 && e == io.EOF {
					e = nil
				} else if e == nil {
					e = errors.New("trailing object bytes")
				}
			}
		} else {
			if len(it.Parts) > 0 {
				r.Close()
				return nil, errors.New("version 1 object cannot contain parts")
			}
			n, e = io.Copy(io.MultiWriter(h, prefix), io.LimitReader(contextReader{ctx, r}, it.Size+1))
		}
		r.Close()
		if e != nil {
			return nil, e
		}
		if n != it.Size || hex.EncodeToString(h.Sum(nil)) != it.SHA256 {
			return nil, fmt.Errorf("integrity failure: %s", it.ID)
		}
		p.VerifiedPrefixes[it.Object] = prefix.bytes
	}
	if len(seen) != len(p.Files) {
		return nil, errors.New("unlisted zip entries")
	}
	return p, nil
}

type verifiedPrefixWriter struct{ bytes []byte }

func (w *verifiedPrefixWriter) Write(body []byte) (int, error) {
	if remaining := identityPrefix - len(w.bytes); remaining > 0 {
		w.bytes = append(w.bytes, body[:min(len(body), remaining)]...)
	}
	return len(body), nil
}

func readVerifiedEntryContext(ctx context.Context, file *zip.File, item Item, limit int64) ([]byte, error) {
	body, err := readEntryContext(ctx, file, limit)
	if err != nil {
		return nil, err
	}
	if int64(len(body)) != item.Size || digestBytes(body) != item.SHA256 {
		return nil, errors.New("examination input differs from verified object SHA-256")
	}
	return body, nil
}
func readEntry(f *zip.File, limit int64) ([]byte, error) {
	return readEntryContext(context.Background(), f, limit)
}

func readEntryContext(ctx context.Context, f *zip.File, limit int64) ([]byte, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if f.UncompressedSize64 > uint64(limit) {
		return nil, errors.New("entry too large")
	}
	r, e := f.Open()
	if e != nil {
		return nil, e
	}
	defer r.Close()
	b, e := io.ReadAll(io.LimitReader(contextReader{ctx, r}, limit+1))
	if int64(len(b)) > limit {
		return nil, errors.New("entry too large")
	}
	return b, e
}
func decodePrivate(b []byte) (ed25519.PrivateKey, error) {
	v, e := hex.DecodeString(strings.TrimSpace(string(b)))
	if e != nil || len(v) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid private key")
	}
	key := ed25519.PrivateKey(v)
	if !bytes.Equal(key, ed25519.NewKeyFromSeed(key.Seed())) {
		return nil, errors.New("inconsistent Ed25519 private key")
	}
	return key, nil
}
func loadPublic(path string) (ed25519.PublicKey, error) {
	b, e := ReadLimited(path, 4096)
	if e != nil {
		return nil, e
	}
	v, e := hex.DecodeString(strings.TrimSpace(string(b)))
	if e != nil || len(v) != ed25519.PublicKeySize {
		return nil, errors.New("invalid public key")
	}
	return ed25519.PublicKey(v), nil
}
func Keygen(prefix string) error {
	pub, priv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return e
	}
	if e = WriteNew(prefix+".key", []byte(hex.EncodeToString(priv)+"\n")); e != nil {
		return e
	}
	if e = WriteNew(prefix+".pub", []byte(hex.EncodeToString(pub)+"\n")); e != nil {
		os.Remove(prefix + ".key")
		return e
	}
	return nil
}
