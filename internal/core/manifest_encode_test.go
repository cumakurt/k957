package core

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSignedManifestAboveLegacyReaderLimit(t *testing.T) {
	dir := t.TempDir()
	m := Manifest{Schema: Schema, Version: Version, ID: "large", Case: "Synthetic", Status: "complete", Items: []Item{}, Issues: []Issue{}}
	empty := sha256.Sum256(nil)
	for i := 0; i < 20000; i++ {
		id := fmt.Sprintf("E%06d", i+1)
		m.Items = append(m.Items, Item{ID: id, Object: "objects/" + id, Source: strings.Repeat("source/", 120) + id, SHA256: hex.EncodeToString(empty[:])})
	}
	body, err := marshalManifest(m)
	if err != nil || len(body) <= 16<<20 || len(body) > manifestLimit {
		t.Fatalf("large fixture size %d: %v", len(body), err)
	}
	path := filepath.Join(dir, "large.k957")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(file)
	for _, item := range m.Items {
		if _, err = writer.Create(item.Object); err != nil {
			t.Fatal(err)
		}
	}
	manifest, err := writer.Create("manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = manifest.Write(body); err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	signature, err := writer.Create("manifest.sig")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = signature.Write(ed25519.Sign(key, body)); err != nil {
		t.Fatal(err)
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	public := filepath.Join(dir, "signing.pub")
	if err = WriteNew(public, []byte(hex.EncodeToString(key.Public().(ed25519.PublicKey)))); err != nil {
		t.Fatal(err)
	}
	p, err := Open(path, public)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if len(p.Manifest.Items) != len(m.Items) || p.Signature != "verified against supplied trusted key" {
		t.Fatal("large signed inventory not verified")
	}
}

func TestManifestEncodingPreservesSignedBytes(t *testing.T) {
	stamp := time.Date(2024, 1, 1, 0, 0, 0, 100, time.FixedZone("offset", 3600))
	uid := uint32(123)
	item := Item{ID: "E000001", Source: "Unicode Café <tag> \"source\"\n", Modified: stamp, Metadata: &FileMetadata{UID: &uid, Accessed: &stamp, Attributes: []ExtendedAttribute{{Name: "attribute", Value: "AA=="}}}, Parts: []Part{{Size: 2, Acquired: stamp}}}
	for _, m := range []Manifest{
		{},
		{Items: []Item{}, Issues: []Issue{}},
		{Items: []Item{item}, Issues: []Issue{{Source: "items", Reason: "missing"}}},
		{Acquisition: liveFileGuarantees(), Epochs: []Epoch{{ID: "epoch", Started: stamp}}, Items: []Item{item, {}}, Issues: []Issue{}},
	} {
		want, err := MarshalJSON(m)
		if err != nil {
			t.Fatal(err)
		}
		got, err := marshalManifest(m)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("encoding differs: %v\ngot %s\nwant %s", err, got, want)
		}
		key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
		if !ed25519.Verify(key.Public().(ed25519.PublicKey), got, ed25519.Sign(key, want)) {
			t.Fatal("exact-byte signature compatibility lost")
		}
	}
}

func TestManifestEncodingBoundsAndWriteErrors(t *testing.T) {
	m := Manifest{Items: []Item{{Source: strings.Repeat("s", 2048)}}}
	var b bytes.Buffer
	if err := writeManifestJSON(&boundedJSONWriter{writer: &b, remaining: 1024}, m); err == nil {
		t.Fatal("encoded byte budget ignored")
	}
	if b.Len() > 1024 {
		t.Fatal("encoded bytes exceeded limit")
	}
	failure := errors.New("synthetic writer failure")
	if err := writeManifestJSON(&boundedJSONWriter{writer: failedJSONWriter{failure}, remaining: manifestLimit}, m); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	if err := writeManifestJSON(&boundedJSONWriter{writer: shortJSONWriter{}, remaining: manifestLimit}, m); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal(err)
	}
}

type shortJSONWriter struct{}

func (shortJSONWriter) Write(b []byte) (int, error) { return len(b) - 1, nil }

type failedJSONWriter struct{ err error }

func (w failedJSONWriter) Write([]byte) (int, error) { return 0, w.err }
