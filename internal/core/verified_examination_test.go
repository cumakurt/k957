package core

import (
	"archive/zip"
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestExaminationRechecksSHAInsteadOfOnlyZIPCRC(t *testing.T) {
	var buffer bytes.Buffer
	w := zip.NewWriter(&buffer)
	entry, err := w.Create("object")
	if err != nil {
		t.Fatal(err)
	}
	entry.Write([]byte("record"))
	w.Close()
	r, err := zip.NewReader(bytes.NewReader(buffer.Bytes()), int64(buffer.Len()))
	if err != nil {
		t.Fatal(err)
	}
	item := Item{Size: 6, SHA256: digestBytes([]byte("record"))}
	if _, err = readVerifiedEntryContext(context.Background(), r.File[0], item, 100); err != nil {
		t.Fatal(err)
	}
	item.SHA256 = strings.Repeat("a", 64)
	if _, err = readVerifiedEntryContext(context.Background(), r.File[0], item, 100); err == nil {
		t.Fatal("ZIP CRC was treated as authoritative evidence identity")
	}
	if _, err = scanPackageMemoryContext(context.Background(), r.File[0], item, nil); err == nil {
		t.Fatal("memory scan used unverified bytes")
	}
}

func TestFileClassificationUsesVerifiedPrefixSnapshot(t *testing.T) {
	item := Item{ID: "E1", Object: "objects/E1", Source: "file.bin"}
	p := &Package{VerifiedPrefixes: map[string][]byte{item.Object: []byte("SQLite format 3\x00")}, Files: map[string]*zip.File{}}
	identity := identifyVerifiedItem(p, item)
	if identity.MediaType != "application/vnd.sqlite3" || identity.MatchedBy != "magic" {
		t.Fatal("classification reopened evidence instead of using verified prefix", identity)
	}
}
