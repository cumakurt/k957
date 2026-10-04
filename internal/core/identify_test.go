package core

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestIdentifyHeader(t *testing.T) {
	pe := make([]byte, 0x80)
	copy(pe, "MZ")
	binary.LittleEndian.PutUint32(pe[0x3c:], 0x40)
	copy(pe[0x40:], "PE\x00\x00")
	mz := []byte("MZ")
	mz = append(mz, make([]byte, 0x40)...)
	cases := []struct {
		in, media string
	}{
		{string([]byte("SQLite format 3\x00")), "application/vnd.sqlite3"},
		{"ElfFile\x00", "application/x-ms-evtx"},
		{"regf", "application/x-windows-registry"},
		{"%PDF-1.7", "application/pdf"},
		{string([]byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}), "image/png"},
		{string([]byte{0xff, 0xd8, 0xff, 0x00}), "image/jpeg"},
		{"GIF89a", "image/gif"},
		{string([]byte{0x50, 0x4b, 0x03, 0x04}), "application/zip"},
		{string([]byte{0x1f, 0x8b}), "application/gzip"},
		{string([]byte{0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c}), "application/x-7z-compressed"},
		{"Rar!\x1a\x07", "application/vnd.rar"},
		{string([]byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}), "application/x-ole-storage"},
		{string([]byte{0x0a, 0x0d, 0x0d, 0x0a}), "application/x-pcapng"},
		{string([]byte{0xd4, 0xc3, 0xb2, 0xa1}), "application/vnd.tcpdump.pcap"},
		{string([]byte{0x45, 0x4d, 0x69, 0x4c}), "application/x-lime"},
		{"LiME", ""},
		{string([]byte{0x7f, 'E', 'L', 'F'}), "application/x-elf"},
		{string([]byte{0xfe, 0xed, 0xfa, 0xcf}), "application/x-mach-binary"},
		{string([]byte{0x00, 'a', 's', 'm'}), "application/wasm"},
		{string(pe), "application/vnd.microsoft.portable-executable"},
		{string(mz), "application/x-dos-mz"},
		{"#!/bin/sh\n", "text/x-script"},
		{"<?xml version=\"1.0\"?>", "text/xml"},
		{string([]byte{0xef, 0xbb, 0xbf}) + "<?xml version=\"1.0\"?>", "text/xml"},
		{string([]byte{0xef, 0xbb, 0xbf}) + "text", "text/plain"},
		{"plain", ""},
	}
	for _, c := range cases {
		media, _ := identifyHeader([]byte(c.in))
		if media != c.media {
			t.Fatalf("%q: got %s want %s", c.in[:min(12, len(c.in))], media, c.media)
		}
	}
	if !extensionMismatch("note.txt", "image/png") || extensionMismatch("note.txt", "text/plain") || extensionMismatch("photo.png", "image/png") || extensionMismatch("app.exe", "application/vnd.microsoft.portable-executable") {
		t.Fatal("extension mismatch classification")
	}
	if id := identifyItem(nil, Item{ID: "E", Source: "x"}); id.MatchedBy != "error" {
		t.Fatal(id)
	}
}

func TestHashSetAndApply(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/set.txt"
	body := "# comment\n\n" + strings.Repeat("ab", 32) + " sample\nknown-good " + strings.Repeat("cd", 32) + " trusted-label\n"
	if e := WriteNew(path, []byte(body)); e != nil {
		t.Fatal(e)
	}
	set, e := LoadHashSet(path)
	if e != nil || set.Len() != 2 {
		t.Fatal(e, set)
	}
	if _, e = LoadHashSet(dir + "/missing"); e == nil {
		t.Fatal("expected missing file")
	}
	bad := dir + "/bad.txt"
	WriteNew(bad, []byte("not-a-hash\n"))
	if _, e = LoadHashSet(bad); e == nil {
		t.Fatal("expected invalid hash")
	}
	conflict := dir + "/conflict.txt"
	WriteNew(conflict, []byte(strings.Repeat("ab", 32)+"\nknown-good "+strings.Repeat("ab", 32)+"\n"))
	if _, e = LoadHashSet(conflict); e == nil {
		t.Fatal("expected conflict")
	}
	js := dir + "/set.json"
	WriteNew(js, []byte(`{"schema":"k957-hashset/1","entries":[{"sha256":"`+strings.Repeat("ef", 32)+`","verdict":"known-bad","label":"json"}]}`+"\n"))
	if set, e = LoadHashSet(js); e != nil || set.Len() != 1 {
		t.Fatal(e, set)
	}
	WriteNew(dir+"/trail.json", []byte(`{"schema":"k957-hashset/1","entries":[]}{}`))
	if _, e = LoadHashSet(dir + "/trail.json"); e == nil {
		t.Fatal("expected trailing json")
	}
	a := Analysis{EvidenceDigest: strings.Repeat("a", 64), Manifest: Manifest{Items: []Item{
		{ID: "E1", Source: "bad.bin", SHA256: strings.Repeat("ab", 32)},
		{ID: "E2", Source: "good.bin", SHA256: strings.Repeat("cd", 32)},
	}}}
	ApplyHashSet(&a, set)
	if len(a.HashMatches) != 0 {
		t.Fatal("json set should not match the text hashes")
	}
	ApplyHashSet(&a, mustSet(t, path))
	if len(a.HashMatches) != 2 || len(a.Findings) != 1 || a.Findings[0].Rule != "hashset" || a.Findings[0].ID == "" {
		t.Fatalf("matches %d findings %#v", len(a.HashMatches), a.Findings)
	}
	if _, _, ok := (*HashSet)(nil).Lookup("aa"); ok {
		t.Fatal("nil lookup")
	}
}

func mustSet(t *testing.T, path string) *HashSet {
	t.Helper()
	set, e := LoadHashSet(path)
	if e != nil {
		t.Fatal(e)
	}
	return set
}

func TestAcceptedCollectionVersion(t *testing.T) {
	if !acceptedCollectionVersion("0.13.0") || !acceptedCollectionVersion(Version) || acceptedCollectionVersion("0.9.0") {
		t.Fatal(Version)
	}
}

func TestCollectorFingerprintFailure(t *testing.T) {
	prev := executablePath
	executablePath = func() (string, error) { return t.TempDir() + "/missing-binary", nil }
	t.Cleanup(func() { executablePath = prev })
	if _, e := collectorFingerprint(); e == nil {
		t.Fatal("expected missing executable")
	}
}
