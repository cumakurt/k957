package core

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/rand"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

type failReader struct{ err error }

func (r failReader) Read(p []byte) (int, error) {
	if r.err == nil {
		return 0, errors.New("read failed")
	}
	return 0, r.err
}

type failWriter struct{}

func (failWriter) Write(p []byte) (int, error) { return 0, errors.New("write failed") }

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return len(p) - 1, nil
}

type failAt struct{}

func (failAt) ReadAt(p []byte, off int64) (int, error) { return 0, errors.New("readat failed") }

type zeroAt struct{}

func (zeroAt) ReadAt(p []byte, off int64) (int, error) { return 0, nil }

func useRand(t *testing.T, r io.Reader) {
	t.Helper()
	old := rand.Reader
	rand.Reader = r
	t.Cleanup(func() { rand.Reader = old })
}

func TestModelAndVolumeEdges(t *testing.T) {
	useRand(t, failReader{})
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("expected ID panic")
			}
		}()
		ID()
	}()
	if e := EncryptionKey(filepath.Join(t.TempDir(), "k")); e == nil {
		t.Fatal("expected rand failure")
	}

	dir := t.TempDir()

	if _, e := ReadLimited(filepath.Join(dir, "missing"), 8); e == nil {
		t.Fatal("expected missing file")
	}
	big := filepath.Join(dir, "big")
	if e := os.WriteFile(big, []byte("abcdef"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := ReadLimited(big, 3); e == nil {
		t.Fatal("expected limit")
	}
	if _, e := ReadLimited(dir, 8); e == nil {
		t.Fatal("expected directory read error")
	}

	if _, e := probeVolume(filepath.Join(dir, "missing")); e == nil {
		t.Fatal("expected statfs error")
	}

	if e := ensureSpace(dir, -1, 0); e == nil {
		t.Fatal("expected negative capacity")
	}
	if e := ensureSpace(dir, math.MaxInt64, 1); e == nil {
		t.Fatal("expected overflow")
	}
	if e := ensureSpace(filepath.Join(dir, "missing"), 1, 0); e == nil {
		t.Fatal("expected unknown capacity")
	}
	if e := ensureSpace(dir, 1<<62, 0); e == nil {
		t.Fatal("expected insufficient space")
	}
}

func TestCryptoEdges(t *testing.T) {
	dir := t.TempDir()
	if _, e := cryptKey(filepath.Join(dir, "missing")); e == nil {
		t.Fatal("expected missing key")
	}
	bad := filepath.Join(dir, "bad")
	os.WriteFile(bad, []byte("zz\n"), 0600)
	if _, e := cryptKey(bad); e == nil {
		t.Fatal("expected hex error")
	}
	os.WriteFile(bad, []byte("aa\n"), 0600)
	if _, e := cryptKey(bad); e == nil {
		t.Fatal("expected length error")
	}
	if _, e := buildAEAD([]byte{1, 2, 3}); e == nil {
		t.Fatal("expected cipher error")
	}
	key := bytes.Repeat([]byte{7}, 32)
	aead, e := buildAEAD(key)
	if e != nil {
		t.Fatal(e)
	}
	good := filepath.Join(dir, "good")
	os.WriteFile(good, []byte(fmt.Sprintf("%x\n", key)), 0600)
	oldBuild := buildAEAD
	buildAEAD = func(key []byte) (cipher.AEAD, error) { return nil, errors.New("aead") }
	t.Cleanup(func() { buildAEAD = oldBuild })
	if _, e := cryptKey(good); e == nil {
		t.Fatal("expected aead failure")
	}
	if _, e := newWorkCrypto(good); e == nil {
		t.Fatal("expected stage aead failure")
	}
	n := 0
	buildAEAD = func(key []byte) (cipher.AEAD, error) {
		n++
		if n >= 2 {
			return nil, errors.New("second")
		}
		return oldBuild(key)
	}
	if _, e := newWorkCrypto(good); e == nil {
		t.Fatal("expected transport aead failure")
	}
	buildAEAD = oldBuild
	wc, e := newWorkCrypto(good)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := wc.open("state", []byte("short")); e == nil {
		t.Fatal("expected bad envelope")
	}
	if sealed, e := wc.seal("state", []byte("ok")); e != nil {
		t.Fatal(e)
	} else if _, e = wc.open("other", sealed); e == nil {
		t.Fatal("expected auth failure")
	}

	if e := encryptIndexed(strings.NewReader(""), &bytes.Buffer{}, aead, ^uint32(0)); e == nil {
		t.Fatal("expected nonce limit")
	}
	hdr := append([]byte("K957ENC1"), make([]byte, 8)...)
	if e := decryptIndexed(bytes.NewReader(hdr), &bytes.Buffer{}, aead, ^uint32(0)); e == nil {
		t.Fatal("expected decrypt nonce limit")
	}
	if e := decryptIndexed(strings.NewReader("short"), &bytes.Buffer{}, aead, 0); e == nil {
		t.Fatal("expected short header")
	}
	if e := decryptIndexed(bytes.NewReader(make([]byte, 16)), &bytes.Buffer{}, aead, 0); e == nil {
		t.Fatal("expected bad magic")
	}
	useRand(t, failReader{})
	if e := encryptIndexed(strings.NewReader("x"), &bytes.Buffer{}, aead, 0); e == nil {
		t.Fatal("expected rand failure")
	}
	rand.Reader = bytes.NewReader(bytes.Repeat([]byte{1}, 64))
	if e := encryptIndexed(strings.NewReader(""), failWriter{}, aead, 0); e == nil {
		t.Fatal("expected header write failure")
	}
	if e := encryptIndexed(failReader{err: errors.New("body")}, &bytes.Buffer{}, aead, 0); e == nil {
		t.Fatal("expected body read failure")
	}
}

func TestProfileSystemAndOperator(t *testing.T) {

	if len(systemSources()) == 0 {
		t.Fatal("expected linux sources")
	}
	oldOS := systemGOOS
	t.Cleanup(func() { systemGOOS = oldOS })
	for _, name := range []string{"windows", "darwin", "plan9"} {
		systemGOOS = name
		if len(systemSources()) == 0 {
			t.Fatal(name)
		}
	}
	systemGOOS = oldOS

	b := &cappedBuffer{limit: 2}
	if n, e := b.Write([]byte("abcd")); n != 4 || e != nil || !b.overflow || b.Len() != 2 || string(b.Bytes()) != "ab" || b.String() != "ab" {
		t.Fatalf("cap %d %v %v %q", n, e, b.overflow, b.Bytes())
	}
	b.limit = 0
	if n, e := b.Write([]byte("z")); n != 1 || e != nil || b.Len() != 2 {
		t.Fatalf("negative remain %d %v %d", n, e, b.Len())
	}
	if _, e := readPrefix(filepath.Join(t.TempDir(), "missing"), 8); e == nil {
		t.Fatal("expected missing")
	}
	if _, e := readPrefix(t.TempDir(), 8); e == nil {
		t.Fatal("expected directory read")
	}
	small := filepath.Join(t.TempDir(), "small")
	os.WriteFile(small, []byte("ok"), 0600)
	if got, e := readPrefix(small, 8); e != nil || string(got) != "ok" {
		t.Fatal(e, got)
	}
	if _, _, e := snapshot(context.Background(), source{Command: "k957-missing-command"}); e == nil {
		t.Fatal("expected command error")
	}

	oldUser := currentUser
	t.Cleanup(func() { currentUser = oldUser })
	currentUser = func() (*user.User, error) { return nil, errors.New("no user") }
	t.Setenv("USER", "")
	t.Setenv("USERNAME", "")
	if currentOperator() != "unknown" {
		t.Fatal(currentOperator())
	}
	t.Setenv("USER", "ada")
	if currentOperator() != "ada" {
		t.Fatal(currentOperator())
	}
	currentUser = func() (*user.User, error) { return &user.User{Username: ""}, nil }
	t.Setenv("USER", "")
	t.Setenv("USERNAME", "grace")
	if currentOperator() != "grace" {
		t.Fatal(currentOperator())
	}

	oldHost := hostName
	t.Cleanup(func() { hostName = oldHost })
	hostName = func() (string, error) { return "", errors.New("no host") }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := CollectFull(ctx, FullOptions{Memory: true}); e == nil {
		t.Fatal("expected cancelled collection")
	}
	if _, e := CollectFull(context.Background(), FullOptions{}); e == nil {
		t.Fatal("expected empty selection")
	}
}

func TestMemoryEdges(t *testing.T) {
	if _, e := parseIOMem(failReader{}); e == nil {
		t.Fatal("expected scan error")
	}
	for _, in := range []string{"abcd : System RAM\n", "zz-1 : System RAM\n", "2-1 : System RAM\n", "0-ffffffffffffffff : System RAM\n", "0000-0001 : Reserved\n"} {
		if _, e := parseIOMem(strings.NewReader(in)); e == nil {
			t.Fatal(in)
		}
	}
	if _, e := parseIOMem(strings.NewReader("00000000-00000000 : System RAM\n")); e == nil {
		t.Fatal("expected privilege error")
	}
	merged, e := parseIOMem(strings.NewReader("00002000-00002fff : System RAM\n00001000-00001fff : System RAM\n00001800-00003000 : System RAM\n"))
	if e != nil || len(merged) != 1 {
		t.Fatal(e, merged)
	}
	f := &elf.File{Progs: []*elf.Prog{
		{ProgHeader: elf.ProgHeader{Type: elf.PT_NOTE, Paddr: 1, Filesz: 1}},
		{ProgHeader: elf.ProgHeader{Type: elf.PT_LOAD, Paddr: ^uint64(0), Filesz: 10}},
		{ProgHeader: elf.ProgHeader{Type: elf.PT_LOAD, Paddr: 1, Filesz: 0}},
		{ProgHeader: elf.ProgHeader{Type: elf.PT_LOAD, Paddr: 8, Filesz: 4, Off: 20}},
		{ProgHeader: elf.ProgHeader{Type: elf.PT_LOAD, Paddr: 1, Filesz: 4, Off: 3}},
	}}
	if segs := kcoreSegments(f); len(segs) != 2 || segs[0].paddr != 1 {
		t.Fatal(segs)
	}
	planned, gaps := planPhysical([]physRange{{start: 0, end: 20}}, kcoreSegments(f))
	if len(planned) == 0 || len(gaps) == 0 {
		t.Fatal(planned, gaps)
	}
	planned, gaps = planPhysical([]physRange{{start: 100, end: 110}}, kcoreSegments(f))
	if len(planned) != 0 || len(gaps) != 1 {
		t.Fatal(planned, gaps)
	}

	w := newLimeWriter(failWriter{})
	if _, e := w.copyRange(context.Background(), 0, 0, zeroAt{}, 0); e == nil {
		t.Fatal("expected invalid range")
	}
	if _, e := w.copyRange(context.Background(), ^uint64(0), 1, zeroAt{}, 0); e == nil {
		t.Fatal("expected overflow")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	w = newLimeWriter(&bytes.Buffer{})
	if _, e := w.copyRange(ctx, 0, 4096, zeroAt{}, 0); e == nil {
		t.Fatal("expected cancel")
	}
	w = newLimeWriter(&bytes.Buffer{})
	unread, e := w.copyRange(context.Background(), 0, uint64(memoryPage), failAt{}, 0)
	if e != nil || unread == 0 {
		t.Fatal(e, unread)
	}
	lw := newLimeWriter(shortWriter{})
	if e := lw.write([]byte("ab")); e == nil {
		t.Fatal("expected short write")
	}
	if e := readFullAt(zeroAt{}, []byte{0}, 0); e == nil {
		t.Fatal("expected unexpected eof")
	}

	dir := t.TempDir()
	if _, e := fileSHA256(dir); e == nil {
		t.Fatal("expected hash error")
	}
	if _, _, _, _, e := hashFile(dir); e == nil {
		t.Fatal("expected hash error")
	}
	if _, e := ParseLime(strings.NewReader("")); e == nil {
		t.Fatal("expected empty")
	}
	if _, e := ParseLime(strings.NewReader("xxxx")); e == nil {
		t.Fatal("expected truncated")
	}
	hdr := make([]byte, limeHeaderSize)
	if _, e := ParseLime(bytes.NewReader(hdr)); e == nil {
		t.Fatal("expected invalid header")
	}
	binary.LittleEndian.PutUint32(hdr[0:4], limeMagic)
	binary.LittleEndian.PutUint32(hdr[4:8], limeVersion)
	binary.LittleEndian.PutUint64(hdr[8:16], 5)
	binary.LittleEndian.PutUint64(hdr[16:24], 4)
	if _, e := ParseLime(bytes.NewReader(hdr)); e == nil {
		t.Fatal("expected invalid range")
	}
	binary.LittleEndian.PutUint64(hdr[16:24], 6)
	if _, e := ParseLime(bytes.NewReader(append(append([]byte{}, hdr...), 0))); e == nil {
		t.Fatal("expected truncated payload")
	}

	oldExec := executablePath
	t.Cleanup(func() { executablePath = oldExec })
	executablePath = func() (string, error) { return "", errors.New("no exe") }
	if findBundledWinPmem() != "" {
		t.Fatal("expected empty")
	}
	bin := t.TempDir()
	os.WriteFile(filepath.Join(bin, "winpmem_a.exe"), []byte("a"), 0600)
	os.Mkdir(filepath.Join(bin, "tools"), 0700)
	os.WriteFile(filepath.Join(bin, "tools", "winpmem_b.exe"), []byte("b"), 0600)
	executablePath = func() (string, error) { return filepath.Join(bin, "k957"), nil }
	if findBundledWinPmem() == "" {
		t.Fatal("expected bundled tool")
	}
	os.WriteFile(filepath.Join(bin, "winpmem_c.exe"), []byte("c"), 0600)
	got := findBundledWinPmem()
	if !strings.Contains(got, "tools") {
		t.Fatal(got)
	}

	oldOS := systemGOOS
	t.Cleanup(func() { systemGOOS = oldOS })
	systemGOOS = "darwin"
	if _, e := AcquireMemory(context.Background(), MemoryOptions{Dir: dir, Limit: -1}); e == nil {
		t.Fatal("expected negative limit")
	}
	if _, e := AcquireMemory(context.Background(), MemoryOptions{Dir: dir}); e == nil {
		t.Fatal("expected no native method")
	}
	systemGOOS = "windows"
	if _, e := AcquireMemory(context.Background(), MemoryOptions{Dir: dir}); e == nil {
		t.Fatal("expected windows fallback")
	}
	systemGOOS = oldOS

	script := filepath.Join(dir, "tool.sh")
	os.WriteFile(script, []byte("#!/bin/sh\necho boom >&2\nexit 1\n"), 0700)
	out := filepath.Join(dir, "ext")
	os.Mkdir(out, 0700)
	if _, e := AcquireMemory(context.Background(), MemoryOptions{Dir: out, Tool: script, ToolArgs: []string{"{output}"}}); e == nil {
		t.Fatal("expected tool failure")
	}
	os.WriteFile(script, []byte("#!/bin/sh\nexit 1\n"), 0700)
	if _, e := AcquireMemory(context.Background(), MemoryOptions{Dir: out, Tool: script, ToolArgs: []string{"{output}"}}); e == nil {
		t.Fatal("expected silent tool failure")
	}
	os.WriteFile(script, []byte("#!/bin/sh\n: > \"$1\"\n"), 0700)
	if _, e := AcquireMemory(context.Background(), MemoryOptions{Dir: out, Tool: script, ToolArgs: []string{"{output}"}}); e == nil {
		t.Fatal("expected empty image")
	}
	os.WriteFile(script, []byte("#!/bin/sh\nprintf '0123456789' > \"$1\"\n"), 0700)
	if _, e := AcquireMemory(context.Background(), MemoryOptions{Dir: out, Tool: script, ToolArgs: []string{"{output}"}, Limit: 4}); e == nil {
		t.Fatal("expected limit")
	}
	os.WriteFile(script, []byte("#!/bin/sh\nprintf x > \"$1\"\nchmod 000 \"$1\"\n"), 0700)
	if _, e := AcquireMemory(context.Background(), MemoryOptions{Dir: out, Tool: script, ToolArgs: []string{"{output}"}}); e == nil {
		t.Fatal("expected hash failure")
	}
	os.Mkdir(filepath.Join(out, "memory.raw"), 0700)
	os.WriteFile(filepath.Join(out, "memory.raw", "x"), []byte("x"), 0600)
	os.WriteFile(script, []byte("#!/bin/sh\nprintf x > \"$1\"\n"), 0700)
	if _, e := AcquireMemory(context.Background(), MemoryOptions{Dir: out, Tool: script, ToolArgs: []string{"{output}"}}); e == nil {
		t.Fatal("expected rename failure")
	}
	if _, e := AcquireMemory(context.Background(), MemoryOptions{Dir: out, Tool: out, ToolArgs: []string{"{output}"}}); e == nil {
		t.Fatal("expected unreadable tool")
	}
	if _, e := AcquireMemory(context.Background(), MemoryOptions{Dir: out, Tool: "k957-missing-tool", ToolArgs: []string{"{output}"}}); e == nil {
		t.Fatal("expected missing tool")
	}
	cancelled, stop := context.WithCancel(context.Background())
	stop()
	os.WriteFile(script, []byte("#!/bin/sh\nsleep 30\n"), 0700)
	cancelDir := filepath.Join(dir, "cancel")
	os.Mkdir(cancelDir, 0700)
	if _, e := AcquireMemory(cancelled, MemoryOptions{Dir: cancelDir, Tool: script, ToolArgs: []string{"{output}"}}); e == nil {
		t.Fatal("expected cancelled tool")
	}
}
