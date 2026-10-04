package core

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T, sign bool) (string, Options) {
	t.Helper()
	d := t.TempDir()
	root := filepath.Join(d, "source")
	os.Mkdir(root, 0700)
	os.WriteFile(filepath.Join(root, "auth.log"), []byte("2026-09-27T10:00:00Z failed password\n<script>alert(1)</script> powershell\n"), 0600)
	o := Options{Root: root, Out: filepath.Join(d, "case.k957"), Case: "TEST", Operator: "Tester", Scope: "synthetic", MaxFile: 1 << 20, MaxTotal: 8 << 20, MaxFiles: 100}
	if sign {
		o.SignKey = filepath.Join(d, "sign.key")
		if e := Keygen(filepath.Join(d, "sign")); e != nil {
			t.Fatal(e)
		}
	}
	return d, o
}
func TestCollectAnalyze(t *testing.T) {
	d, o := fixture(t, true)
	m, e := Collect(context.Background(), o)
	if e != nil {
		t.Fatal(e)
	}
	if len(m.Items) != 1 || m.Status != "complete" {
		t.Fatalf("%+v", m)
	}
	p, e := Open(o.Out, filepath.Join(d, "sign.pub"))
	if e != nil {
		t.Fatal(e)
	}
	defer p.Zip.Close()
	a := Analyze(p, []Rule{{ID: "R", Contains: "powershell"}})
	if len(a.Findings) != 1 || a.Findings[0].Line != 2 {
		t.Fatalf("%+v", a.Findings)
	}
	out := filepath.Join(d, "report")
	if e = Export(a, out); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(filepath.Join(out, "report.html"))
	if bytes.Contains(b, []byte("<script>alert(1)</script>")) {
		t.Fatal("report injection")
	}
	if !bytes.Contains(b, []byte("&lt;script&gt;")) {
		t.Fatal("missing escaped evidence")
	}
	if e = Export(a, out); e == nil {
		t.Fatal("overwrote report")
	}
}
func rewrite(t *testing.T, path, out string, change func(string, []byte) []byte, extra bool) {
	t.Helper()
	z, e := zip.OpenReader(path)
	if e != nil {
		t.Fatal(e)
	}
	defer z.Close()
	f, _ := os.Create(out)
	w := zip.NewWriter(f)
	for _, v := range z.File {
		b, e := readEntry(v, 32<<20)
		if e != nil {
			t.Fatal(e)
		}
		b = change(v.Name, b)
		x, _ := w.Create(v.Name)
		x.Write(b)
	}
	if extra {
		x, _ := w.Create("../evil")
		x.Write([]byte("x"))
	}
	w.Close()
	f.Close()
}
func TestTampering(t *testing.T) {
	d, o := fixture(t, true)
	Collect(context.Background(), o)
	for _, target := range []string{"objects/E000001", "manifest.json", "manifest.sig"} {
		t.Run(target, func(t *testing.T) {
			out := filepath.Join(d, ID())
			rewrite(t, o.Out, out, func(n string, b []byte) []byte {
				if n == target {
					b[0] ^= 1
				}
				return b
			}, false)
			if p, e := Open(out, filepath.Join(d, "sign.pub")); e == nil {
				p.Zip.Close()
				t.Fatal("accepted tampering")
			}
		})
	}
	out := filepath.Join(d, "extra")
	rewrite(t, o.Out, out, func(n string, b []byte) []byte { return b }, true)
	if p, e := Open(out, ""); e == nil {
		p.Zip.Close()
		t.Fatal("accepted extra")
	}
}
func TestWrongKey(t *testing.T) {
	d, o := fixture(t, true)
	Collect(context.Background(), o)
	Keygen(filepath.Join(d, "other"))
	if p, e := Open(o.Out, filepath.Join(d, "other.pub")); e == nil {
		p.Zip.Close()
		t.Fatal("wrong key accepted")
	}
}
func TestUnsignedTrust(t *testing.T) {
	d, o := fixture(t, false)
	Collect(context.Background(), o)
	Keygen(filepath.Join(d, "key"))
	if p, e := Open(o.Out, filepath.Join(d, "key.pub")); e == nil {
		p.Zip.Close()
		t.Fatal("unsigned trusted")
	}
}
func TestLimitsAndSymlink(t *testing.T) {
	d, o := fixture(t, false)
	os.Symlink(filepath.Join(o.Root, "auth.log"), filepath.Join(o.Root, "link"))
	o.MaxFile = 1
	m, e := Collect(context.Background(), o)
	if e != nil {
		t.Fatal(e)
	}
	if m.Status != "partial" || len(m.Items) != 0 || len(m.Issues) == 0 {
		t.Fatal(m)
	}
	p, e := Open(o.Out, "")
	if e != nil {
		t.Fatal(e)
	}
	p.Zip.Close()
	_ = d
}
func TestOutputProtection(t *testing.T) {
	_, o := fixture(t, false)
	o.Out = filepath.Join(o.Root, "out")
	if _, e := Collect(context.Background(), o); e == nil {
		t.Fatal("source output accepted")
	}
	o.Out = filepath.Join(filepath.Dir(o.Root), "exists")
	os.WriteFile(o.Out, []byte("original"), 0600)
	if _, e := Collect(context.Background(), o); e == nil {
		t.Fatal("overwrite accepted")
	}
	b, _ := os.ReadFile(o.Out)
	if string(b) != "original" {
		t.Fatal("overwritten")
	}
}
func TestCancelled(t *testing.T) {
	_, o := fixture(t, false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, e := Collect(ctx, o)
	if e == nil {
		t.Fatal("cancelled succeeded")
	}
	if _, e = os.Stat(o.Out); !os.IsNotExist(e) {
		t.Fatal("left incomplete package")
	}
}

func aead(t *testing.T) cipher.AEAD {
	b, _ := aes.NewCipher(make([]byte, 32))
	a, e := cipher.NewGCM(b)
	if e != nil {
		t.Fatal(e)
	}
	return a
}
func TestEnvelope(t *testing.T) {
	for _, n := range []int{0, 1, chunkSize, chunkSize + 12} {
		t.Run(string(rune(n%100+65)), func(t *testing.T) {
			src := bytes.Repeat([]byte("x"), n)
			var enc, dec bytes.Buffer
			if e := encryptStream(bytes.NewReader(src), &enc, aead(t)); e != nil {
				t.Fatal(e)
			}
			if e := decryptStream(bytes.NewReader(enc.Bytes()), &dec, aead(t)); e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(src, dec.Bytes()) {
				t.Fatal("roundtrip")
			}
			for _, b := range [][]byte{enc.Bytes()[:enc.Len()-1], append(append([]byte{}, enc.Bytes()...), 1)} {
				if e := decryptStream(bytes.NewReader(b), &bytes.Buffer{}, aead(t)); e == nil {
					t.Fatal("accepted truncation/trailing")
				}
			}
			b := append([]byte{}, enc.Bytes()...)
			b[len(b)-1] ^= 1
			if e := decryptStream(bytes.NewReader(b), &bytes.Buffer{}, aead(t)); e == nil {
				t.Fatal("accepted tamper")
			}
		})
	}
}
func TestDecryptCleanup(t *testing.T) {
	d := t.TempDir()
	key := filepath.Join(d, "key")
	EncryptionKey(key)
	in := filepath.Join(d, "bad")
	os.WriteFile(in, []byte("invalid"), 0600)
	out := filepath.Join(d, "out")
	if e := Transform(in, out, key, true); e == nil {
		t.Fatal("accepted invalid")
	}
	if _, e := os.Stat(out); !os.IsNotExist(e) {
		t.Fatal("left plaintext")
	}
}
func TestRulesAndCSV(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "rules")
	for _, v := range []string{`[{"id":"a"}]`, `[{"id":"a","contains":"x"},{"id":"a","contains":"y"}]`, `[{"id":"a","sha256":"oops"}]`} {
		os.WriteFile(p, []byte(v), 0600)
		if _, e := LoadRules(p); e == nil {
			t.Fatal("invalid rules accepted")
		}
	}
	if csvSafe("=SUM(A1)") != "'=SUM(A1)" {
		t.Fatal("formula injection")
	}
	if csvSafe("") != "" {
		t.Fatal("empty")
	}
}
func TestManifestDuplicates(t *testing.T) {
	d, o := fixture(t, false)
	Collect(context.Background(), o)
	out := filepath.Join(d, "bad")
	rewrite(t, o.Out, out, func(n string, b []byte) []byte {
		if n == "manifest.json" {
			var m Manifest
			json.Unmarshal(b, &m)
			m.Items = append(m.Items, m.Items[0])
			return JSON(m)
		}
		return b
	}, false)
	if p, e := Open(out, ""); e == nil {
		p.Zip.Close()
		t.Fatal("duplicate accepted")
	}
}
func TestSystemTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	_, _, e := snapshot(ctx, source{Name: "missing", Command: "k957-nonexistent-command"})
	if e == nil {
		t.Fatal("missing command succeeded")
	}
}
func FuzzRules(f *testing.F) {
	f.Add(`[{"id":"r","contains":"test"}]`)
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 100000 {
			t.Skip()
		}
		p := filepath.Join(t.TempDir(), "rules")
		os.WriteFile(p, []byte(s), 0600)
		LoadRules(p)
	})
}
func FuzzEnvelope(f *testing.F) {
	f.Add([]byte("K957ENC1bad"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 2<<20 {
			t.Skip()
		}
		decryptStream(bytes.NewReader(b), &bytes.Buffer{}, aead(t))
	})
}
func TestTextBudgetAndBinary(t *testing.T) {
	_, o := fixture(t, false)
	os.WriteFile(filepath.Join(o.Root, "binary"), []byte{0, 1, 2, 3}, 0600)
	Collect(context.Background(), o)
	p, e := Open(o.Out, "")
	if e != nil {
		t.Fatal(e)
	}
	defer p.Zip.Close()
	a := Analyze(p, []Rule{{ID: "r", Contains: "failed password"}})
	if len(a.Findings) != 1 {
		t.Fatal(a.Findings)
	}
	if !strings.Contains(strings.Join(a.Notes, " "), "binary text scan skipped") {
		t.Fatal("missing limitation")
	}
}
func TestLogTimestamp(t *testing.T) {
	it := Item{ID: "E1", Source: "log"}
	for _, s := range []string{`{"timestamp":"2026-09-27T14:00:00+03:00","message":"test"}`, "2026-09-27T11:00:00Z event"} {
		ev, ok := parseLogLine(s, it, 7)
		if !ok || ev.Time.Hour() != 11 || ev.Line != 7 || ev.Evidence != "E1" {
			t.Fatal(ev, ok)
		}
	}
	if _, ok := parseLogLine("Sep 27 14:00:00 host event", it, 1); ok {
		t.Fatal("guessed timezone")
	}
}
func TestPrivateKeyExcluded(t *testing.T) {
	_, o := fixture(t, false)
	Keygen(filepath.Join(o.Root, "private"))
	o.SignKey = filepath.Join(o.Root, "private.key")
	if _, e := Collect(context.Background(), o); e == nil {
		t.Fatal("collected signing key")
	}
}
