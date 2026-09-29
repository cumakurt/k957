package core

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func encryptedFixture(t *testing.T) (string, Options, string) {
	d, o, work := resumeFixture(t)
	o.EncryptionKey = filepath.Join(d, "transport.key")
	if e := EncryptionKey(o.EncryptionKey); e != nil {
		t.Fatal(e)
	}
	return d, o, work
}
func TestEncryptedResumeAndSignedOutput(t *testing.T) {
	d, o, work := encryptedFixture(t)
	Keygen(filepath.Join(d, "sign"))
	o.SignKey = filepath.Join(d, "sign.key")
	ctx, cancel := context.WithCancel(context.Background())
	_, e := collectResumable(ctx, o, work, false, cancel)
	cancel()
	if e == nil {
		t.Fatal("not interrupted")
	}
	if _, e = os.Stat(filepath.Join(work, "state.json")); !os.IsNotExist(e) {
		t.Fatal("plaintext checkpoint")
	}
	if _, e = InspectWork(context.Background(), work, true); e == nil {
		t.Fatal("missing key accepted")
	}
	status, e := InspectWork(context.Background(), work, true, o.EncryptionKey)
	if e != nil || !status.Encrypted || status.Parts != 1 {
		t.Fatal(status, e)
	}
	filepath.WalkDir(work, func(path string, de os.DirEntry, err error) error {
		if err != nil {
			t.Fatal(err)
		}
		if !de.IsDir() {
			b, _ := os.ReadFile(path)
			if bytes.Contains(b, []byte(o.Root)) || bytes.Contains(b, bytes.Repeat([]byte("A"), 64)) {
				t.Fatal("plaintext staging leak", path)
			}
		}
		return nil
	})
	m, e := CollectResumable(context.Background(), o, work, true)
	if e != nil {
		t.Fatal(e)
	}
	if len(m.Epochs) != 2 {
		t.Fatal(m.Epochs)
	}
	b, _ := os.ReadFile(o.Out)
	if !bytes.HasPrefix(b, magic) {
		t.Fatal("unencrypted output")
	}
	plain := filepath.Join(d, "plain.k957")
	if e = Transform(o.Out, plain, o.EncryptionKey, true); e != nil {
		t.Fatal(e)
	}
	p, e := Open(plain, filepath.Join(d, "sign.pub"))
	if e != nil {
		t.Fatal(e)
	}
	p.Zip.Close()
}
func TestEncryptedWrongKeyAndMode(t *testing.T) {
	d, o, work := encryptedFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	collectResumable(ctx, o, work, false, cancel)
	cancel()
	before, _ := os.ReadFile(filepath.Join(work, "state.enc"))
	bad := o
	bad.EncryptionKey = filepath.Join(d, "wrong.key")
	EncryptionKey(bad.EncryptionKey)
	if _, e := CollectResumable(context.Background(), bad, work, true); e == nil {
		t.Fatal("wrong key accepted")
	}
	after, _ := os.ReadFile(filepath.Join(work, "state.enc"))
	if !bytes.Equal(before, after) {
		t.Fatal("state modified by wrong key")
	}
	bad.EncryptionKey = ""
	if _, e := CollectResumable(context.Background(), bad, work, true); e == nil {
		t.Fatal("downgrade accepted")
	}
}
func TestEncryptedTampering(t *testing.T) {
	_, o, work := encryptedFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	collectResumable(ctx, o, work, false, cancel)
	cancel()
	c, _ := newWorkCrypto(o.EncryptionKey)
	var s WorkState
	readWork(work, &s, c)
	path := filepath.Join(work, "chunks", c.name(s.Files[0].Item.Parts[0].SHA256))
	b, _ := os.ReadFile(path)
	b[len(b)-1] ^= 1
	os.WriteFile(path, b, 0600)
	if _, e := InspectWork(context.Background(), work, true, o.EncryptionKey); e == nil {
		t.Fatal("bad chunk accepted")
	}
	path = filepath.Join(work, "state.enc")
	b, _ = os.ReadFile(path)
	b[len(b)-1] ^= 1
	os.WriteFile(path, b, 0600)
	if _, e := InspectWork(context.Background(), work, false, o.EncryptionKey); e == nil {
		t.Fatal("bad state accepted")
	}
}
func TestStageDomainSeparation(t *testing.T) {
	d := t.TempDir()
	key := filepath.Join(d, "key")
	EncryptionKey(key)
	c, _ := newWorkCrypto(key)
	b, _ := c.seal("state", []byte("secret"))
	if _, e := c.open("chunk:abc", b); e == nil {
		t.Fatal("cross-purpose accepted")
	}
	b2, _ := c.seal("state", []byte("secret"))
	if bytes.Equal(b, b2) {
		t.Fatal("nonce reused")
	}
	plain, e := c.open("state", b)
	if e != nil || string(plain) != "secret" {
		t.Fatal(e)
	}
	if c.name("abcd") == "abcd" {
		t.Fatal("plain filename")
	}
}
func TestEncryptionKeyIsolation(t *testing.T) {
	_, o, work := encryptedFixture(t)
	copyKey := filepath.Join(o.Root, "secret.key")
	b, _ := os.ReadFile(o.EncryptionKey)
	os.WriteFile(copyKey, b, 0600)
	o.EncryptionKey = copyKey
	if _, e := CollectResumable(context.Background(), o, work, false); e == nil {
		t.Fatal("collected key")
	}
	if _, e := Collect(context.Background(), o); e == nil {
		t.Fatal("silently ignored encryption")
	}
}

type brokenWriter struct{}

func (brokenWriter) Write(b []byte) (int, error) { return 0, errors.New("injected disk write error") }
func TestEncryptedPipelineWriteFailure(t *testing.T) {
	_, o, work := encryptedFixture(t)
	m, e := CollectResumable(context.Background(), o, work, false)
	if e != nil {
		t.Fatal(e)
	}
	c, _ := newWorkCrypto(o.EncryptionKey)
	done := make(chan error, 1)
	go func() { done <- writeEncryptedWork(context.Background(), work, brokenWriter{}, m, nil, c) }()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("write error lost")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("encrypted pipe deadlock")
	}
}
func TestPlainWorkCannotConvertInPlace(t *testing.T) {
	d, o := fixture(t, false)
	work := filepath.Join(d, "work")
	if _, e := CollectResumable(context.Background(), o, work, false); e != nil {
		t.Fatal(e)
	}
	o.Out = filepath.Join(d, "encrypted")
	o.EncryptionKey = filepath.Join(d, "key")
	EncryptionKey(o.EncryptionKey)
	if _, e := CollectResumable(context.Background(), o, work, true); e == nil {
		t.Fatal("in-place mode change")
	}
}
