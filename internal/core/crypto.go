package core

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strings"
)

// Envelope: magic, random 8-byte nonce prefix, repeated length + AEAD frame.
// Each frame authenticates the header and its monotonic index. Empty final
// frame is mandatory; absence, reordering, and trailing bytes are rejected.
var magic = []byte("K957ENC1")

const chunkSize = 1 << 20

func EncryptionKey(path string) error {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		return e
	}
	return WriteNew(path, []byte(hex.EncodeToString(b)+"\n"))
}
func cryptKey(path string) (cipher.AEAD, error) {
	b, e := ReadLimited(path, 4096)
	if e != nil {
		return nil, e
	}
	key, e := hex.DecodeString(strings.TrimSpace(string(b)))
	if e != nil || len(key) != 32 {
		return nil, errors.New("encryption key must be 32 bytes hex")
	}
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	return cipher.NewGCM(block)
}
func Transform(in, out, key string, decrypt bool) (err error) {
	a, e := cryptKey(key)
	if e != nil {
		return e
	}
	src, e := os.Open(in)
	if e != nil {
		return e
	}
	defer src.Close()
	dst, e := os.OpenFile(out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	ok := false
	defer func() {
		dst.Close()
		if !ok {
			os.Remove(out)
		}
	}()
	if decrypt {
		e = decryptStream(src, dst, a)
	} else {
		e = encryptStream(src, dst, a)
	}
	if e != nil {
		return e
	}
	if e = dst.Sync(); e != nil {
		return e
	}
	if e = dst.Close(); e != nil {
		return e
	}
	ok = true
	return nil
}
func nonce(header []byte, index uint32) []byte {
	n := make([]byte, 12)
	copy(n, header[8:])
	binary.BigEndian.PutUint32(n[8:], index)
	return n
}
func encryptStream(r io.Reader, w io.Writer, a cipher.AEAD) error {
	header := make([]byte, 16)
	copy(header, magic)
	if _, e := rand.Read(header[8:]); e != nil {
		return e
	}
	if _, e := w.Write(header); e != nil {
		return e
	}
	buf := make([]byte, chunkSize)
	for i := uint32(0); ; i++ {
		if i == ^uint32(0) {
			return errors.New("nonce limit")
		}
		n, e := io.ReadFull(r, buf)
		if e != nil && e != io.EOF && e != io.ErrUnexpectedEOF {
			return e
		}
		ct := a.Seal(nil, nonce(header, i), buf[:n], header)
		if e = binary.Write(w, binary.BigEndian, uint32(len(ct))); e != nil {
			return e
		}
		if _, e = w.Write(ct); e != nil {
			return e
		}
		if n == 0 {
			return nil
		}
	}
}
func decryptStream(r io.Reader, w io.Writer, a cipher.AEAD) error {
	header := make([]byte, 16)
	if _, e := io.ReadFull(r, header); e != nil {
		return e
	}
	if !bytes.Equal(header[:8], magic) {
		return errors.New("invalid envelope")
	}
	for i := uint32(0); ; i++ {
		if i == ^uint32(0) {
			return errors.New("nonce limit")
		}
		var n uint32
		if e := binary.Read(r, binary.BigEndian, &n); e != nil {
			return e
		}
		if n < uint32(a.Overhead()) || n > chunkSize+uint32(a.Overhead()) {
			return errors.New("invalid frame length")
		}
		ct := make([]byte, n)
		if _, e := io.ReadFull(r, ct); e != nil {
			return e
		}
		p, e := a.Open(nil, nonce(header, i), ct, header)
		if e != nil {
			return e
		}
		if len(p) == 0 {
			var b [1]byte
			n, e := r.Read(b[:])
			if n != 0 || e != io.EOF {
				return errors.New("trailing envelope data")
			}
			return nil
		}
		if _, e = w.Write(p); e != nil {
			return e
		}
	}
}
