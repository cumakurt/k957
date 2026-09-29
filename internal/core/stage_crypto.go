package core

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
)

const stageMode = "aes256-gcm-stage/1"
const stageMagic = "K957STG1"
const stageOverhead = 8 + 12 + 16

// Keys are domain separated: staging ciphertext, opaque filenames and the
// existing transport envelope use distinct key material/purposes.
type workCrypto struct {
	aead      cipher.AEAD
	transport cipher.AEAD
	nameKey   []byte
}

func newWorkCrypto(path string) (*workCrypto, error) {
	if path == "" {
		return nil, nil
	}
	b, e := ReadLimited(path, 4096)
	if e != nil {
		return nil, e
	}
	master, e := hex.DecodeString(strings.TrimSpace(string(b)))
	if e != nil || len(master) != 32 {
		return nil, errors.New("encryption key must be 32 bytes hex")
	}
	derive := func(label string) []byte {
		h := hmac.New(sha256.New, master)
		h.Write([]byte(label))
		return h.Sum(nil)
	}
	block, e := aes.NewCipher(derive("k957/stage/aead/v1"))
	if e != nil {
		return nil, e
	}
	a, e := cipher.NewGCM(block)
	if e != nil {
		return nil, e
	}
	transportBlock, _ := aes.NewCipher(master)
	transport, e := cipher.NewGCM(transportBlock)
	if e != nil {
		return nil, e
	}
	return &workCrypto{aead: a, transport: transport, nameKey: derive("k957/stage/name/v1")}, nil
}
func chooseCrypto(cs []*workCrypto) *workCrypto {
	if len(cs) > 0 {
		return cs[0]
	}
	return nil
}
func (c *workCrypto) name(hash string) string {
	if c == nil {
		return hash
	}
	h := hmac.New(sha256.New, c.nameKey)
	h.Write([]byte(hash))
	return hex.EncodeToString(h.Sum(nil))
}
func (c *workCrypto) stateName() string {
	if c == nil {
		return "state.json"
	}
	return "state.enc"
}
func (c *workCrypto) seal(purpose string, b []byte) ([]byte, error) {
	if c == nil {
		return b, nil
	}
	nonce := make([]byte, 12)
	if _, e := rand.Read(nonce); e != nil {
		return nil, e
	}
	out := append([]byte(stageMagic), nonce...)
	return c.aead.Seal(out, nonce, b, []byte(stageMode+":"+purpose)), nil
}
func (c *workCrypto) open(purpose string, b []byte) ([]byte, error) {
	if c == nil {
		return b, nil
	}
	if len(b) < stageOverhead || !bytes.Equal(b[:8], []byte(stageMagic)) {
		return nil, errors.New("invalid encrypted staging envelope")
	}
	return c.aead.Open(nil, b[8:20], b[20:], []byte(stageMode+":"+purpose))
}
