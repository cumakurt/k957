package core

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const custodySchema = "k957-custody/1"
const custodyClaimSchema = "k957-custody-event/1"
const custodyTrustSchema = "k957-custody-trust/1"
const custodySignDomain = "k957/custody/signature/v1\x00"
const custodyHeadDomain = "k957/custody/head/v1\x00"

// Payload preserves the exact signed bytes, avoiding cross-language JSON
// canonicalization. Events retain all prior signatures, including across keys.
type CustodyEntry struct {
	Payload   string `json:"payload_base64"`
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`
	Hash      string `json:"hash"`
}
type CustodyLedger struct {
	Schema         string         `json:"schema"`
	Case           string         `json:"case"`
	EvidenceID     string         `json:"evidence_id"`
	EvidenceDigest string         `json:"evidence_digest"`
	Events         []CustodyEntry `json:"events"`
}
type CustodyClaim struct {
	Schema         string    `json:"schema"`
	Case           string    `json:"case"`
	EvidenceID     string    `json:"evidence_id"`
	EvidenceDigest string    `json:"evidence_digest"`
	Sequence       int       `json:"sequence"`
	Action         string    `json:"action"`
	Actor          string    `json:"actor"`
	From           string    `json:"from"`
	To             string    `json:"to"`
	Location       string    `json:"location"`
	Note           string    `json:"note"`
	OccurredAt     time.Time `json:"occurred_at"`
	RecordedAt     time.Time `json:"recorded_at"`
	Previous       string    `json:"previous"`
	Signer         string    `json:"signer_sha256"`
}
type CustodyIdentity struct {
	Actor     string `json:"actor"`
	PublicKey string `json:"public_key"`
}
type CustodyTrust struct {
	Schema    string             `json:"schema"`
	Keys      []CustodyIdentity  `json:"keys"`
	Lifecycle []CustodyKeyPolicy `json:"lifecycle,omitempty"`
}
type CustodyRequest struct {
	Action, Actor, To, Location, Note string
	OccurredAt                        time.Time
}
type CustodyStatus struct {
	EvidenceDigest string         `json:"evidence_digest"`
	Head           string         `json:"head"`
	CurrentHolder  string         `json:"current_holder"`
	PendingTo      string         `json:"pending_to,omitempty"`
	Trust          string         `json:"trust"`
	TrustDigest    string         `json:"trust_digest"`
	TimeAssurance  string         `json:"time_assurance"`
	Events         []CustodyClaim `json:"events"`
}

func custodyText(s string, n int, multiline bool) bool {
	if strings.TrimSpace(s) == "" || len(s) > n || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) && !(multiline && (r == '\n' || r == '\r' || r == '\t')) {
			return false
		}
	}
	return multiline || s == strings.TrimSpace(s)
}
func custodyHex(s string, size int) ([]byte, error) {
	b, e := hex.DecodeString(s)
	if e != nil || len(b) != size || hex.EncodeToString(b) != s {
		return nil, errors.New("invalid lowercase hex encoding")
	}
	return b, nil
}
func custodyTrustMap(t CustodyTrust) (map[string]string, error) {
	if t.Schema != custodyTrustSchema || len(t.Keys) == 0 || len(t.Keys) > 1000 {
		return nil, errors.New("invalid custody trust schema or bounds")
	}
	keys := map[string]string{}
	for _, k := range t.Keys {
		if !custodyText(k.Actor, 256, false) {
			return nil, errors.New("invalid custody actor")
		}
		if _, e := custodyHex(k.PublicKey, ed25519.PublicKeySize); e != nil {
			return nil, e
		}
		if _, ok := keys[k.PublicKey]; ok {
			return nil, errors.New("duplicate custody key; one key must identify one actor")
		}
		keys[k.PublicKey] = k.Actor
	}
	if err := validateCustodyLifecycle(t, keys); err != nil {
		return nil, err
	}
	return keys, nil
}

// Reject duplicate object keys as well as unknown fields: signed data must not
// have conflicting interpretations in another JSON implementation.
func custodyJSON(b []byte, v any) error {
	if !utf8.Valid(b) {
		return errors.New("invalid UTF-8 JSON")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 32 {
			return errors.New("JSON nesting limit exceeded")
		}
		tok, e := dec.Token()
		if e != nil {
			return e
		}
		d, ok := tok.(json.Delim)
		if !ok {
			return nil
		}
		switch d {
		case '{':
			seen := map[string]bool{}
			for dec.More() {
				k, e := dec.Token()
				if e != nil {
					return e
				}
				name, ok := k.(string)
				if !ok || name != strings.ToLower(name) || seen[name] {
					return errors.New("duplicate or invalid JSON key")
				}
				seen[name] = true
				if e = walk(depth + 1); e != nil {
					return e
				}
			}
		case '[':
			for dec.More() {
				if e := walk(depth + 1); e != nil {
					return e
				}
			}
		default:
			return errors.New("invalid JSON delimiter")
		}
		_, e = dec.Token()
		return e
	}
	if e := walk(0); e != nil {
		return e
	}
	if _, e := dec.Token(); e != io.EOF {
		return errors.New("trailing JSON")
	}
	dec = json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}
func LoadCustody(path string) (l CustodyLedger, e error) {
	b, e := ReadLimited(path, 32<<20)
	if e == nil {
		e = custodyJSON(b, &l)
	}
	return
}
func LoadCustodyTrust(path string) (t CustodyTrust, e error) {
	if path == "" {
		return t, errors.New("external custody trust file required")
	}
	b, e := ReadLimited(path, 1<<20)
	if e != nil {
		return t, e
	}
	if e = custodyJSON(b, &t); e != nil {
		return t, e
	}
	_, e = custodyTrustMap(t)
	return
}
func custodyHead(pub, sig, payload []byte) string {
	h := sha256.New()
	h.Write([]byte(custodyHeadDomain))
	h.Write(pub)
	h.Write(sig)
	h.Write(payload)
	return hex.EncodeToString(h.Sum(nil))
}
func custodySigner(pub []byte) string { h := sha256.Sum256(pub); return hex.EncodeToString(h[:]) }

// Transition rules describe signed declarations. They do not prove that a
// physical handover took place. CurrentHolder changes only after acceptance.
func custodyTransition(holder, pending, action, actor, recipient string) (from, to, nextHolder, nextPending string, err error) {
	fail := func() (string, string, string, string, error) {
		return "", "", "", "", errors.New("invalid custody transition, actor or recipient")
	}
	if !custodyText(actor, 256, false) {
		return fail()
	}
	if holder == "" {
		if action != "register" || recipient != "" {
			return fail()
		}
		return "", actor, actor, "", nil
	}
	switch action {
	case "transfer":
		if pending != "" || actor != holder || recipient == holder || !custodyText(recipient, 256, false) {
			return fail()
		}
		return holder, recipient, holder, recipient, nil
	case "accept":
		if pending == "" || actor != pending || recipient != "" {
			return fail()
		}
		return holder, pending, pending, "", nil
	case "cancel":
		if pending == "" || actor != holder || recipient != "" {
			return fail()
		}
		return holder, pending, holder, "", nil
	case "note":
		if pending != "" || actor != holder || recipient != "" {
			return fail()
		}
		return holder, holder, holder, "", nil
	default:
		return fail()
	}
}

// EvidenceDigest binds exact manifest bytes and the verified object hashes,
// not the incidental ZIP container layout. Caller must verify the package.
func ValidateCustody(l CustodyLedger, evidenceDigest, evidenceID, caseID string, t CustodyTrust, expectedHead string) (s CustodyStatus, err error) {
	keys, e := custodyTrustMap(t)
	if e != nil {
		return s, e
	}
	if l.Schema != custodySchema || !validHash(l.EvidenceDigest) || l.EvidenceDigest != evidenceDigest || l.EvidenceID != evidenceID || l.Case != caseID || len(l.Events) == 0 || len(l.Events) > 10000 || len(JSON(l)) > 32<<20 {
		return s, errors.New("custody ledger does not match verified evidence or bounds")
	}
	if expectedHead != "" && !validHash(expectedHead) {
		return s, errors.New("invalid expected custody head")
	}
	s = CustodyStatus{EvidenceDigest: evidenceDigest, Trust: "all event signatures verified against supplied actor/key trust list", TrustDigest: digestJSON(t), Events: []CustodyClaim{}}
	s.TimeAssurance = "Declared recorded_at values only; no independent trusted timestamp. External trust policy controls key intervals/revocation. A compromised signer can backdate assertions."
	var lastOccurred, lastRecorded time.Time
	for i, entry := range l.Events {
		payload, e := base64.StdEncoding.Strict().DecodeString(entry.Payload)
		if e != nil || len(payload) > 128<<10 || base64.StdEncoding.EncodeToString(payload) != entry.Payload {
			return s, errors.New("invalid custody payload encoding or size")
		}
		var c CustodyClaim
		if e = custodyJSON(payload, &c); e != nil {
			return s, e
		}
		pub, e := custodyHex(entry.PublicKey, ed25519.PublicKeySize)
		if e != nil {
			return s, e
		}
		sig, e := custodyHex(entry.Signature, ed25519.SignatureSize)
		if e != nil {
			return s, e
		}
		if c.Schema != custodyClaimSchema || c.Case != caseID || c.EvidenceID != evidenceID || c.EvidenceDigest != evidenceDigest || c.Sequence != i+1 || c.Previous != s.Head || c.Signer != custodySigner(pub) {
			return s, errors.New("custody event binding, sequence or chain mismatch")
		}
		if keys[entry.PublicKey] != c.Actor || !custodyText(c.Actor, 256, false) {
			return s, errors.New("custody signer not trusted for this actor")
		}
		if err := custodyKeyAllowed(t, entry.PublicKey, c.RecordedAt); err != nil {
			return s, err
		}
		if entry.Hash != custodyHead(pub, sig, payload) || !ed25519.Verify(pub, append([]byte(custodySignDomain), payload...), sig) {
			return s, errors.New("custody signature or event hash mismatch")
		}
		if !custodyText(c.Location, 1024, false) || !custodyText(c.Note, 16000, true) || c.OccurredAt.IsZero() || c.RecordedAt.IsZero() || c.OccurredAt.After(c.RecordedAt) || c.OccurredAt.Before(lastOccurred) || c.RecordedAt.Before(lastRecorded) {
			return s, errors.New("invalid custody text or non-monotonic declared timestamps")
		}
		recipient := ""
		if c.Action == "transfer" {
			recipient = c.To
		}
		from, to, holder, pending, e := custodyTransition(s.CurrentHolder, s.PendingTo, c.Action, c.Actor, recipient)
		if e != nil {
			return s, e
		}
		if c.From != from || c.To != to {
			return s, errors.New("custody parties differ from transition")
		}
		s.CurrentHolder, s.PendingTo, s.Head = holder, pending, entry.Hash
		s.Events = append(s.Events, c)
		lastOccurred, lastRecorded = c.OccurredAt, c.RecordedAt
	}
	if expectedHead != "" && expectedHead != s.Head {
		return s, errors.New("custody head differs from external expected head")
	}
	return s, nil
}
func AddCustody(p *Package, previous *CustodyLedger, r CustodyRequest, signKey string, t CustodyTrust, expectedHead string) (l CustodyLedger, err error) {
	if p == nil || !validHash(p.ManifestSHA256) {
		return l, errors.New("verified package required")
	}
	keys, e := custodyTrustMap(t)
	if e != nil {
		return l, e
	}
	l = CustodyLedger{Schema: custodySchema, Case: p.Manifest.Case, EvidenceID: p.Manifest.ID, EvidenceDigest: p.ManifestSHA256, Events: []CustodyEntry{}}
	var state CustodyStatus
	if previous != nil {
		state, e = ValidateCustody(*previous, l.EvidenceDigest, l.EvidenceID, l.Case, t, expectedHead)
		if e != nil {
			return l, e
		}
		l.Events = append(l.Events, previous.Events...)
	} else if expectedHead != "" {
		return l, errors.New("expected head requires previous custody ledger")
	}
	if len(l.Events) >= 10000 {
		return l, errors.New("custody event limit reached")
	}
	from, to, _, _, e := custodyTransition(state.CurrentHolder, state.PendingTo, r.Action, r.Actor, r.To)
	if e != nil {
		return l, e
	}
	if !custodyText(r.Location, 1024, false) || !custodyText(r.Note, 16000, true) {
		return l, errors.New("location and note required within bounds")
	}
	b, e := ReadLimited(signKey, 4096)
	if e != nil {
		return l, e
	}
	key, e := decodePrivate(b)
	if e != nil {
		return l, e
	}
	// Reject inconsistent 64-byte key files rather than signing with a bad suffix.
	derived := ed25519.NewKeyFromSeed(key.Seed())
	if !bytes.Equal(key, derived) {
		return l, errors.New("inconsistent Ed25519 private key")
	}
	pub := key.Public().(ed25519.PublicKey)
	if keys[hex.EncodeToString(pub)] != r.Actor {
		return l, errors.New("signing key is not trusted for actor")
	}
	now := time.Now().UTC()
	at := r.OccurredAt.UTC()
	if r.OccurredAt.IsZero() {
		at = now
	}
	c := CustodyClaim{Schema: custodyClaimSchema, Case: l.Case, EvidenceID: l.EvidenceID, EvidenceDigest: l.EvidenceDigest, Sequence: len(l.Events) + 1, Action: r.Action, Actor: r.Actor, From: from, To: to, Location: r.Location, Note: r.Note, OccurredAt: at, RecordedAt: now, Previous: state.Head, Signer: custodySigner(pub)}
	payload, err := MarshalJSON(c)
	if err != nil {
		return l, err
	}
	sig := ed25519.Sign(key, append([]byte(custodySignDomain), payload...))
	l.Events = append(l.Events, CustodyEntry{Payload: base64.StdEncoding.EncodeToString(payload), PublicKey: hex.EncodeToString(pub), Signature: hex.EncodeToString(sig), Hash: custodyHead(pub, sig, payload)})
	_, err = ValidateCustody(l, l.EvidenceDigest, l.EvidenceID, l.Case, t, "")
	return
}
func ApplyCustody(a *Analysis, l CustodyLedger, t CustodyTrust, expectedHead string) error {
	s, e := ValidateCustody(l, a.EvidenceDigest, a.Manifest.ID, a.Manifest.Case, t, expectedHead)
	if e != nil {
		return e
	}
	a.Custody = &s
	a.Notes = append(a.Notes, fmt.Sprintf("%d signed custody declarations verified against the supplied actor/key trust list. This is not proof of physical possession, civil identity or trusted time. Trust list provenance must be established outside this package. An independently retained expected head is needed to detect rollback or divergent histories.", len(s.Events)))
	return nil
}
