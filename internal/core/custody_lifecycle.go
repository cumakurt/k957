package core

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"
)

type CustodyKeyPolicy struct {
	PublicKey      string     `json:"public_key"`
	ValidFrom      *time.Time `json:"valid_from,omitempty"`
	ValidUntil     *time.Time `json:"valid_until,omitempty"`
	RevokedAt      *time.Time `json:"revoked_at,omitempty"`
	RevocationMode string     `json:"revocation_mode,omitempty"`
	Reason         string     `json:"reason,omitempty"`
}

func validateCustodyLifecycle(trust CustodyTrust, keys map[string]string) error {
	if len(trust.Lifecycle) > 1000 {
		return errors.New("custody lifecycle exceeds bounds")
	}
	seen := map[string]bool{}
	for _, policy := range trust.Lifecycle {
		if keys[policy.PublicKey] == "" || seen[policy.PublicKey] {
			return errors.New("unknown or duplicate lifecycle key")
		}
		seen[policy.PublicKey] = true
		for _, stamp := range []*time.Time{policy.ValidFrom, policy.ValidUntil, policy.RevokedAt} {
			if stamp != nil && stamp.IsZero() {
				return errors.New("empty custody key validity timestamp")
			}
		}
		if policy.ValidFrom != nil && policy.ValidUntil != nil && !policy.ValidFrom.Before(*policy.ValidUntil) {
			return errors.New("invalid custody key interval")
		}
		if policy.RevokedAt != nil {
			if (policy.RevocationMode != "from_time" && policy.RevocationMode != "all_history") || !custodyText(policy.Reason, 4096, true) {
				return errors.New("revocation requires from_time/all_history mode and reason")
			}
		} else if policy.RevocationMode != "" {
			return errors.New("revocation mode requires revoked_at")
		}
		if len(policy.Reason) > 4096 {
			return errors.New("custody key policy reason exceeds bounds")
		}
	}
	return nil
}

func custodyKeyAllowed(trust CustodyTrust, public string, recorded time.Time) error {
	for _, policy := range trust.Lifecycle {
		if policy.PublicKey != public {
			continue
		}
		if policy.ValidFrom != nil && recorded.Before(*policy.ValidFrom) {
			return errors.New("custody key was not valid at declared recording time")
		}
		if policy.ValidUntil != nil && !recorded.Before(*policy.ValidUntil) {
			return errors.New("custody key expired at declared recording time")
		}
		if policy.RevokedAt != nil && (policy.RevocationMode == "all_history" || !recorded.Before(*policy.RevokedAt)) {
			return errors.New("custody key is revoked for this declared recording time")
		}
	}
	return nil
}

const custodyAnchorSchema = "k957-custody-anchor/1"
const custodyAnchorDomain = "k957/custody/anchor/v1\x00"

func LoadCustodyAnchor(path string) (anchor CustodyAnchor, err error) {
	err = strictJSON(path, 64<<10, &anchor)
	return
}

type CustodyAnchorClaim struct {
	Schema         string    `json:"schema"`
	EvidenceDigest string    `json:"evidence_digest"`
	EvidenceID     string    `json:"evidence_id"`
	Case           string    `json:"case"`
	Head           string    `json:"head"`
	Sequence       int       `json:"sequence"`
	TrustDigest    string    `json:"trust_digest"`
	Created        time.Time `json:"created"`
	Witness        string    `json:"witness"`
	Reference      string    `json:"reference"`
}
type CustodyAnchor struct {
	Schema    string `json:"schema"`
	Payload   string `json:"payload_base64"`
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`
}

func AnchorCustody(ledger CustodyLedger, trust CustodyTrust, keyPath, witness, reference string) (anchor CustodyAnchor, err error) {
	state, err := ValidateCustody(ledger, ledger.EvidenceDigest, ledger.EvidenceID, ledger.Case, trust, "")
	if err != nil {
		return anchor, err
	}
	if !custodyText(witness, 256, false) || !custodyText(reference, 4096, true) {
		return anchor, errors.New("anchor requires witness identity and retention reference")
	}
	body, err := ReadLimited(keyPath, 4096)
	if err != nil {
		return anchor, err
	}
	key, err := decodePrivate(body)
	if err != nil {
		return anchor, err
	}
	claim := CustodyAnchorClaim{custodyAnchorSchema, ledger.EvidenceDigest, ledger.EvidenceID, ledger.Case, state.Head, len(ledger.Events), state.TrustDigest, time.Now().UTC(), witness, reference}
	payload, err := MarshalJSON(claim)
	if err != nil {
		return anchor, err
	}
	anchor = CustodyAnchor{Schema: custodyAnchorSchema, Payload: base64.StdEncoding.EncodeToString(payload), PublicKey: hex.EncodeToString(key.Public().(ed25519.PublicKey)), Signature: hex.EncodeToString(ed25519.Sign(key, append([]byte(custodyAnchorDomain), payload...)))}
	return anchor, nil
}

func VerifyCustodyAnchor(anchor CustodyAnchor, ledger CustodyLedger, trust CustodyTrust, trustedKey string) (claim CustodyAnchorClaim, err error) {
	if anchor.Schema != custodyAnchorSchema || trustedKey == "" {
		return claim, errors.New("anchor requires explicit externally trusted witness public key")
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(anchor.Payload)
	if err != nil || len(payload) > 16384 || base64.StdEncoding.EncodeToString(payload) != anchor.Payload {
		return claim, errors.New("invalid anchor payload")
	}
	if err = custodyJSON(payload, &claim); err != nil {
		return claim, err
	}
	pub, err := custodyHex(anchor.PublicKey, ed25519.PublicKeySize)
	if err != nil {
		return claim, err
	}
	sig, err := custodyHex(anchor.Signature, ed25519.SignatureSize)
	if err != nil {
		return claim, err
	}
	trusted, err := loadPublic(trustedKey)
	if err != nil {
		return claim, err
	}
	if !ed25519.PublicKey(pub).Equal(trusted) || !ed25519.Verify(pub, append([]byte(custodyAnchorDomain), payload...), sig) {
		return claim, errors.New("custody anchor signer/signature differs from trusted witness")
	}
	if claim.Schema != custodyAnchorSchema || claim.Created.IsZero() || !custodyText(claim.Witness, 256, false) || !custodyText(claim.Reference, 4096, true) || claim.Sequence != len(ledger.Events) || claim.EvidenceDigest != ledger.EvidenceDigest || claim.EvidenceID != ledger.EvidenceID || claim.Case != ledger.Case || claim.TrustDigest != digestJSON(trust) {
		return claim, errors.New("custody anchor does not bind this ledger/trust policy")
	}
	_, err = ValidateCustody(ledger, ledger.EvidenceDigest, ledger.EvidenceID, ledger.Case, trust, claim.Head)
	return claim, err
}
