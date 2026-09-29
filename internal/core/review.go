package core

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const reviewSchema = "k957-review/1"

type ReviewEvent struct {
	Sequence int       `json:"sequence"`
	Finding  string    `json:"finding"`
	Decision string    `json:"decision"`
	Analyst  string    `json:"analyst"`
	Note     string    `json:"note"`
	Created  time.Time `json:"created"`
	Previous string    `json:"previous"`
	Hash     string    `json:"hash"`
}
type ReviewLedger struct {
	Schema         string        `json:"schema"`
	Basis          string        `json:"basis"`
	Case           string        `json:"case"`
	EvidenceDigest string        `json:"evidence_digest"`
	Events         []ReviewEvent `json:"events"`
	Signature      string        `json:"signature,omitempty"`
}

func digestJSON(v any) string { h := sha256.Sum256(JSON(v)); return hex.EncodeToString(h[:]) }
func findingID(evidence string, f Finding) string {
	return "F-" + digestJSON(struct {
		Evidence, Rule, SourceID, Source string
		Line                             int
		Excerpt                          string
	}{evidence, f.Rule, f.Evidence, f.Source, f.Line, f.Excerpt})
}
func reviewBasis(a Analysis) string {
	fs := make([]Finding, len(a.Findings))
	copy(fs, a.Findings)
	for i := range fs {
		fs[i].Review = "unreviewed"
		fs[i].Reviewer = ""
		fs[i].ReviewNote = ""
	}
	return digestJSON(struct {
		Version, Evidence string
		Rules             []Rule
		Findings          []Finding
	}{a.Version, a.EvidenceDigest, a.Rules, fs})
}
func strictJSON(path string, limit int64, v any) error {
	b, e := ReadLimited(path, limit)
	if e != nil {
		return e
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if e = dec.Decode(v); e != nil {
		return e
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

// Analysis is used to address findings, never as proof of package integrity.
// Applying a ledger requires a fresh analysis of a verified evidence package.
func LoadAnalysis(path string) (a Analysis, err error) {
	if err = strictJSON(path, 128<<20, &a); err != nil {
		return
	}
	if a.Version != Version || !validHash(a.EvidenceDigest) || a.Manifest.Case == "" || len(a.Findings) > 10000 {
		err = errors.New("unsupported analysis; regenerate with current version")
		return
	}
	seen := map[string]bool{}
	for _, f := range a.Findings {
		if f.ID != findingID(a.EvidenceDigest, f) || seen[f.ID] {
			err = errors.New("invalid or duplicate finding ID")
			return
		}
		seen[f.ID] = true
	}
	return
}
func eventHash(basis string, e ReviewEvent) string {
	e.Hash = ""
	return digestJSON(struct {
		Basis string
		Event ReviewEvent
	}{basis, e})
}
func ledgerBytes(l ReviewLedger) []byte { l.Signature = ""; return JSON(l) }
func validDecision(s string) bool       { return s == "confirmed" || s == "rejected" || s == "needs-review" }
func ValidateLedger(l ReviewLedger, a Analysis, trustedKey string) (string, error) {
	if l.Schema != reviewSchema || l.Basis != reviewBasis(a) || l.EvidenceDigest != a.EvidenceDigest || l.Case != a.Manifest.Case || len(l.Events) == 0 || len(l.Events) > 10000 {
		return "", errors.New("ledger does not match analysis basis or bounds")
	}
	ids := map[string]bool{}
	for _, f := range a.Findings {
		ids[f.ID] = true
	}
	prev := ""
	for i, e := range l.Events {
		if e.Sequence != i+1 || !ids[e.Finding] || !validDecision(e.Decision) || strings.TrimSpace(e.Analyst) == "" || len(e.Analyst) > 256 || strings.TrimSpace(e.Note) == "" || len(e.Note) > 16000 || e.Created.IsZero() || e.Previous != prev || e.Hash != eventHash(l.Basis, e) {
			return "", errors.New("invalid review history or hash chain")
		}
		prev = e.Hash
	}
	status := "unsigned; analyst identity not authenticated"
	if l.Signature != "" {
		sig, e := hex.DecodeString(l.Signature)
		if e != nil || len(sig) != ed25519.SignatureSize {
			return "", errors.New("invalid review signature encoding")
		}
		status = "present, not authenticated"
		if trustedKey != "" {
			pub, e := loadPublic(trustedKey)
			if e != nil {
				return "", e
			}
			if !ed25519.Verify(pub, ledgerBytes(l), sig) {
				return "", errors.New("review signature verification failed")
			}
			status = "verified against supplied trusted review key"
		}
	} else if trustedKey != "" {
		return "", errors.New("review ledger is unsigned")
	}
	return status, nil
}
func LoadLedger(path string) (l ReviewLedger, e error) { e = strictJSON(path, 32<<20, &l); return }
func AddReview(a Analysis, previous *ReviewLedger, finding, decision, analyst, note, signKey, previousKey string) (l ReviewLedger, err error) {
	if !validDecision(decision) || strings.TrimSpace(analyst) == "" || len(analyst) > 256 || strings.TrimSpace(note) == "" || len(note) > 16000 {
		return l, errors.New("decision must be confirmed/rejected/needs-review; analyst and reason required")
	}
	found := false
	for _, f := range a.Findings {
		if f.ID == finding {
			found = true
		}
	}
	if !found {
		return l, errors.New("finding ID not present in analysis")
	}
	l = ReviewLedger{Schema: reviewSchema, Basis: reviewBasis(a), Case: a.Manifest.Case, EvidenceDigest: a.EvidenceDigest, Events: []ReviewEvent{}}
	if previous != nil {
		if _, err = ValidateLedger(*previous, a, previousKey); err != nil {
			return
		}
		if previous.Signature != "" && (previousKey == "" || signKey == "") {
			return l, errors.New("extending signed history requires previous trusted key and new signing key")
		}
		l.Events = append(l.Events, previous.Events...)
	} else if previousKey != "" {
		return l, errors.New("previous key supplied without previous ledger")
	}
	if len(l.Events) >= 10000 {
		return l, errors.New("review event limit reached")
	}
	prev := ""
	if len(l.Events) > 0 {
		prev = l.Events[len(l.Events)-1].Hash
	}
	event := ReviewEvent{Sequence: len(l.Events) + 1, Finding: finding, Decision: decision, Analyst: analyst, Note: note, Created: time.Now().UTC(), Previous: prev}
	event.Hash = eventHash(l.Basis, event)
	l.Events = append(l.Events, event)
	if signKey != "" {
		b, e := ReadLimited(signKey, 4096)
		if e != nil {
			return l, e
		}
		key, e := decodePrivate(b)
		if e != nil {
			return l, e
		}
		l.Signature = hex.EncodeToString(ed25519.Sign(key, ledgerBytes(l)))
	}
	if len(JSON(l)) > 32<<20 {
		return l, errors.New("review ledger exceeds 32 MiB limit")
	}
	return
}
func ApplyReviews(a *Analysis, l ReviewLedger, trustedKey string) error {
	status, e := ValidateLedger(l, *a, trustedKey)
	if e != nil {
		return e
	}
	byID := map[string]int{}
	for i := range a.Findings {
		byID[a.Findings[i].ID] = i
		a.Findings[i].Review = "unreviewed"
		a.Findings[i].Reviewer = ""
		a.Findings[i].ReviewNote = ""
	}
	for _, r := range l.Events {
		f := &a.Findings[byID[r.Finding]]
		f.Review = r.Decision
		f.Reviewer = r.Analyst
		f.ReviewNote = r.Note
	}
	a.ReviewHistory = append([]ReviewEvent{}, l.Events...)
	a.ReviewSignature = status
	a.ReviewDigest = digestJSON(l)
	a.Notes = append(a.Notes, fmt.Sprintf("%d analyst review events applied. Decisions express the analyst's assessment; a hash chain alone does not authenticate identity or prove history completeness.", len(l.Events)))
	return nil
}
