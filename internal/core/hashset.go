package core

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const hashSetSchema = "k957-hashset/1"

// HashMatch is one evidence object whose SHA-256 is in an examiner set.
type HashMatch struct {
	Host     string `json:"host,omitempty"`
	Evidence string `json:"evidence"`
	Source   string `json:"source"`
	SHA256   string `json:"sha256"`
	Verdict  string `json:"verdict"`
	Label    string `json:"label,omitempty"`
}

// HashSetSummary distinguishes an unused set from a set with no matches.
type HashSetSummary struct {
	SHA256    string `json:"sha256,omitempty"`
	Entries   int    `json:"entries"`
	Matched   int    `json:"matched"`
	Truncated bool   `json:"truncated"`
}

type hashEntry struct {
	Verdict string
	Label   string
}

// HashSet is an examiner-supplied SHA-256 list. It is not a malware verdict.
type HashSet struct {
	sourceSHA256 string
	byHash       map[string]hashEntry
}

func (s *HashSet) Lookup(sum string) (verdict, label string, ok bool) {
	if s == nil {
		return "", "", false
	}
	e, ok := s.byHash[strings.ToLower(sum)]
	if !ok {
		return "", "", false
	}
	return e.Verdict, e.Label, true
}

func (s *HashSet) Len() int {
	if s == nil {
		return 0
	}
	return len(s.byHash)
}

// LoadHashSet reads a k957-hashset/1 JSON document or a line-oriented list.
// A line is a SHA-256, optionally preceded by known-bad or known-good and
// followed by a label. A bare hash is known-bad. Comments start with #.
func LoadHashSet(path string) (*HashSet, error) {
	if path == "" {
		return nil, nil
	}
	b, e := ReadLimited(path, 32<<20)
	if e != nil {
		return nil, e
	}
	digest := sha256.Sum256(b)
	set := &HashSet{byHash: map[string]hashEntry{}, sourceSHA256: hex.EncodeToString(digest[:])}
	trimmed := bytes.TrimSpace(b)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		return set, decodeHashSetJSON(trimmed, set)
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		if e = set.addLine(sc.Text()); e != nil {
			return nil, fmt.Errorf("hash set line %d: %w", lineNo, e)
		}
	}
	if e = sc.Err(); e != nil {
		return nil, e
	}
	return set, nil
}

func decodeHashSetJSON(b []byte, set *HashSet) error {
	var doc struct {
		Schema  string `json:"schema"`
		Entries []struct {
			SHA256  string `json:"sha256"`
			Verdict string `json:"verdict"`
			Label   string `json:"label"`
		} `json:"entries"`
	}
	if e := custodyJSON(b, &doc); e != nil {
		return e
	}
	if doc.Schema != hashSetSchema {
		return errors.New("unsupported hash set schema")
	}
	for _, entry := range doc.Entries {
		if e := set.add(entry.Verdict, entry.SHA256, entry.Label); e != nil {
			return e
		}
	}
	return nil
}

func (s *HashSet) addLine(line string) error {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil
	}
	fields := strings.Fields(line)
	verdict := "known-bad"
	if fields[0] == "known-bad" || fields[0] == "known-good" {
		verdict = fields[0]
		fields = fields[1:]
		if len(fields) == 0 {
			return errors.New("missing hash")
		}
	}
	return s.add(verdict, fields[0], strings.Join(fields[1:], " "))
}

func (s *HashSet) add(verdict, sum, label string) error {
	if len(s.byHash) >= 500000 {
		return errors.New("hash set exceeds 500000 entries")
	}
	verdict = strings.ToLower(strings.TrimSpace(verdict))
	if verdict != "known-bad" && verdict != "known-good" {
		return errors.New("verdict must be known-bad or known-good")
	}
	sum = strings.ToLower(strings.TrimSpace(sum))
	if len(sum) != 64 || strings.Trim(sum, "0123456789abcdef") != "" {
		return errors.New("invalid sha256")
	}
	label = strings.TrimSpace(label)
	if len(label) > 200 {
		return errors.New("label too long")
	}
	if prev, ok := s.byHash[sum]; ok && (prev.Verdict != verdict || prev.Label != label) {
		return errors.New("conflicting hash set entry")
	}
	s.byHash[sum] = hashEntry{Verdict: verdict, Label: label}
	return nil
}

// ApplyHashSet records exact SHA-256 matches. known-bad also becomes an
// unreviewed finding. known-good is recorded and is not a finding.
func ApplyHashSet(a *Analysis, set *HashSet) {
	if set == nil || a == nil {
		return
	}
	a.HashSet = &HashSetSummary{Entries: set.Len(), SHA256: set.sourceSHA256}
	a.Notes = append(a.Notes, "Hash-set results are exact SHA-256 comparisons with an examiner-supplied list. A known-good match is not a trust decision. A known-bad match is not a malware verdict.")
	for _, it := range a.Manifest.Items {
		verdict, label, ok := set.Lookup(it.SHA256)
		if !ok {
			continue
		}
		a.HashSet.Matched++
		if len(a.HashMatches) >= findingLimit {
			if !a.HashSet.Truncated {
				a.Notes = append(a.Notes, "Hash-match limit reached: additional match details omitted")
			}
			a.HashSet.Truncated = true
			if verdict == "known-bad" {
				markFindingsTruncated(a)
			}
			continue
		}
		a.HashMatches = append(a.HashMatches, HashMatch{Evidence: it.ID, Source: it.Source, SHA256: strings.ToLower(it.SHA256), Verdict: verdict, Label: label})
		if verdict != "known-bad" {
			continue
		}
		f := Finding{Rule: "hashset", Description: hashsetDescription(label), Evidence: it.ID, Source: it.Source, Review: "unreviewed"}
		f.ID = findingID(a.EvidenceDigest, f)
		appendFinding(a, f)
	}
}

func hashsetDescription(label string) string {
	if label == "" {
		return "SHA-256 is listed as known-bad in the examiner hash set"
	}
	return "SHA-256 is listed as known-bad in the examiner hash set (" + label + ")"
}

func writeHashMatches(matches []HashMatch, path string) error {
	var b bytes.Buffer
	w := csv.NewWriter(&b)
	_ = w.Write([]string{"host", "evidence_id", "source", "sha256", "verdict", "label"})
	for _, m := range matches {
		_ = w.Write([]string{csvSafe(m.Host), m.Evidence, csvSafe(m.Source), m.SHA256, m.Verdict, csvSafe(m.Label)})
	}
	w.Flush()
	if e := w.Error(); e != nil {
		return e
	}
	return WriteNew(path, b.Bytes())
}
