package core

import (
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
)

var attackTechniquePattern = regexp.MustCompile(`^T[0-9]{4}(?:\.[0-9]{3})?$`)

type attackMapping struct {
	Technique string `json:"technique"`
	Finding   string `json:"finding_id"`
	Rule      string `json:"rule_id"`
	Evidence  string `json:"evidence"`
	Source    string `json:"source"`
	Review    string `json:"review"`
}
type attackMetadata struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type attackTechnique struct {
	ID       string           `json:"techniqueID"`
	Score    int              `json:"score"`
	Enabled  bool             `json:"enabled"`
	Comment  string           `json:"comment"`
	Metadata []attackMetadata `json:"metadata"`
}
type attackLayer struct {
	Name        string            `json:"name"`
	Versions    map[string]string `json:"versions"`
	Domain      string            `json:"domain"`
	Description string            `json:"description"`
	Techniques  []attackTechnique `json:"techniques"`
	Metadata    []attackMetadata  `json:"metadata"`
}

func exportAttackLayer(a Analysis, out string) error {
	byRule := map[string][]string{}
	for _, r := range a.Rules {
		if len(r.Techniques) > 0 {
			byRule[r.ID] = r.Techniques
		}
	}
	if len(byRule) == 0 {
		return nil
	}
	mappings := []attackMapping{}
	counts := map[string]int{}
	rejected := map[string]int{}
	for _, f := range a.Findings {
		for _, id := range byRule[f.Rule] {
			mappings = append(mappings, attackMapping{id, f.ID, f.Rule, f.Evidence, f.Source, f.Review})
			if f.Review == "rejected" {
				rejected[id]++
			} else {
				counts[id]++
			}
		}
	}
	set := map[string]bool{}
	for _, ids := range byRule {
		for _, id := range ids {
			set[id] = true
		}
	}
	ids := []string{}
	for id := range set {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	note := "Technique mappings are examiner-supplied rule metadata, not inferred from text. Scores count non-rejected findings in this analysis projection, not severity, confidence, confirmed activity or full memory hit counts. Full memory results remain in their private JSONL. ID syntax is checked; membership in a particular ATT&CK release is not verified."
	layer := attackLayer{Name: "k957 / " + a.Manifest.Case, Versions: map[string]string{"layer": "4.5"}, Domain: "enterprise-attack", Description: note, Techniques: []attackTechnique{}, Metadata: []attackMetadata{{"evidence SHA-256", a.EvidenceDigest}, {"rules SHA-256", digestJSON(a.Rules)}}}
	for _, id := range ids {
		layer.Techniques = append(layer.Techniques, attackTechnique{id, counts[id], true, "Review source-linked candidates in attack-mappings.json.", []attackMetadata{{"rejected findings", strconv.Itoa(rejected[id])}}})
	}
	if e := WriteJSONNew(filepath.Join(out, "attack-navigator.json"), layer); e != nil {
		return e
	}
	return WriteJSONNew(filepath.Join(out, "attack-mappings.json"), struct {
		Schema string          `json:"schema"`
		Note   string          `json:"note"`
		Rows   []attackMapping `json:"rows"`
	}{"k957-attack-mappings/1", note, mappings})
}
