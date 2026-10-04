package core

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const usnGroupPreviewLimit = 100

// A group is scoped to one acquired journal object and record version. It is a
// set of observations, not a reconstructed path, rename pair or file lifetime.
type USNFileGroup struct {
	Evidence   string           `json:"evidence"`
	Source     string           `json:"source"`
	Version    string           `json:"version"`
	FileID     string           `json:"file_id_le_hex"`
	Records    int              `json:"records"`
	First      time.Time        `json:"first_observed_time"`
	Last       time.Time        `json:"last_observed_time"`
	Names      []string         `json:"observed_names"`
	Parents    []string         `json:"parent_ids_le_hex"`
	Reasons    []string         `json:"observed_reasons"`
	References []USNGroupRecord `json:"references"`
}

type USNGroupRecord struct {
	Offset int64  `json:"byte_offset"`
	USN    string `json:"usn"`
}

type usnGroupKey struct{ evidence, source, version, id string }
type usnGroupAccumulator struct {
	group          USNFileGroup
	names, parents map[string]bool
	reasons        uint32
}

type usnGroupPreview struct {
	USNFileGroup
	NamesOmitted, ParentsOmitted int
}

func usnFileGroups(events []Event) []USNFileGroup {
	groups := map[usnGroupKey]*usnGroupAccumulator{}
	for _, event := range events {
		r := event.USN
		if r == nil {
			continue
		}
		key := usnGroupKey{event.Evidence, event.Source, r.Version, r.FileID}
		g := groups[key]
		if g == nil {
			g = &usnGroupAccumulator{group: USNFileGroup{Evidence: event.Evidence, Source: event.Source, Version: r.Version, FileID: r.FileID}, names: map[string]bool{}, parents: map[string]bool{}}
			groups[key] = g
		}
		g.group.Records++
		if !event.Time.IsZero() {
			if g.group.First.IsZero() || event.Time.Before(g.group.First) {
				g.group.First = event.Time
			}
			if g.group.Last.IsZero() || event.Time.After(g.group.Last) {
				g.group.Last = event.Time
			}
		}
		g.names[r.Name], g.parents[r.ParentID] = true, true
		g.reasons |= r.Reason
		g.group.References = append(g.group.References, USNGroupRecord{Offset: event.ByteOffset, USN: r.USN})
	}
	out := make([]USNFileGroup, 0, len(groups))
	for _, g := range groups {
		for name := range g.names {
			g.group.Names = append(g.group.Names, name)
		}
		for parent := range g.parents {
			g.group.Parents = append(g.group.Parents, parent)
		}
		sort.Strings(g.group.Names)
		sort.Strings(g.group.Parents)
		g.group.Reasons = usnReasons(g.reasons)
		sort.SliceStable(g.group.References, func(i, j int) bool { return g.group.References[i].Offset < g.group.References[j].Offset })
		out = append(out, g.group)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Evidence != b.Evidence {
			return a.Evidence < b.Evidence
		}
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		if a.Version != b.Version {
			return a.Version < b.Version
		}
		return a.FileID < b.FileID
	})
	return out
}

func previewUSNGroups(groups []USNFileGroup) []usnGroupPreview {
	out := make([]usnGroupPreview, 0, min(len(groups), usnGroupPreviewLimit))
	for _, g := range groups[:min(len(groups), usnGroupPreviewLimit)] {
		p := usnGroupPreview{USNFileGroup: g, NamesOmitted: max(0, len(g.Names)-5), ParentsOmitted: max(0, len(g.Parents)-5)}
		p.Names = p.Names[:min(5, len(p.Names))]
		p.Parents = p.Parents[:min(5, len(p.Parents))]
		out = append(out, p)
	}
	return out
}

func exportUSNGroups(ctx context.Context, a Analysis, out string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	groups := usnFileGroups(a.Timeline)
	if err := ctx.Err(); err != nil {
		return err
	}
	analysisBytes, err := MarshalJSON(a)
	if err != nil {
		return err
	}
	record := struct {
		Schema         string         `json:"schema"`
		EvidenceDigest string         `json:"evidence_digest"`
		AnalysisDigest string         `json:"source_analysis_digest"`
		Scope          string         `json:"scope"`
		Groups         []USNFileGroup `json:"groups"`
	}{"k957-usn-file-groups/1", a.EvidenceDigest, digestBytes(analysisBytes), "Groups cover emitted USN events only. Counts describe records, not distinct operations. Names and parent IDs are observations, not resolved paths or inferred rename pairs. Refer to parser coverage for omitted records.", groups}
	if err := writeFileNew(filepath.Join(out, "usn-files.json"), func(w io.Writer) error {
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(record); err != nil {
			return err
		}
		return ctx.Err()
	}); err != nil {
		return err
	}
	return writeCSVNew(filepath.Join(out, "usn-files.csv"), func(w *csv.Writer) error {
		if err := w.Write([]string{"evidence_id", "source", "version", "file_id_le_hex", "record_count", "first_observed_utc", "last_observed_utc", "names_json", "parent_ids_json", "reasons", "references_json"}); err != nil {
			return err
		}
		for _, g := range groups {
			if err := ctx.Err(); err != nil {
				return err
			}
			names, err := json.Marshal(g.Names)
			if err != nil {
				return err
			}
			parents, err := json.Marshal(g.Parents)
			if err != nil {
				return err
			}
			refs, err := json.Marshal(g.References)
			if err != nil {
				return err
			}
			if err := w.Write([]string{csvSafe(g.Evidence), csvSafe(g.Source), csvSafe(g.Version), csvSafe(g.FileID), strconv.Itoa(g.Records), g.First.UTC().Format(time.RFC3339Nano), g.Last.UTC().Format(time.RFC3339Nano), string(names), string(parents), strings.Join(g.Reasons, "|"), string(refs)}); err != nil {
				return err
			}
		}
		return nil
	})
}

func usnGroupDocumentCoverage(groups []USNFileGroup) []Coverage {
	var names, parents, shownNames, shownParents int64
	for i, g := range groups {
		names += int64(len(g.Names))
		parents += int64(len(g.Parents))
		if i < usnGroupPreviewLimit {
			shownNames += int64(min(5, len(g.Names)))
			shownParents += int64(min(5, len(g.Parents)))
		}
	}
	return []Coverage{
		coverage("document_usn_file_groups", "groups", int64(len(groups)), int64(min(len(groups), usnGroupPreviewLimit)), usnGroupPreviewLimit, true),
		coverage("document_usn_group_names", "group_names", names, shownNames, usnGroupPreviewLimit*5, true),
		coverage("document_usn_group_parents", "group_parent_ids", parents, shownParents, usnGroupPreviewLimit*5, true),
	}
}

func usnGroupParagraphs(groups []USNFileGroup) []documentParagraph {
	if len(groups) == 0 {
		return nil
	}
	rows := []documentParagraph{{fmt.Sprintf("USN file record groups: %d total; first %d shown", len(groups), min(len(groups), usnGroupPreviewLimit)), true},
		{"Groups cover emitted records in each journal object. Counts are not distinct operations; names and parent IDs do not establish full paths, rename pairs or user attribution. Full names, parents and source record offsets are in usn-files.json and usn-files.csv in the original analysis report bundle.", false}}
	for _, g := range previewUSNGroups(groups) {
		rows = append(rows, documentParagraph{fmt.Sprintf("%s · %s · version=%s · file ID (raw LE hex)=%s · records=%d · observed UTC=%s to %s", g.Evidence, g.Source, g.Version, g.FileID, g.Records, g.First.UTC().Format(time.RFC3339Nano), g.Last.UTC().Format(time.RFC3339Nano)), true},
			documentParagraph{fmt.Sprintf("Observed names: %s · additional names omitted=%d. Parent IDs: %s · additional parents omitted=%d. Observed reason flags: %s.", strings.Join(g.Names, "; "), g.NamesOmitted, strings.Join(g.Parents, "; "), g.ParentsOmitted, strings.Join(g.Reasons, " | ")), false})
	}
	return rows
}
