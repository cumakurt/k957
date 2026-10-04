package core

import (
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const CaseSchema = "k957-case/1"
const caseItemLimit = 100000

// CaseDossier is a derived examination of every collection under one root.
// It is not a new evidence package. The signed collections remain the evidence.
type CaseDossier struct {
	Memories         []CaseMemoryExamination  `json:"memory_examinations,omitempty"`
	Index            string                   `json:"index,omitempty"`
	Events           int64                    `json:"events,omitempty"`
	Findings         int64                    `json:"findings,omitempty"`
	Reviews          int64                    `json:"reviews,omitempty"`
	AnalysisCoverage []CaseAnalysisCoverage   `json:"analysis_coverage,omitempty"`
	Coverage         []Coverage               `json:"coverage,omitempty"`
	Schema           string                   `json:"schema"`
	Version          string                   `json:"version"`
	ID               string                   `json:"id"`
	Created          time.Time                `json:"created"`
	Root             string                   `json:"root"`
	Directory        string                   `json:"directory"`
	Collections      int                      `json:"collections"`
	Verified         int                      `json:"verified"`
	Failed           int                      `json:"failed"`
	Items            int                      `json:"items"`
	Hosts            []string                 `json:"hosts"`
	Failures         []CollectionVerification `json:"failures,omitempty"`
	Duplicates       []CaseDuplicate          `json:"duplicates"`
	HashMatches      []HashMatch              `json:"hash_matches"`
	Mismatches       []FileIdentity           `json:"extension_mismatches"`
	MediaCounts      []MediaCount             `json:"media_counts"`
	Timeline         []CaseEvent              `json:"timeline"`
	Notes            []string                 `json:"notes"`
}

type CaseAnalysisCoverage struct {
	Collection string     `json:"collection"`
	Digest     string     `json:"collection_digest"`
	Coverage   []Coverage `json:"coverage"`
}

type CaseOptions struct {
	Rules       []Rule
	ReviewPaths []string
	ReviewKey   string
}

// CaseDuplicate is one SHA-256 shared by two or more non-empty evidence objects.
type CaseDuplicate struct {
	SHA256  string   `json:"sha256"`
	Size    int64    `json:"size"`
	Count   int      `json:"count"`
	Hosts   []string `json:"hosts"`
	Sources []string `json:"sources"`
}

// CaseEvent is a collection boundary. File modification times are in timeline.csv.
type CaseEvent struct {
	Time       time.Time `json:"time"`
	Type       string    `json:"type"`
	Host       string    `json:"host"`
	Collection string    `json:"collection"`
	Source     string    `json:"source,omitempty"`
}

// MediaCount is how many evidence objects shared one magic-byte type.
type MediaCount struct {
	MediaType string `json:"media_type"`
	Count     int    `json:"count"`
}

type caseCopy struct {
	host, collection, evidence, source, sum string
	size                                    int64
}

// BuildCase verifies every collection under root and writes an examination
// directory. out must be a new path. An empty store is an error. Individual
// collection failures are recorded; the returned error is non-nil when any
// collection failed.
func BuildCase(ctx context.Context, root, out, trusted string, set *HashSet) (d CaseDossier, err error) {
	return BuildCaseWithOptions(ctx, root, out, trusted, set, CaseOptions{Rules: BuiltinRules()})
}

func BuildCaseWithOptions(ctx context.Context, root, out, trusted string, set *HashSet, opts CaseOptions) (d CaseDossier, err error) {
	ledgers := map[string]ReviewLedger{}
	for _, path := range opts.ReviewPaths {
		l, e := LoadLedger(path)
		if e != nil {
			return d, e
		}
		if _, exists := ledgers[l.EvidenceDigest]; exists {
			return d, fmt.Errorf("duplicate review ledger for collection digest")
		}
		ledgers[l.EvidenceDigest] = l
	}
	dirs, e := DiscoverCollections(root)
	if e != nil {
		return d, e
	}
	sort.Strings(dirs)
	if len(dirs) == 0 {
		return d, fmt.Errorf("no collections in %s", root)
	}
	if e = os.Mkdir(out, 0700); e != nil {
		return d, fmt.Errorf("new output directory required: %w", e)
	}
	ok := false
	defer func() {
		if !ok {
			os.RemoveAll(out)
		}
	}()
	workspace, e := os.MkdirTemp(out, ".memory-analysis-")
	if e != nil {
		return d, e
	}
	defer os.RemoveAll(workspace)
	ctx = WithMemoryWorkspace(ctx, workspace)
	index, e := newCaseIndex(ctx, filepath.Join(out, "case-index.sqlite"))
	if e != nil {
		return d, e
	}
	defer index.close()
	exports, e := newCaseExports(ctx, index.tx)
	if e != nil {
		return d, e
	}
	defer exports.close()
	d = CaseDossier{
		Schema: CaseSchema, Version: Version, ID: ID(), Created: time.Now().UTC(), Root: root, Directory: out, Index: "case-index.sqlite",
		Collections: len(dirs), Hosts: []string{}, Duplicates: []CaseDuplicate{}, HashMatches: []HashMatch{},
		Mismatches: []FileIdentity{}, MediaCounts: []MediaCount{}, Timeline: []CaseEvent{},
		Notes: []string{
			"This dossier is derived. The signed collection directories remain the evidence.",
			"Duplicate SHA-256 values mean the acquired bytes match. They do not prove the same user action or that the files were copied from each other.",
			"File types are magic-byte hints from the first 560 bytes. An extension mismatch is a triage signal, not proof of concealment.",
			"bodyfile.txt is a Sleuth Kit body file. Only mtime is populated. atime, ctime, crtime, uid, gid and MD5 are zero because logical collection records SHA-256.",
			"Hash-set rows are exact comparisons with an examiner-supplied list. known-good is not a trust decision. known-bad is not a malware verdict.",
			"Failed collections are listed and were not inventoried. A failed signature means that directory cannot support findings.",
		},
	}
	seenHost := map[string]bool{}
	copies := map[string][]caseCopy{}
	media := map[string]int{}
	limited := false
	hashEligible, mismatchEligible := int64(0), int64(0)
	for i, dir := range dirs {
		if e = ctx.Err(); e != nil {
			return d, e
		}
		ReportProgress(ctx, Progress{Phase: "case", Detail: dir, Step: i + 1, Steps: len(dirs)})
		v := verifyCollectionForExamination(ctx, dir, trusted, nil)
		if v.Status != "verified" {
			d.Failed++
			d.Failures = append(d.Failures, v)
			continue
		}
		d.Verified++
		bodyBytes, rec, e := verifiedCollectionSnapshot(v)
		if e != nil {
			d.Failed++
			d.Verified--
			v.Status = "failed"
			v.Errors = append(v.Errors, e.Error())
			d.Failures = append(d.Failures, v)
			continue
		}
		digestBytes := sha256.Sum256(bodyBytes)
		collectionDigest := hex.EncodeToString(digestBytes[:])
		if !seenHost[rec.Host] {
			seenHost[rec.Host] = true
			d.Hosts = append(d.Hosts, rec.Host)
		}
		boundaryStart := len(d.Timeline)
		d.Timeline = append(d.Timeline, CaseEvent{Time: rec.Started, Type: "collection_started", Host: rec.Host, Collection: dir})
		d.Timeline = append(d.Timeline, CaseEvent{Time: rec.Finished, Type: "collection_finished", Host: rec.Host, Collection: dir})
		if rec.Memory != nil && rec.Memory.Image != "" {
			d.Timeline = append(d.Timeline, CaseEvent{Time: rec.Memory.Started, Type: "memory_acquired", Host: rec.Host, Collection: dir, Source: rec.Memory.Image})
		}
		for _, boundary := range d.Timeline[boundaryStart:] {
			if boundary.Collection != dir {
				continue
			}
			stamp := boundary.Time
			if e := index.add(ctx, CaseRow{Kind: "boundary", Collection: dir, Digest: collectionDigest, Host: rec.Host, Source: boundary.Source, Time: &stamp, Payload: JSON(boundary)}, boundary.Type); e != nil {
				return d, e
			}
		}
		var p *Package
		if rec.Evidence != "" {
			p, e = openVerifiedCollectionPackage(ctx, dir, rec)
		}
		if e != nil {
			d.Failed++
			d.Verified--
			v.Status = "failed"
			v.Errors = append(v.Errors, "evidence: "+e.Error())
			d.Failures = append(d.Failures, v)
			continue
		}
		a := Analysis{Version: Version, Run: ID(), Created: time.Now().UTC(), Rules: opts.Rules, Manifest: Manifest{Schema: Schema, Version: Version, ID: rec.ID, Case: rec.Case, Operator: rec.Operator, Scope: rec.Scope, Host: rec.Host, OS: rec.OS, Arch: rec.Arch, Status: rec.Status, Started: rec.Started, Finished: rec.Finished, Items: []Item{}}}
		if p != nil {
			analysisCtx := ctx
			if limited {
				analysisCtx = context.WithValue(ctx, memoryOnlyKey{}, true)
			}
			a = AnalyzeContext(analysisCtx, p, opts.Rules)
		}
		closePackage := func() {
			if p != nil {
				p.Close()
			}
		}
		if limited {
			a.Notes = append(a.Notes, "The case logical-file projection reached its capacity; this collection still receives complete memory examination. Its logical files are omitted from this case projection.")
		}
		a.PackageDigest = a.EvidenceDigest
		a.EvidenceDigest = collectionDigest
		a.Signature = v.Signature
		a.CollectionStatus = rec.Status
		a.CollectionIssues = append([]Issue(nil), rec.Issues...)
		a.Adaptive = rec.Adaptive
		for j := range a.Findings {
			a.Findings[j].ID = findingID(a.EvidenceDigest, a.Findings[j])
		}
		if rec.Memory != nil && rec.Memory.Image != "" {
			m, scanErr := scanVerifiedMemoryFile(ctx, filepath.Join(dir, rec.Memory.Image), rec.Memory.SHA256, opts.Rules, &verifyMeter{ctx: ctx})
			if scanErr != nil {
				closePackage()
				return d, fmt.Errorf("case memory analysis: %w", scanErr)
			}
			m.Evidence = "MEMORY"
			m.Source = rec.Memory.Image
			annotateMemory(&m, rec.Memory)
			if e = examineConfiguredMemory(ctx, filepath.Join(dir, rec.Memory.Image), rec.Memory.OS, &m); e != nil {
				closePackage()
				return d, e
			}
			rememberMemory(&a, m)
		}
		for _, m := range a.Memories {
			d.Memories = append(d.Memories, CaseMemoryExamination{Collection: dir, Digest: collectionDigest, Host: rec.Host, Source: m.Source, SHA256: m.SHA256, Bytes: m.Bytes, Results: m.Results, Kernel: m.Kernel, Notes: m.Notes})
		}
		applyConfiguredIndicators(ctx, &a)
		ApplyHashSet(&a, set)
		if ledger, found := ledgers[collectionDigest]; found {
			if e = ApplyReviews(&a, ledger, opts.ReviewKey); e != nil {
				closePackage()
				return d, fmt.Errorf("case review: %w", e)
			}
			delete(ledgers, collectionDigest)
		}
		if a.Canceled {
			closePackage()
			return d, ctx.Err()
		}
		if e = exportMemoryKernel(ctx, a, out); e != nil {
			closePackage()
			return d, e
		}
		if e = exportMemoryResults(ctx, a, out); e != nil {
			closePackage()
			return d, e
		}
		d.AnalysisCoverage = append(d.AnalysisCoverage, CaseAnalysisCoverage{Collection: dir, Digest: collectionDigest, Coverage: analysisCoverage(a)})
		if e = index.analysis(ctx, a, dir, rec.Host); e != nil {
			closePackage()
			return d, e
		}
		if p == nil {
			continue
		}
		for _, it := range p.Manifest.Items {
			ReportProgress(ctx, Progress{Phase: "case", Detail: it.Source, Step: i + 1, Steps: len(dirs)})
			if e := ctx.Err(); e != nil {
				p.Close()
				return d, e
			}
			if d.Items >= caseItemLimit {
				limited = true
				break
			}
			d.Items++
			if e = index.add(ctx, caseInventoryRow(dir, collectionDigest, rec.Host, it), it.Source+" "+it.SHA256); e != nil {
				p.Close()
				return d, e
			}
			id := identifyVerifiedItem(p, it)
			id.Host = rec.Host
			media[id.MediaType]++
			if id.ExtensionMismatch {
				mismatchEligible++
				if len(d.Mismatches) < 2000 {
					d.Mismatches = append(d.Mismatches, id)
				}
			}
			if verdict, label, ok := set.Lookup(it.SHA256); ok {
				hashEligible++
				if len(d.HashMatches) < 10000 {
					d.HashMatches = append(d.HashMatches, HashMatch{Host: rec.Host, Evidence: it.ID, Source: it.Source, SHA256: strings.ToLower(it.SHA256), Verdict: verdict, Label: label})
				}
			}
			if it.Size > 0 {
				copies[strings.ToLower(it.SHA256)] = append(copies[strings.ToLower(it.SHA256)], caseCopy{host: rec.Host, collection: dir, evidence: it.ID, source: it.Source, sum: strings.ToLower(it.SHA256), size: it.Size})
			}
			if e = exports.add(ctx, rec.Host, dir, it, id); e != nil {
				p.Close()
				return d, e
			}
		}
		p.Close()
	}
	if len(ledgers) > 0 {
		return d, fmt.Errorf("a supplied review ledger does not match an examined collection")
	}
	if e := ctx.Err(); e != nil {
		return d, e
	}
	if limited {
		d.Notes = append(d.Notes, "Inventory stopped at 100000 evidence objects. Remaining objects were not classified.")
	}
	sort.Strings(d.Hosts)
	sort.SliceStable(d.Timeline, func(i, j int) bool {
		if d.Timeline[i].Time.Equal(d.Timeline[j].Time) {
			return d.Timeline[i].Type < d.Timeline[j].Type
		}
		return d.Timeline[i].Time.Before(d.Timeline[j].Time)
	})
	d.Duplicates = duplicateGroups(copies)
	dupEligible := int64(0)
	for _, group := range copies {
		if len(group) > 1 {
			dupEligible++
		}
	}
	d.Coverage = []Coverage{
		coverage("collections", "collections", int64(d.Collections), int64(d.Verified), 0, true),
		coverage("inventory", "objects", int64(d.Items), int64(d.Items), caseItemLimit, !limited && d.Failed == 0),
		coverage("duplicates", "groups", dupEligible, int64(len(d.Duplicates)), 2000, !limited && d.Failed == 0),
		coverage("hash_matches", "matches", hashEligible, int64(len(d.HashMatches)), 10000, !limited && d.Failed == 0),
		coverage("extension_mismatches", "objects", mismatchEligible, int64(len(d.Mismatches)), 2000, !limited && d.Failed == 0),
	}
	d.Coverage = append(d.Coverage, coverage("case_index", "rows", index.eligible, index.count, caseIndexLimit, !limited && d.Failed == 0))
	d.Events, d.Findings, d.Reviews = index.events, index.findings, index.reviews
	d.Notes = append(d.Notes, caseIndexNote(index))
	if e = exports.boundaries(ctx, d.Timeline); e != nil {
		return d, e
	}
	if e = exports.close(); e != nil {
		return d, e
	}
	if e = index.finish(); e != nil {
		return d, e
	}
	if e = exportCaseIndex(ctx, filepath.Join(out, d.Index), filepath.Join(out, "examination.csv")); e != nil {
		return d, e
	}
	for _, kind := range sortedKeys(media) {
		d.MediaCounts = append(d.MediaCounts, MediaCount{MediaType: kind, Count: media[kind]})
	}
	if e = exportLegacyCase(ctx, filepath.Join(out, d.Index), out); e != nil {
		return d, e
	}
	dupHeader, dupRows := duplicateRows(d.Duplicates)
	if e = writeCaseCSV(filepath.Join(out, "duplicates.csv"), dupHeader, dupRows); e != nil {
		return d, e
	}
	if e = writeHashMatches(d.HashMatches, filepath.Join(out, "hash-matches.csv")); e != nil {
		return d, e
	}
	if e = WriteJSONNew(filepath.Join(out, "case.json"), d); e != nil {
		return d, e
	}
	if e = exportCasePDF(ctx, d, out); e != nil {
		return d, e
	}
	if e = writeCaseHTML(d, filepath.Join(out, "report.html")); e != nil {
		return d, e
	}
	if e := ctx.Err(); e != nil {
		return d, e
	}
	ok = true
	if d.Failed > 0 {
		return d, fmt.Errorf("%d of %d collections failed verification", d.Failed, d.Collections)
	}
	return d, nil
}

func duplicateGroups(copies map[string][]caseCopy) []CaseDuplicate {
	sums := make([]string, 0, len(copies))
	for sum, group := range copies {
		if len(group) > 1 {
			sums = append(sums, sum)
		}
	}
	sort.Strings(sums)
	out := []CaseDuplicate{}
	for _, sum := range sums {
		if len(out) >= 2000 {
			break
		}
		group := copies[sum]
		hosts := map[string]bool{}
		sources := map[string]bool{}
		for _, c := range group {
			hosts[c.host] = true
			sources[c.host+" "+c.source] = true
		}
		out = append(out, CaseDuplicate{SHA256: sum, Size: group[0].size, Count: len(group), Hosts: sortedKeysBool(hosts), Sources: sortedKeysBool(sources)})
	}
	return out
}

func duplicateRows(dups []CaseDuplicate) ([]string, [][]string) {
	header := []string{"sha256", "size", "count", "hosts", "sources"}
	var rows [][]string
	for _, d := range dups {
		rows = append(rows, []string{d.SHA256, strconv.FormatInt(d.Size, 10), strconv.Itoa(d.Count), strings.Join(d.Hosts, ";"), strings.Join(d.Sources, ";")})
	}
	return header, rows
}

func writeCaseCSV(path string, header []string, rows [][]string) error {
	return writeCSVNew(path, func(w *csv.Writer) error {
		if err := w.Write(header); err != nil {
			return err
		}
		for _, row := range rows {
			if err := writeSafeCSVRow(w, append([]string(nil), row...)); err != nil {
				return err
			}
		}
		return nil
	})
}

func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedKeysBool(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func writeCaseHTML(d CaseDossier, path string) error {
	t, e := template.New("case").Parse(caseTemplate)
	if e != nil {
		return e
	}
	return writeFileNew(path, func(w io.Writer) error { return t.Execute(w, d) })
}

const caseTemplate = `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>k957 case {{.ID}}</title><style>` + reportStyle + `</style><main><header><small>k957 {{.Version}} · derived examination · not a new evidence package</small><h1>Case dossier</h1><p>{{.Root}}</p><small>{{.ID}} · {{.Created}}</small><p class="reading-edition"><a href="report.pdf">PDF reading edition</a> · <a href="documents.json">Document coverage</a> · <a href="examination.csv">Full examination rows</a></p></header>
<section class="grid"><div class="card">Collections<br><b>{{.Collections}}</b></div><div class="card">Verified<br><b>{{.Verified}}</b></div><div class="card">Failed<br><b>{{.Failed}}</b></div><div class="card">Objects<br><b>{{.Items}}</b></div></section>
<p>Hosts: {{range .Hosts}}{{.}} {{end}}</p>
{{if .Memories}}<h2>Memory examinations</h2><table><thead><tr><th>Host / collection digest</th><th>Image SHA-256 / bytes</th><th>Complete scan</th><th>Kernel methods</th></tr></thead><tbody>{{range .Memories}}<tr><td>{{.Host}}<br><code>{{.Digest}}</code></td><td><code>{{.SHA256}}</code><br>{{.Bytes}} bytes</td><td>{{if .Results}}<a href="{{.Results.Name}}">{{.Results.Rows}} complete records</a><br><code>{{.Results.SHA256}}</code>{{end}}</td><td>{{if .Kernel}}{{.Kernel.Status}} · {{len .Kernel.Examinations}} plugin receipts · <a href="{{.Kernel.Directory}}/memory-suite.json">Suite record</a>{{else}}Not run; inspect examination notes{{end}}{{range .Notes}}<p>{{.}}</p>{{end}}</td></tr>{{end}}</tbody></table>{{end}}
<h2>Method and limits</h2>{{range .Notes}}<p class="note">{{.}}</p>{{end}}
{{if .Coverage}}<h2>Coverage</h2><table><thead><tr><th>Stage</th><th>Status</th><th>Eligible</th><th>Emitted</th><th>Omitted</th><th>Total known</th></tr></thead><tbody>{{range .Coverage}}<tr><td>{{.Stage}}</td><td>{{.Status}}</td><td>{{.Eligible}}</td><td>{{.Emitted}}</td><td>{{.Omitted}}</td><td>{{.TotalKnown}}</td></tr>{{end}}</tbody></table>{{end}}
<h2>Signature mismatches</h2><table><thead><tr><th>Host</th><th>Source</th><th>Detected type</th></tr></thead><tbody>{{range .Mismatches}}<tr><td>{{.Host}}</td><td>{{.Source}}</td><td>{{.MediaType}}<br>{{.Description}}</td></tr>{{else}}<tr><td colspan="3">No extension and signature disagreement in the inspected objects.</td></tr>{{end}}</tbody></table>
<h2>Examiner hash set</h2><table><thead><tr><th>Host</th><th>Verdict</th><th>SHA-256</th><th>Label</th></tr></thead><tbody>{{range .HashMatches}}<tr><td>{{.Host}}<br>{{.Evidence}}</td><td>{{.Verdict}}</td><td><code>{{.SHA256}}</code></td><td>{{.Label}}<br>{{.Source}}</td></tr>{{else}}<tr><td colspan="4">No hash-set match, or no set was supplied.</td></tr>{{end}}</tbody></table>
<h2>Byte-identical objects</h2><table><thead><tr><th>SHA-256</th><th>Count</th><th>Hosts</th><th>Sources</th></tr></thead><tbody>{{range .Duplicates}}<tr><td><code>{{.SHA256}}</code></td><td>{{.Count}} · {{.Size}} bytes</td><td>{{range .Hosts}}{{.}}<br>{{end}}</td><td>{{range .Sources}}{{.}}<br>{{end}}</td></tr>{{else}}<tr><td colspan="4">No SHA-256 was shared by two non-empty objects.</td></tr>{{end}}</tbody></table>
<h2>Media types</h2><table><thead><tr><th>Type</th><th>Objects</th></tr></thead><tbody>{{range .MediaCounts}}<tr><td>{{.MediaType}}</td><td>{{.Count}}</td></tr>{{end}}</tbody></table>
<h2>Collection boundaries</h2><table><thead><tr><th>Time</th><th>Event</th><th>Host</th></tr></thead><tbody>{{range .Timeline}}<tr><td>{{.Time}}</td><td>{{.Type}}<br>{{.Source}}</td><td>{{.Host}}</td></tr>{{end}}</tbody></table>
<h2>Collections that did not verify</h2><table><thead><tr><th>Directory</th><th>Errors</th></tr></thead><tbody>{{range .Failures}}<tr><td>{{.Directory}}</td><td>{{range .Errors}}{{.}}<br>{{end}}</td></tr>{{else}}<tr><td colspan="2">None.</td></tr>{{end}}</tbody></table>
<footer><small>Inventory, timeline, duplicates, hash matches and a Sleuth Kit bodyfile are beside this page. Confirm every finding from the signed collection.</small></footer></main></html>`

type CaseMemoryExamination struct {
	Notes      []string       `json:"notes,omitempty"`
	Collection string         `json:"collection"`
	Digest     string         `json:"collection_digest"`
	Host       string         `json:"host"`
	Source     string         `json:"source"`
	SHA256     string         `json:"image_sha256"`
	Bytes      uint64         `json:"bytes"`
	Results    *MemoryResults `json:"scan_results,omitempty"`
	Kernel     *MemorySuite   `json:"kernel_examination,omitempty"`
}
