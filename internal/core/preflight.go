package core

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

type volumeSample struct {
	ID        string
	Available int64
}
type PreflightCheck struct {
	Code    string `json:"code"`
	Status  string `json:"status"`
	Message string `json:"message"`
}
type StorageBudget struct {
	Filesystem string   `json:"filesystem"`
	Roles      []string `json:"roles"`
	Available  int64    `json:"available_bytes"`
	Estimated  int64    `json:"estimated_additional_bytes"`
	Reserve    int64    `json:"reserve_bytes"`
	Required   int64    `json:"estimated_with_reserve_bytes"`
	Enough     bool     `json:"enough_at_check_time"`
}
type PreflightResult struct {
	Version         string           `json:"version"`
	Time            time.Time        `json:"time"`
	Root            string           `json:"root"`
	Output          string           `json:"output"`
	Work            string           `json:"work,omitempty"`
	Encrypted       bool             `json:"encrypted"`
	Resume          bool             `json:"resume"`
	EligibleFiles   int              `json:"eligible_files"`
	EligibleBytes   int64            `json:"eligible_bytes"`
	CompletedFiles  int              `json:"completed_files"`
	AcquiredBytes   int64            `json:"acquired_bytes"`
	RemainingBytes  int64            `json:"remaining_bytes"`
	RemainingParts  int64            `json:"remaining_parts"`
	Parts           int64            `json:"planned_parts"`
	EstimatedOutput int64            `json:"estimated_output_bytes"`
	EstimatedWork   int64            `json:"estimated_work_bytes"`
	Outcome         string           `json:"outcome"`
	Checks          []PreflightCheck `json:"checks"`
	Issues          []Issue          `json:"inventory_issues"`
	Storage         []StorageBudget  `json:"storage"`
	Notes           []string         `json:"notes"`
}

// Preflight is read-only and does not open evidence contents or reserve disk
// space. It applies the same inventory budgets as resumable collection.
func Preflight(ctx context.Context, o Options, work string, encrypted bool, reserve int64) (PreflightResult, error) {
	return preflight(ctx, o, work, encrypted, reserve, probeVolume)
}
func preflight(ctx context.Context, o Options, work string, encrypted bool, reserve int64, probe func(string) (volumeSample, error)) (r PreflightResult, err error) {
	return planPreflight(ctx, o, work, encrypted, false, reserve, probe)
}

// PreflightResume plans additional space from an existing frozen inventory.
// It reads checkpoint/key contents and file metadata, but does not rehash chunks
// or read source contents. Collection still performs its full integrity checks.
// Root and limits must match the original acquisition. Nonempty case/operator/
// scope options are also checked, as when gating a collect invocation.
func PreflightResume(ctx context.Context, o Options, work string, reserve int64) (PreflightResult, error) {
	return planPreflight(ctx, o, work, o.EncryptionKey != "", true, reserve, probeVolume)
}

func planPreflight(ctx context.Context, o Options, work string, encrypted, resume bool, reserve int64, probe func(string) (volumeSample, error)) (r PreflightResult, err error) {
	r = PreflightResult{Version: Version, Time: time.Now().UTC(), Encrypted: encrypted, Resume: resume, Outcome: "pass", Checks: []PreflightCheck{}, Issues: []Issue{}, Storage: []StorageBudget{}, Notes: []string{"Read-only metadata inventory; evidence contents, permissions to read every file, write access, signing keys and live system commands are not validated.", "Estimates are planning allowances, not worst-case guarantees. Filesystem allocation units, quotas, snapshots, concurrent writers, changing sources and compression affect actual space. No capacity is reserved.", "Filesystem identity does not prove physical-device separation. Different partitions may share the same physical disk."}}
	if e := ctx.Err(); e != nil {
		return r, e
	}
	if resume {
		r.Notes = append(r.Notes, "Uses the frozen checkpoint inventory. Checkpoint metadata and saved chunk type/size are checked; source prefixes and chunk contents are not verified. Encrypted checkpoints require the original key. Completed sources are not re-inventoried.", "Acquired/remaining byte counts are logical sizes, not allocated disk usage. Existing staging/orphan files already consume reported free space. No future deduplication or cleanup savings are assumed.")
	} else {
		r.Notes = append(r.Notes, "Encryption keys are not read or validated for fresh acquisition estimates.")
	}
	if o.Root == "" || o.Out == "" || o.System {
		return r, errors.New("preflight requires root and out; system snapshots are not supported")
	}
	if o.MaxFile <= 0 || o.MaxFile > 64<<30 || o.MaxTotal <= 0 || o.MaxTotal > 1<<40 || o.MaxFiles <= 0 || o.MaxFiles > 100000 || reserve < 0 || reserve > 1<<40 {
		return r, errors.New("invalid preflight limits")
	}
	if (encrypted || resume) && work == "" {
		return r, errors.New("encrypted or resumed acquisition requires work")
	}
	root, e := filepath.Abs(o.Root)
	if e != nil {
		return r, e
	}
	root, e = filepath.EvalSymlinks(root)
	if e != nil {
		return r, e
	}
	info, e := os.Stat(root)
	if e != nil {
		return r, e
	}
	if !info.IsDir() {
		return r, errors.New("root must be directory")
	}
	r.Root = root
	out, e := canonicalDestination(o.Out)
	if e != nil {
		return r, e
	}
	r.Output = out
	if work != "" {
		work, e = canonicalDestination(work)
		if e != nil {
			return r, e
		}
		r.Work = work
	}
	add := func(code, status, message string) { r.Checks = append(r.Checks, PreflightCheck{code, status, message}) }
	if inside(root, out) {
		add("OUTPUT_IN_SOURCE", "blocked", "Output is inside the source tree")
	}
	if work != "" && (inside(root, work) || inside(work, root) || inside(work, out)) {
		add("WORK_PATH_OVERLAP", "blocked", "Source/work/output trees overlap")
	}
	destinations := []string{out}
	if work != "" && !resume {
		destinations = append(destinations, work)
	}
	for _, p := range destinations {
		if _, e = os.Lstat(p); e == nil {
			add("DESTINATION_EXISTS", "blocked", p)
		} else if !os.IsNotExist(e) {
			add("DESTINATION_UNAVAILABLE", "blocked", e.Error())
		}
	}
	var state WorkState
	if resume {
		state, e = resumePreflightInventory(ctx, o, root, work, &r)
	} else {
		// No content is copied: planWork only obtains directory/file metadata.
		state, e = planWork(ctx, root, o)
	}
	if e != nil {
		return r, e
	}
	r.Issues = state.Manifest.Issues
	r.EligibleFiles = len(state.Files)
	for _, wf := range state.Files {
		r.EligibleBytes += wf.ExpectedSize
		var acquired int64
		for _, part := range wf.Item.Parts {
			acquired += part.Size
		}
		r.AcquiredBytes += acquired
		remaining := wf.ExpectedSize - acquired
		parts := (remaining + resumeChunk - 1) / resumeChunk
		r.RemainingBytes += remaining
		r.RemainingParts += parts
		r.Parts += int64(len(wf.Item.Parts)) + parts
		if wf.Complete {
			r.CompletedFiles++
		}
	}
	if len(r.Issues) > 0 {
		add("INVENTORY_PARTIAL", "warning", fmt.Sprintf("%d inventory issues or budget exclusions; review inventory_issues", len(r.Issues)))
	}
	if len(state.Files) == 0 {
		add("EMPTY_SELECTION", "warning", "No eligible regular files were found")
	}
	// Conservative working allowance; explicitly not a proven bound.
	r.EstimatedOutput = r.EligibleBytes + r.EligibleBytes/100 + int64(r.EligibleFiles)*1024 + (16 << 20)
	if encrypted {
		r.EstimatedOutput += ((r.EstimatedOutput+chunkSize-1)/chunkSize+1)*20 + 16
	}
	if work != "" {
		r.EstimatedWork = r.RemainingBytes + r.RemainingBytes/10 + (r.RemainingParts+int64(r.EligibleFiles-r.CompletedFiles))*4096 + (64 << 20)
		if encrypted {
			r.EstimatedWork += r.RemainingParts*stageOverhead + 2*stageOverhead
		}
	}
	sourceFS, e := probe(root)
	if e != nil || sourceFS.ID == "" || sourceFS.Available < 0 {
		message := "invalid filesystem capacity response"
		if e != nil {
			message = e.Error()
		}
		add("SOURCE_FILESYSTEM_UNKNOWN", "unknown", message)
		sourceFS = volumeSample{}
	}
	type target struct {
		role, path string
		bytes      int64
	}
	targets := []target{{"output", filepath.Dir(out), r.EstimatedOutput}}
	if work != "" {
		if resume {
			// Existing work/chunks may be mount points on different filesystems.
			// Probe each actual destination instead of the staging parent.
			metadata := int64(64 << 20)
			if encrypted {
				metadata += 2 * stageOverhead
			}
			targets = append(targets, target{"work", work, metadata})
			if remaining := r.EstimatedWork - metadata; remaining > 0 {
				targets = append(targets, target{"chunks", filepath.Join(work, "chunks"), remaining})
			}
		} else {
			targets = append(targets, target{"work", filepath.Dir(work), r.EstimatedWork})
		}
	}
	grouped := map[string]*StorageBudget{}
	for _, t := range targets {
		if e = ctx.Err(); e != nil {
			return r, e
		}
		v, e := probe(t.path)
		if e != nil || v.ID == "" || v.Available < 0 {
			message := "invalid filesystem capacity response"
			if e != nil {
				message = e.Error()
			}
			add("TARGET_CAPACITY_UNKNOWN", "unknown", t.role+": "+message)
			continue
		}
		if v.ID == sourceFS.ID && sourceFS.ID != "" {
			add("SOURCE_AND_TARGET_SAME_FILESYSTEM", "warning", t.role+" shares the source filesystem")
		}
		b := grouped[v.ID]
		if b == nil {
			b = &StorageBudget{Filesystem: v.ID, Available: v.Available, Reserve: reserve, Roles: []string{}}
			grouped[v.ID] = b
		} else if v.Available < b.Available {
			b.Available = v.Available
		}
		b.Roles = append(b.Roles, t.role)
		b.Estimated += t.bytes
	}
	for _, b := range grouped {
		b.Required = b.Estimated + b.Reserve
		b.Enough = b.Available >= b.Required
		if !b.Enough {
			add("INSUFFICIENT_ESTIMATED_SPACE", "blocked", fmt.Sprintf("%s needs estimated %d bytes including reserve; %d available", b.Filesystem, b.Required, b.Available))
		}
		r.Storage = append(r.Storage, *b)
	}
	sort.Slice(r.Storage, func(i, j int) bool { return r.Storage[i].Filesystem < r.Storage[j].Filesystem })
	rank := map[string]int{"pass": 0, "warning": 1, "unknown": 2, "blocked": 3}
	for _, c := range r.Checks {
		if rank[c.Status] > rank[r.Outcome] {
			r.Outcome = c.Status
		}
	}
	return r, nil
}
