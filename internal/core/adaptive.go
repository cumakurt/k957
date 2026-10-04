package core

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// Process discovery and file acquisition happen at different times. The record
// binds the observed path to later collected bytes without claiming an atomic
// process snapshot or that those bytes were mapped by the observed process.
type ExecutableReference struct {
	ObservedPath string                 `json:"observed_path,omitempty"`
	Module       *LoadedModuleReference `json:"module,omitempty"`
	Kind         string                 `json:"kind,omitempty"`
	Mappings     []ExecutableMapping    `json:"mappings,omitempty"`
	PID          int                    `json:"pid"`
	Path         string                 `json:"path,omitempty"`
	Status       string                 `json:"status"`
	Reason       string                 `json:"reason,omitempty"`
	Evidence     string                 `json:"evidence,omitempty"`
	SHA256       string                 `json:"sha256,omitempty"`
}

type LoadedModuleReference struct {
	Name        string `json:"name"`
	BaseAddress string `json:"base_address"`
	ImageBytes  uint32 `json:"image_bytes"`
}

// Addresses and filesystem identifiers remain strings to preserve exact values
// in JSON consumers whose numbers cannot represent all 64-bit integers.
type ExecutableMapping struct {
	Line        int    `json:"line"`
	Address     string `json:"address"`
	Permissions string `json:"permissions"`
	Offset      string `json:"offset"`
	Device      string `json:"device"`
	Inode       string `json:"inode"`
}
type AdaptiveExecutables struct {
	Schema     string                `json:"schema"`
	Started    time.Time             `json:"started"`
	Finished   time.Time             `json:"finished"`
	Method     string                `json:"method"`
	References []ExecutableReference `json:"references"`
	Notes      []string              `json:"notes"`
}
type AdaptiveSummary struct {
	MappedFiles   int    `json:"mapped_file_references,omitempty"`
	MappingIssues int    `json:"unavailable_mapping_references,omitempty"`
	Record        string `json:"record"`
	Processes     int    `json:"processes"`
	Selected      int    `json:"selected_paths"`
	Collected     int    `json:"collected_paths"`
	Unavailable   int    `json:"unavailable_processes"`
}

var discoverProcessExecutables = platformProcessExecutables

func selectAdaptiveExecutables(ctx context.Context, output string) (AdaptiveExecutables, []string, error) {
	r := AdaptiveExecutables{Schema: "k957-adaptive-executables/1", Started: time.Now().UTC(), Notes: []string{
		"Process executable paths were observed before logical file acquisition. Process exit, permission failures, deleted executables and file changes can make this incomplete.",
		"The later package object hash identifies the acquired file. It does not establish which bytes a process had mapped at discovery time. Memory remains the primary source for mapped or deleted executable recovery.",
		"Default logical file size, total size and file count limits still apply. These limits do not cap memory examination. Linux selects regular files with executable /proc/<pid>/maps mappings, including shared libraries. Windows selects Tool Help loaded modules including DLLs, with base addresses and image sizes. macOS library discovery and recently opened files are not included.",
		"Linux mapping references retain address ranges, permissions, offsets, device and inode. A candidate path must match the observed device/inode before selection. Deleted, ambiguous escaped and inaccessible paths remain explicit unavailable references; anonymous executable mappings require memory examination.",
		"Windows module discovery includes native and 32-bit module snapshots. Protected/exited processes, path truncation and unstable loader lists may prevent enumeration; failures retain available references. Tool Help does not enumerate modules loaded as data files, unlinked modules or manually mapped code. These require memory examination.",
	}}
	refs, method, err := discoverProcessExecutables(ctx)
	r.References, r.Method, r.Finished = refs, method, time.Now().UTC()
	if err != nil {
		return r, nil, err
	}
	seen := map[string]bool{}
	paths := []string{}
	for i := range r.References {
		if e := ctx.Err(); e != nil {
			return r, paths, e
		}
		ref := &r.References[i]
		if ref.Status != "observed" {
			continue
		}
		resolved, e := filepath.EvalSymlinks(ref.Path)
		if e == nil {
			resolved, e = filepath.Abs(resolved)
		}
		if e == nil {
			var info os.FileInfo
			info, e = os.Lstat(resolved)
			if e == nil && (!info.Mode().IsRegular() || inside(output, resolved)) {
				ref.Status, ref.Reason = "unavailable", "not a regular file outside the collection directory"
				continue
			}
		}
		if e != nil {
			ref.Status, ref.Reason = "unavailable", e.Error()
			continue
		}
		ref.ObservedPath, ref.Path, ref.Status = ref.Path, resolved, "selected"
		key := adaptiveSource(resolved)
		if !seen[key] {
			seen[key] = true
			paths = append(paths, resolved)
		}
	}
	sort.Strings(paths)
	return r, paths, nil
}

func bindAdaptiveExecutables(r *AdaptiveExecutables, m Manifest) AdaptiveSummary {
	items := map[string]Item{}
	for _, it := range m.Items {
		items[adaptiveSource(it.Source)] = it
	}
	selected, collected := map[string]bool{}, map[string]bool{}
	s := AdaptiveSummary{Record: "adaptive-executables.json"}
	processes, unavailable := map[int]bool{}, map[int]bool{}
	for i := range r.References {
		ref := &r.References[i]
		processes[ref.PID] = true
		mapped := ref.Kind == "executable_mapping" || ref.Kind == "loaded_module"
		if mapped && ref.Path != "" {
			s.MappedFiles++
		}
		if ref.Status != "selected" {
			if mapped {
				s.MappingIssues++
			} else {
				unavailable[ref.PID] = true
			}
			continue
		}
		selected[adaptiveSource(ref.Path)] = true
		if it, ok := items[adaptiveSource(ref.Path)]; ok {
			ref.Status, ref.Evidence, ref.SHA256 = "collected", it.ID, it.SHA256
			collected[adaptiveSource(ref.Path)] = true
		} else {
			ref.Status, ref.Reason = "not-collected", "not present in the acquired package; inspect collection issues and logical limits"
		}
	}
	s.Selected, s.Collected = len(selected), len(collected)
	s.Processes, s.Unavailable = len(processes), len(unavailable)
	return s
}
func adaptiveSource(path string) string {
	path = filepath.Clean(path)
	if runtime.GOOS == "windows" {
		path = strings.ToLower(path)
	}
	return path
}
