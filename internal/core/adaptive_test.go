package core

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestAdaptiveExecutableAcquisitionProvenance(t *testing.T) {
	d := t.TempDir()
	exe := filepath.Join(d, "observed-executable")
	if e := os.WriteFile(exe, []byte("Synthetic executable bytes"), 0600); e != nil {
		t.Fatal(e)
	}
	oldDiscover, oldProfile := discoverProcessExecutables, fullArtifactCandidates
	defer func() { discoverProcessExecutables, fullArtifactCandidates = oldDiscover, oldProfile }()
	discoverProcessExecutables = func(context.Context) ([]ExecutableReference, string, error) {
		return []ExecutableReference{{PID: 7, Path: exe, Status: "observed"}, {PID: 8, Path: exe, Status: "observed"}, {PID: 9, Status: "unavailable", Reason: "process exited"}}, "synthetic process references", nil
	}
	fullArtifactCandidates = func() []string { return []string{} }
	r, e := CollectFull(context.Background(), FullOptions{OutputDir: filepath.Join(d, "store"), Artifacts: true, MaxFile: 1 << 20, MaxTotal: 1 << 20})
	if e != nil {
		t.Fatal(e)
	}
	if r.Adaptive == nil || r.Adaptive.Processes != 3 || r.Adaptive.Selected != 1 || r.Adaptive.Collected != 1 || r.Adaptive.Unavailable != 1 {
		t.Fatalf("summary %#v", r.Adaptive)
	}
	var record AdaptiveExecutables
	if e := strictJSON(filepath.Join(r.Directory, r.Adaptive.Record), 1<<20, &record); e != nil {
		t.Fatal(e)
	}
	if record.References[0].SHA256 == "" || record.References[0].Evidence == "" || record.References[0].SHA256 != record.References[1].SHA256 {
		t.Fatal(record)
	}
	if v := verifyCollection(r.Directory, ""); v.Status != "verified" {
		t.Fatal(v)
	}
	if e := os.WriteFile(filepath.Join(r.Directory, r.Adaptive.Record), []byte("tampered"), 0600); e != nil {
		t.Fatal(e)
	}
	if v := verifyCollection(r.Directory, ""); v.Status == "verified" {
		t.Fatal("adaptive artifact tamper accepted")
	}
	// Explicit profiles do not expand their scope with process-selected paths.
	discoverProcessExecutables = func(context.Context) ([]ExecutableReference, string, error) {
		t.Fatal("custom profile expanded")
		return nil, "", nil
	}
	r, e = CollectFull(context.Background(), FullOptions{OutputDir: filepath.Join(d, "custom-store"), Artifacts: true, Profile: []string{exe}, MaxFile: 1 << 20, MaxTotal: 1 << 20})
	if e != nil || r.Adaptive != nil {
		t.Fatalf("custom profile %v %v", r.Adaptive, e)
	}
}

func TestAdaptiveExcludesOutputAndUnavailablePaths(t *testing.T) {
	d := t.TempDir()
	exe := filepath.Join(d, "own-output")
	os.WriteFile(exe, []byte("own output"), 0600)
	old := discoverProcessExecutables
	defer func() { discoverProcessExecutables = old }()
	discoverProcessExecutables = func(context.Context) ([]ExecutableReference, string, error) {
		return []ExecutableReference{{PID: 1, Path: exe, Status: "observed"}, {PID: 2, Path: filepath.Join(d, "absent"), Status: "observed"}}, "fixture", nil
	}
	r, paths, e := selectAdaptiveExecutables(context.Background(), d)
	if e != nil || len(paths) != 0 || r.References[0].Status != "unavailable" || r.References[1].Status != "unavailable" {
		t.Fatalf("%v %v %v", r, paths, e)
	}
}
