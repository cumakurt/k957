package core

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func preflightFixture(t *testing.T) (Options, string, func(string) (volumeSample, error)) {
	t.Helper()
	_, o := fixture(t, false)
	var err error
	// Match the canonical paths probed by preflight, including /var aliases
	// used by macOS temporary directories.
	o.Root, err = filepath.EvalSymlinks(o.Root)
	if err != nil {
		t.Fatal(err)
	}
	o.Out, err = canonicalDestination(o.Out)
	if err != nil {
		t.Fatal(err)
	}
	work := filepath.Join(filepath.Dir(o.Out), "work")
	probe := func(p string) (volumeSample, error) {
		id := "target"
		if p == o.Root {
			id = "source"
		}
		return volumeSample{id, 4 << 30}, nil
	}
	return o, work, probe
}
func absent(t *testing.T, paths ...string) {
	t.Helper()
	for _, p := range paths {
		if _, e := os.Lstat(p); !os.IsNotExist(e) {
			t.Fatalf("unexpected destination %s: %v", p, e)
		}
	}
}
func TestPreflightCombinedBudget(t *testing.T) {
	o, work, probe := preflightFixture(t)
	r, e := preflight(context.Background(), o, work, false, 123, probe)
	if e != nil || r.Outcome != "pass" {
		t.Fatalf("%+v %v", r, e)
	}
	st, _ := os.Stat(filepath.Join(o.Root, "auth.log"))
	if r.EligibleFiles != 1 || r.EligibleBytes != st.Size() || r.Parts != 1 {
		t.Fatalf("inventory %+v", r)
	}
	if len(r.Storage) != 1 {
		t.Fatalf("not combined: %+v", r.Storage)
	}
	b := r.Storage[0]
	if b.Required != r.EstimatedOutput+r.EstimatedWork+123 || len(b.Roles) != 2 || !b.Enough {
		t.Fatalf("budget %+v", b)
	}
	absent(t, o.Out, work)
	// Each target individually fits, but the simultaneous work+output do not.
	low := func(p string) (volumeSample, error) {
		v, e := probe(p)
		v.Available = r.EstimatedWork + 123
		return v, e
	}
	r, e = preflight(context.Background(), o, work, false, 123, low)
	if e != nil || r.Outcome != "blocked" || r.Storage[0].Enough {
		t.Fatalf("%+v %v", r, e)
	}
	absent(t, o.Out, work)
}
func TestPreflightSeparateVolumes(t *testing.T) {
	o, work, probe := preflightFixture(t)
	parent := filepath.Join(filepath.Dir(work), "second")
	if e := os.Mkdir(parent, 0700); e != nil {
		t.Fatal(e)
	}
	work = filepath.Join(parent, "work")
	separate := func(p string) (volumeSample, error) {
		v, e := probe(p)
		if p == parent {
			v.ID = "other"
		}
		return v, e
	}
	r, e := preflight(context.Background(), o, work, false, 777, separate)
	if e != nil || r.Outcome != "pass" || len(r.Storage) != 2 {
		t.Fatalf("%+v %v", r, e)
	}
	var required int64
	for _, b := range r.Storage {
		required += b.Required
		if b.Reserve != 777 || len(b.Roles) != 1 {
			t.Fatal(b)
		}
	}
	if required != r.EstimatedOutput+r.EstimatedWork+1554 {
		t.Fatal(required)
	}
}
func TestPreflightUncertainProbes(t *testing.T) {
	for _, which := range []string{"source", "target"} {
		for _, bad := range []string{"error", "empty", "negative"} {
			t.Run(which+bad, func(t *testing.T) {
				o, work, probe := preflightFixture(t)
				uncertain := func(p string) (volumeSample, error) {
					if (p == o.Root) == (which == "source") {
						switch bad {
						case "error":
							return volumeSample{}, errors.New("unavailable")
						case "empty":
							return volumeSample{}, nil
						case "negative":
							return volumeSample{"unknown", -1}, nil
						}
					}
					return probe(p)
				}
				r, e := preflight(context.Background(), o, work, false, 0, uncertain)
				if e != nil || r.Outcome != "unknown" {
					t.Fatalf("%+v %v", r, e)
				}
				absent(t, o.Out, work)
			})
		}
	}
}
func TestPreflightSourceWarningAndEncryption(t *testing.T) {
	o, work, probe := preflightFixture(t)
	same := func(string) (volumeSample, error) { return volumeSample{"one", 4 << 30}, nil }
	r, e := preflight(context.Background(), o, work, false, 0, same)
	if e != nil || r.Outcome != "warning" {
		t.Fatalf("%+v %v", r, e)
	}
	enc, e := preflight(context.Background(), o, work, true, 0, probe)
	if e != nil || !enc.Encrypted || enc.EstimatedWork <= r.EstimatedWork || enc.EstimatedOutput <= r.EstimatedOutput {
		t.Fatalf("%+v %v", enc, e)
	}
	if _, e = preflight(context.Background(), o, "", true, 0, probe); e == nil {
		t.Fatal("encryption without work")
	}
	plain, e := preflight(context.Background(), o, "", false, 0, probe)
	if e != nil || plain.EstimatedWork != 0 || len(plain.Storage) != 1 {
		t.Fatalf("%+v %v", plain, e)
	}
}
func TestPreflightOverlapAndExisting(t *testing.T) {
	for _, kind := range []string{"output-in-source", "work-in-source", "source-in-work", "work-equals-output", "existing-output", "existing-work"} {
		t.Run(kind, func(t *testing.T) {
			o, work, probe := preflightFixture(t)
			switch kind {
			case "output-in-source":
				o.Out = filepath.Join(o.Root, "out")
			case "work-in-source":
				work = filepath.Join(o.Root, "work")
			case "source-in-work":
				work = filepath.Dir(o.Root)
			case "work-equals-output":
				work = o.Out
			case "existing-output":
				if e := os.WriteFile(o.Out, []byte("preserve"), 0600); e != nil {
					t.Fatal(e)
				}
			case "existing-work":
				if e := os.Mkdir(work, 0700); e != nil {
					t.Fatal(e)
				}
			}
			r, e := preflight(context.Background(), o, work, false, 0, probe)
			if e != nil || r.Outcome != "blocked" {
				t.Fatalf("%+v %v", r, e)
			}
			if kind == "existing-output" {
				b, _ := os.ReadFile(o.Out)
				if string(b) != "preserve" {
					t.Fatal("changed output")
				}
			}
		})
	}
}
func TestPreflightBudgetsAndCancellation(t *testing.T) {
	o, work, probe := preflightFixture(t)
	if e := os.WriteFile(filepath.Join(o.Root, "z"), []byte("small"), 0600); e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"file", "total", "count", "empty"} {
		t.Run(kind, func(t *testing.T) {
			limit := o
			switch kind {
			case "file":
				limit.MaxFile = 5
			case "total":
				limit.MaxTotal = 5
			case "count":
				limit.MaxFiles = 1
			case "empty":
				limit.MaxFile = 1
			}
			r, e := preflight(context.Background(), limit, work, false, 0, probe)
			if e != nil || r.Outcome != "warning" || len(r.Issues) == 0 {
				t.Fatalf("%+v %v", r, e)
			}
			if kind == "empty" && r.EligibleFiles != 0 || kind != "empty" && r.EligibleFiles != 1 {
				t.Fatal(r.EligibleFiles)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := preflight(ctx, o, work, false, 0, probe); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	absent(t, o.Out, work)
}
func TestPreflightInvalidInput(t *testing.T) {
	for _, kind := range []string{"root", "output", "system", "limit", "reserve", "missing-root", "file-root", "missing-parent"} {
		t.Run(kind, func(t *testing.T) {
			o, work, probe := preflightFixture(t)
			var reserve int64
			switch kind {
			case "root":
				o.Root = ""
			case "output":
				o.Out = ""
			case "system":
				o.System = true
			case "limit":
				o.MaxFile = 0
			case "reserve":
				reserve = -1
			case "missing-root":
				o.Root += "missing"
			case "file-root":
				o.Root = filepath.Join(o.Root, "auth.log")
			case "missing-parent":
				o.Out = filepath.Join(work, "output")
			}
			if _, e := preflight(context.Background(), o, work, false, reserve, probe); e == nil {
				t.Fatal("accepted invalid input")
			}
		})
	}
}
func TestNativeVolumeProbe(t *testing.T) {
	dir := t.TempDir()
	v, e := probeVolume(dir)
	if e != nil {
		t.Fatal(e)
	}
	if v.ID == "" || v.Available < 0 {
		t.Fatal(v)
	}
	if _, e = probeVolume(filepath.Join(dir, "missing")); e == nil {
		t.Fatal("missing path accepted")
	}
}
