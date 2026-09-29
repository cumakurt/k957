package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func resumePreflightFixture(t *testing.T, encrypted bool) (Options, string, func(string) (volumeSample, error)) {
	t.Helper()
	_, o, work := resumeFixture(t)
	var err error
	o.Root, err = filepath.EvalSymlinks(o.Root)
	if err != nil {
		t.Fatal(err)
	}
	work, err = canonicalDestination(work)
	if err != nil {
		t.Fatal(err)
	}
	o.Out, err = canonicalDestination(o.Out)
	if err != nil {
		t.Fatal(err)
	}
	if encrypted {
		o.EncryptionKey = filepath.Join(filepath.Dir(work), "key")
		if err := EncryptionKey(o.EncryptionKey); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := collectResumable(ctx, o, work, false, cancel); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected saved mid-file checkpoint: %v", err)
	}
	probe := func(p string) (volumeSample, error) {
		id := "target"
		if p == o.Root {
			id = "source"
		}
		return volumeSample{id, 4 << 30}, nil
	}
	return o, work, probe
}

func workDigests(t *testing.T, work string) map[string][32]byte {
	t.Helper()
	out := map[string][32]byte{}
	err := filepath.WalkDir(work, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		out[path] = sha256.Sum256(b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func requireCheck(t *testing.T, r PreflightResult, code string) {
	t.Helper()
	for _, check := range r.Checks {
		if check.Code == code && check.Status == "blocked" && r.Outcome == "blocked" {
			return
		}
	}
	t.Fatalf("missing blocked %s: %+v", code, r)
}

func TestResumePreflightRemainingBudget(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(map[bool]string{false: "plain", true: "encrypted"}[encrypted], func(t *testing.T) {
			o, work, probe := resumePreflightFixture(t, encrypted)
			before := workDigests(t, work)
			r, err := planPreflight(context.Background(), o, work, encrypted, true, 123, probe)
			if err != nil || r.Outcome != "pass" || !r.Resume || r.Encrypted != encrypted {
				t.Fatalf("%+v %v", r, err)
			}
			if r.EligibleFiles != 1 || r.EligibleBytes != 2*resumeChunk+19 || r.AcquiredBytes != resumeChunk || r.RemainingBytes != resumeChunk+19 || r.Parts != 3 || r.RemainingParts != 2 || r.CompletedFiles != 0 {
				t.Fatalf("wrong remaining inventory: %+v", r)
			}
			fresh, err := preflight(context.Background(), o, work+"-new", encrypted, 123, probe)
			if err != nil || fresh.EstimatedOutput != r.EstimatedOutput || fresh.EstimatedWork <= r.EstimatedWork {
				t.Fatalf("saved bytes must reduce staging only: fresh=%+v resumed=%+v err=%v", fresh, r, err)
			}
			if len(r.Storage) != 1 || r.Storage[0].Required != r.EstimatedWork+r.EstimatedOutput+123 || !reflect.DeepEqual(r.Storage[0].Roles, []string{"output", "work", "chunks"}) {
				t.Fatalf("wrong combined budget: %+v", r.Storage)
			}
			for _, delta := range []int64{0, -1} {
				limited := func(p string) (volumeSample, error) {
					v, err := probe(p)
					v.Available = r.Storage[0].Required + delta
					return v, err
				}
				got, err := planPreflight(context.Background(), o, work, encrypted, true, 123, limited)
				if err != nil {
					t.Fatal(err)
				}
				if delta == 0 && got.Outcome != "pass" {
					t.Fatalf("already occupied space was counted twice: %+v", got)
				}
				if delta < 0 {
					requireCheck(t, got, "INSUFFICIENT_ESTIMATED_SPACE")
				}
			}
			if !reflect.DeepEqual(before, workDigests(t, work)) {
				t.Fatal("preflight changed saved work")
			}
			absent(t, o.Out, filepath.Join(work, "active.lock"))
		})
	}
}

func TestResumePreflightMountedStagingBudgets(t *testing.T) {
	o, work, _ := resumePreflightFixture(t, false)
	ids := map[string]string{o.Root: "source", filepath.Dir(o.Out): "output", work: "metadata", filepath.Join(work, "chunks"): "parts"}
	probe := func(path string) (volumeSample, error) {
		id, ok := ids[path]
		if !ok {
			t.Fatalf("probed parent instead of actual destination: %s", path)
		}
		return volumeSample{id, 4 << 30}, nil
	}
	r, err := planPreflight(context.Background(), o, work, false, true, 321, probe)
	if err != nil || r.Outcome != "pass" || len(r.Storage) != 3 {
		t.Fatalf("%+v %v", r, err)
	}
	var sum int64
	for _, b := range r.Storage {
		if b.Reserve != 321 || len(b.Roles) != 1 {
			t.Fatal(b)
		}
		if b.Filesystem == "metadata" && b.Estimated != 64<<20 {
			t.Fatal(b)
		}
		sum += b.Required
	}
	if sum != r.EstimatedWork+r.EstimatedOutput+3*321 {
		t.Fatal("incorrect per-filesystem reserves", sum)
	}
	unknown := func(path string) (volumeSample, error) {
		if path == filepath.Join(work, "chunks") {
			return volumeSample{}, errors.New("offline chunk volume")
		}
		return probe(path)
	}
	r, err = planPreflight(context.Background(), o, work, false, true, 0, unknown)
	if err != nil || r.Outcome != "unknown" {
		t.Fatalf("unknown chunk capacity accepted: %+v %v", r, err)
	}
}

func TestResumePreflightCompletedFrozenInventory(t *testing.T) {
	o, work, probe := resumePreflightFixture(t, false)
	if _, err := CollectResumable(context.Background(), o, work, true); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(o.Root, "large.bin")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(o.Root, "new.bin"), []byte("outside frozen inventory"), 0600); err != nil {
		t.Fatal(err)
	}
	o.Out += "-new"
	r, err := planPreflight(context.Background(), o, work, false, true, 0, probe)
	if err != nil || r.Outcome != "pass" || r.EligibleFiles != 1 || r.CompletedFiles != 1 || r.AcquiredBytes != r.EligibleBytes || r.RemainingBytes != 0 || r.RemainingParts != 0 || r.EstimatedWork != 64<<20 || r.EstimatedOutput < r.EligibleBytes {
		t.Fatalf("completed work must need metadata + full output space: %+v %v", r, err)
	}
	if _, err := CollectResumable(context.Background(), o, work, true); err != nil {
		t.Fatal(err)
	}
}

func TestResumePreflightRejectsInvalidState(t *testing.T) {
	for _, kind := range []string{"lock", "source-missing", "source-size", "source-time", "chunk-missing", "chunk-size", "chunk-directory", "root", "limits", "case", "operator", "scope", "existing-output", "epochs"} {
		t.Run(kind, func(t *testing.T) {
			o, work, probe := resumePreflightFixture(t, false)
			var state WorkState
			if err := readWork(work, &state); err != nil {
				t.Fatal(err)
			}
			chunk := filepath.Join(work, "chunks", state.Files[0].Item.Parts[0].SHA256)
			source := filepath.Join(o.Root, "large.bin")
			code := "RESUME_OPTIONS_MISMATCH"
			var err error
			switch kind {
			case "lock":
				code = "WORK_LOCK_PRESENT"
				err = os.WriteFile(filepath.Join(work, "active.lock"), []byte("owned test lock"), 0600)
			case "source-missing":
				code = "RESUME_SOURCE_CHANGED"
				err = os.Remove(source)
			case "source-size":
				code = "RESUME_SOURCE_CHANGED"
				err = os.Truncate(source, 1)
			case "source-time":
				code = "RESUME_SOURCE_CHANGED"
				modified := state.Files[0].Item.Modified.AddDate(0, 0, -1)
				err = os.Chtimes(source, modified, modified)
			case "chunk-missing", "chunk-directory":
				code = "SAVED_CHUNK_UNAVAILABLE"
				err = os.Remove(chunk)
				if err == nil && kind == "chunk-directory" {
					err = os.Mkdir(chunk, 0700)
				}
			case "chunk-size":
				code = "SAVED_CHUNK_UNAVAILABLE"
				err = os.Truncate(chunk, 1)
			case "root":
				o.Root = filepath.Join(filepath.Dir(work), "different-source")
				err = os.Mkdir(o.Root, 0700)
			case "limits":
				o.MaxTotal++
			case "case":
				o.Case += "different"
			case "operator":
				o.Operator += "different"
			case "scope":
				o.Scope += "different"
			case "existing-output":
				code = "DESTINATION_EXISTS"
				err = os.WriteFile(o.Out, []byte("preserve"), 0600)
			case "epochs":
				code = "EPOCH_LIMIT_REACHED"
				for len(state.Manifest.Epochs) < 1000 {
					epoch := state.Manifest.Epochs[0]
					epoch.ID = fmt.Sprintf("EPOCH-%d", len(state.Manifest.Epochs))
					state.Manifest.Epochs = append(state.Manifest.Epochs, epoch)
				}
				err = saveWork(work, state)
			}
			if err != nil {
				t.Fatal(err)
			}
			before := workDigests(t, work)
			r, err := planPreflight(context.Background(), o, work, false, true, 0, probe)
			if err != nil {
				t.Fatal(err)
			}
			requireCheck(t, r, code)
			if !reflect.DeepEqual(before, workDigests(t, work)) {
				t.Fatal("rejected preflight changed work")
			}
		})
	}
}

func TestResumePreflightAuthenticationAndCancellation(t *testing.T) {
	o, work, _ := resumePreflightFixture(t, true)
	before := workDigests(t, work)
	bad := o
	bad.EncryptionKey = ""
	if _, err := PreflightResume(context.Background(), bad, work, 0); err == nil {
		t.Fatal("encrypted checkpoint accepted without key")
	}
	bad.EncryptionKey = filepath.Join(filepath.Dir(work), "wrong.key")
	if err := EncryptionKey(bad.EncryptionKey); err != nil {
		t.Fatal(err)
	}
	if _, err := PreflightResume(context.Background(), bad, work, 0); err == nil {
		t.Fatal("wrong key accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := PreflightResume(ctx, o, work, 0); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := PreflightResume(context.Background(), o, "", 0); err == nil {
		t.Fatal("missing work accepted")
	}
	if !reflect.DeepEqual(before, workDigests(t, work)) {
		t.Fatal("failed preflight changed work")
	}
}

func TestResumePreflightDoesNotReplaceIntegrityVerification(t *testing.T) {
	o, work, probe := resumePreflightFixture(t, false)
	var state WorkState
	if err := readWork(work, &state); err != nil {
		t.Fatal(err)
	}
	chunk := filepath.Join(work, "chunks", state.Files[0].Item.Parts[0].SHA256)
	if err := os.WriteFile(chunk, bytes.Repeat([]byte("Z"), resumeChunk), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := planPreflight(context.Background(), o, work, false, true, 0, probe)
	if err != nil || r.Outcome != "pass" {
		t.Fatalf("metadata-only preflight unexpectedly read contents: %+v %v", r, err)
	}
	if _, err := CollectResumable(context.Background(), o, work, true); err == nil || !strings.Contains(err.Error(), "hash mismatch") {
		t.Fatalf("resume did not reject corrupted content: %v", err)
	}
	absent(t, o.Out)
}
