package core

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func resumeFixture(t *testing.T) (string, Options, string) {
	d, o := fixture(t, false)
	os.Remove(filepath.Join(o.Root, "auth.log"))
	o.MaxFile = 32 << 20
	o.MaxTotal = 64 << 20
	data := append(bytes.Repeat([]byte("A"), resumeChunk), bytes.Repeat([]byte("B"), resumeChunk+19)...)
	if e := os.WriteFile(filepath.Join(o.Root, "large.bin"), data, 0600); e != nil {
		t.Fatal(e)
	}
	return d, o, filepath.Join(d, "work")
}
func interruptAfterChunk(t *testing.T, o Options, work string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, e := collectResumable(ctx, o, work, false, cancel)
	if e == nil {
		t.Fatal("expected interruption")
	}
	if _, e = os.Stat(o.Out); !os.IsNotExist(e) {
		t.Fatal("incomplete output left")
	}
	var state WorkState
	if e = readWork(work, &state); e != nil {
		t.Fatal(e)
	}
	if len(state.Files[0].Item.Parts) != 1 {
		t.Fatal("expected one saved chunk")
	}
}
func TestResumeAcrossEpochs(t *testing.T) {
	d, o, work := resumeFixture(t)
	interruptAfterChunk(t, o, work)
	Keygen(filepath.Join(d, "sign"))
	o.SignKey = filepath.Join(d, "sign.key")
	m, e := CollectResumable(context.Background(), o, work, true)
	if e != nil {
		t.Fatal(e)
	}
	if len(m.Epochs) != 2 || len(m.Items) != 1 || len(m.Items[0].Parts) != 3 {
		t.Fatalf("bad provenance: %+v", m)
	}
	parts := m.Items[0].Parts
	if parts[0].Epoch == parts[1].Epoch {
		t.Fatal("epochs collapsed")
	}
	p, e := Open(o.Out, filepath.Join(d, "sign.pub"))
	if e != nil {
		t.Fatal(e)
	}
	defer p.Zip.Close()
	got, e := readEntry(p.Files[m.Items[0].Object], 32<<20)
	if e != nil {
		t.Fatal(e)
	}
	want, _ := os.ReadFile(filepath.Join(o.Root, "large.bin"))
	if !bytes.Equal(got, want) {
		t.Fatal("wrong bytes")
	}
	a := Analyze(p, nil)
	if !strings.Contains(strings.Join(a.Notes, " "), "not a single point-in-time") {
		t.Fatal("missing acquisition warning")
	}
	if e = Export(a, filepath.Join(d, "report")); e != nil {
		t.Fatal(e)
	}
}
func TestResumePrefixMutationSameMetadata(t *testing.T) {
	_, o, work := resumeFixture(t)
	interruptAfterChunk(t, o, work)
	path := filepath.Join(o.Root, "large.bin")
	st, _ := os.Stat(path)
	f, _ := os.OpenFile(path, os.O_WRONLY, 0600)
	f.WriteAt([]byte("Z"), 0)
	f.Close()
	os.Chtimes(path, st.ModTime(), st.ModTime())
	_, e := CollectResumable(context.Background(), o, work, true)
	if e == nil || !strings.Contains(e.Error(), "prefix differs") {
		t.Fatal(e)
	}
}
func TestResumeCorruptedChunk(t *testing.T) {
	_, o, work := resumeFixture(t)
	interruptAfterChunk(t, o, work)
	var state WorkState
	readWork(work, &state)
	path := filepath.Join(work, "chunks", state.Files[0].Item.Parts[0].SHA256)
	f, _ := os.OpenFile(path, os.O_WRONLY, 0600)
	f.WriteAt([]byte("Z"), 0)
	f.Close()
	_, e := CollectResumable(context.Background(), o, work, true)
	if e == nil || !strings.Contains(e.Error(), "hash mismatch") {
		t.Fatal(e)
	}
}
func TestResumeMetadataChange(t *testing.T) {
	_, o, work := resumeFixture(t)
	interruptAfterChunk(t, o, work)
	os.WriteFile(filepath.Join(o.Root, "large.bin"), []byte("new"), 0600)
	_, e := CollectResumable(context.Background(), o, work, true)
	if e == nil || !strings.Contains(e.Error(), "source changed") {
		t.Fatal(e)
	}
}
func TestResumeOptionBindingAndLock(t *testing.T) {
	_, o, work := resumeFixture(t)
	interruptAfterChunk(t, o, work)
	changed := o
	changed.Case = "DIFFERENT"
	if _, e := CollectResumable(context.Background(), changed, work, true); e == nil {
		t.Fatal("wrong case accepted")
	}
	WriteNew(filepath.Join(work, "active.lock"), []byte("active"))
	if _, e := CollectResumable(context.Background(), o, work, true); e == nil {
		t.Fatal("concurrent access accepted")
	}
}
func TestResumeCompletedReuseAndFrozenInventory(t *testing.T) {
	d, o, work := resumeFixture(t)
	m, e := CollectResumable(context.Background(), o, work, false)
	if e != nil {
		t.Fatal(e)
	}
	os.Remove(filepath.Join(o.Root, "large.bin"))
	os.WriteFile(filepath.Join(o.Root, "new.txt"), []byte("new"), 0600)
	o.Out = filepath.Join(d, "second.k957")
	m2, e := CollectResumable(context.Background(), o, work, true)
	if e != nil {
		t.Fatal(e)
	}
	if len(m2.Items) != 1 || m2.Items[0].SHA256 != m.Items[0].SHA256 || len(m2.Epochs) != 2 {
		t.Fatal("frozen inventory not preserved")
	}
}
func TestResumeEmptyFileAndSkippedSources(t *testing.T) {
	d, o := fixture(t, false)
	o.MaxFile = 1
	os.WriteFile(filepath.Join(o.Root, "empty"), nil, 0600)
	m, e := CollectResumable(context.Background(), o, filepath.Join(d, "work"), false)
	if e != nil {
		t.Fatal(e)
	}
	if m.Status != "partial" || len(m.Items) != 1 || m.Items[0].Size != 0 {
		t.Fatal(m)
	}
	p, e := Open(o.Out, "")
	if e != nil {
		t.Fatal(e)
	}
	p.Zip.Close()
}
func TestResumePartManifestTamper(t *testing.T) {
	d, o, work := resumeFixture(t)
	CollectResumable(context.Background(), o, work, false)
	bad := filepath.Join(d, "bad")
	rewrite(t, o.Out, bad, func(name string, b []byte) []byte {
		if name == "manifest.json" {
			var m Manifest
			json.Unmarshal(b, &m)
			m.Items[0].Parts[0].SHA256 = strings.Repeat("0", 64)
			return JSON(m)
		}
		return b
	}, false)
	if p, e := Open(bad, ""); e == nil {
		p.Zip.Close()
		t.Fatal("tampered part hash accepted")
	}
}
func TestResumePathIsolation(t *testing.T) {
	_, o, _ := resumeFixture(t)
	if _, e := CollectResumable(context.Background(), o, filepath.Join(o.Root, "work"), false); e == nil {
		t.Fatal("work inside source accepted")
	}
}
func TestResumeCheckpointPathEscape(t *testing.T) {
	_, o, work := resumeFixture(t)
	interruptAfterChunk(t, o, work)
	var s WorkState
	readWork(work, &s)
	s.Files[0].Item.Source = "/outside"
	saveWork(work, s)
	if _, e := CollectResumable(context.Background(), o, work, true); e == nil {
		t.Fatal("checkpoint path escape accepted")
	}
}
func TestInspectWork(t *testing.T) {
	_, o, work := resumeFixture(t)
	interruptAfterChunk(t, o, work)
	s, e := InspectWork(context.Background(), work, true)
	if e != nil {
		t.Fatal(e)
	}
	if s.Completed != 0 || s.AcquiredBytes != resumeChunk || s.Parts != 1 || !s.PartsVerified || s.LockPresent {
		t.Fatalf("%+v", s)
	}
}
func TestRejectSystemResumable(t *testing.T) {
	_, o, work := resumeFixture(t)
	o.System = true
	if _, e := CollectResumable(context.Background(), o, work, false); e == nil {
		t.Fatal("accepted replayable live snapshots")
	}
}
