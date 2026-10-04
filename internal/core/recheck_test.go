package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRecheckFullCollectionTrustAndBinding(t *testing.T) {
	for _, memoryOnly := range []bool{false, true} {
		t.Run(map[bool]string{false: "logical", true: "memory-only"}[memoryOnly], func(t *testing.T) {
			d, o := fixture(t, false)
			options := FullOptions{OutputDir: filepath.Join(d, "output"), Root: o.Root, Case: "T", MaxFile: 1024, MaxTotal: 2048, MaxFiles: 10}
			if memoryOnly {
				options.Root = ""
				options.Memory = true
				options.IOMem = filepath.Join(d, "iomem")
				options.Kcore = filepath.Join(d, "kcore")
				payload := make([]byte, 4096)
				copy(payload, "failed password for analyst\n")
				writeKcore(t, options.Kcore, 0x300000, len(payload), payload)
				if err := os.WriteFile(options.IOMem, []byte("00300000-00300fff : System RAM\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			rec, err := CollectFull(context.Background(), options)
			if err != nil {
				t.Fatal(err)
			}
			body, err := os.ReadFile(filepath.Join(rec.Directory, "collection.json"))
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(body)
			for _, trusted := range []bool{false, true} {
				key := ""
				if trusted {
					key = filepath.Join(rec.Directory, "signing.pub")
				}
				result := analyzeCollection(context.Background(), rec.Directory, BuiltinRules(), key, nil, nil)
				if result.Status != "analyzed" {
					t.Fatalf("%+v", result)
				}
				a, err := LoadAnalysis(filepath.Join(result.Report, "analysis.json"))
				if err != nil {
					t.Fatal(err)
				}
				wantTrust := "verified against embedded key; not an external trust anchor"
				if trusted {
					wantTrust = "verified against supplied trusted key"
				}
				if a.Signature != wantTrust {
					t.Errorf("signature trust overstated: %q", a.Signature)
				}
				if a.EvidenceDigest != hex.EncodeToString(digest[:]) {
					t.Errorf("analysis not bound to full collection record: %s", a.EvidenceDigest)
				}
			}
		})
	}
}

func TestRecheckPartialCollectionReport(t *testing.T) {
	d, o := fixture(t, false)
	rec, err := CollectFull(context.Background(), FullOptions{OutputDir: filepath.Join(d, "output"), Root: o.Root, Memory: true, IOMem: filepath.Join(d, "missing-iomem"), Kcore: filepath.Join(d, "missing-kcore"), MaxFile: 1024, MaxTotal: 2048, MaxFiles: 10})
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != "partial" || len(rec.Issues) == 0 {
		t.Fatalf("missing partial fixture: %+v", rec)
	}
	result := analyzeCollection(context.Background(), rec.Directory, nil, "", nil, nil)
	if result.Status != "analyzed" {
		t.Fatalf("%+v", result)
	}
	a, err := LoadAnalysis(filepath.Join(result.Report, "analysis.json"))
	if err != nil {
		t.Fatal(err)
	}
	view, err := newReportView(a)
	if err != nil {
		t.Fatal(err)
	}
	if view.Status != "partial" || view.IssueCount == 0 || a.Manifest.Status != "complete" {
		t.Fatal("report hid failed memory acquisition or changed package metadata")
	}
	policy, err := LoadSharePolicy("")
	if err != nil {
		t.Fatal(err)
	}
	shared, err := BuildSharedReport(a, policy)
	if err != nil || shared.CollectionStatus != "partial" || shared.SourceIssueCount == 0 {
		t.Fatalf("shared report hid collection failure: %v", err)
	}
}

func TestRecheckMalformedRecordCannotClaimAuthentication(t *testing.T) {
	d := t.TempDir()
	if err := WriteNew(filepath.Join(d, "collection.json"), []byte("{")); err != nil {
		t.Fatal(err)
	}
	v := verifyCollection(d, "")
	if v.Status != "failed" || strings.HasPrefix(v.Signature, "verified") {
		t.Fatalf("unreadable record claimed authentication: %+v", v)
	}
}

func TestRecheckCaseCancellationRemovesPartialOutput(t *testing.T) {
	d, o := fixture(t, false)
	base := filepath.Join(d, "output")
	if _, err := CollectFull(context.Background(), FullOptions{OutputDir: base, Root: o.Root, MaxFile: 1024, MaxTotal: 2048, MaxFiles: 10}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx = WithProgress(ctx, func(p Progress) {
		if p.Phase == "case" && strings.HasSuffix(p.Detail, "auth.log") {
			cancel()
		}
	})
	out := filepath.Join(d, "case-report")
	if _, err := BuildCase(ctx, base, out, "", nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled case published: %v", err)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("canceled case report remained")
	}
}

func TestRecheckDuplicateReviewAndCheckpointKeys(t *testing.T) {
	d, a := reviewFixture(t)
	ledger, err := AddReview(a, nil, a.Findings[0].ID, "needs-review", "Tester", "Inspect fixture", "", "")
	if err != nil {
		t.Fatal(err)
	}
	bad := bytes.Replace(JSON(ledger), []byte(`"schema": "k957-review/1"`), []byte(`"schema": "wrong", "schema": "k957-review/1"`), 1)
	path := filepath.Join(d, "ambiguous-ledger.json")
	if err := WriteNew(path, bad); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadLedger(path); err == nil {
		t.Error("duplicate review key accepted")
	}
	_, o := fixture(t, false)
	work := filepath.Join(filepath.Dir(o.Out), "work")
	if _, err := CollectResumable(context.Background(), o, work, false); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(work, "state.json")
	state, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	state = bytes.Replace(state, []byte(`"schema": "k957-work/1"`), []byte(`"schema": "wrong", "schema": "k957-work/1"`), 1)
	if err := os.WriteFile(statePath, state, 0600); err != nil {
		t.Fatal(err)
	}
	var loaded WorkState
	if err := readWork(work, &loaded); err == nil {
		t.Error("duplicate checkpoint key accepted")
	}
}

func TestRecheckTaskNamespaceSeparation(t *testing.T) {
	text := `<Task xmlns="` + taskNamespace + `"><Actions><Exec xmlns="urn:foreign"><Command>unrelated</Command></Exec><Exec><Command>actual</Command></Exec></Actions></Task>`
	events, summary, _ := parseScheduledTask([]byte(text), Item{ID: "E1", Source: "task.xml"}, 10)
	if summary.Error != "" || len(events) != 1 || events[0].Detail != "actual" {
		t.Fatalf("foreign namespace interpreted as a task command: %+v %+v", events, summary)
	}
}

func TestRecheckCancellationWithoutByteEstimate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	meter := &verifyMeter{ctx: ctx}
	if _, err := io.ReadAll(meter.reader(bytes.NewReader([]byte("fixture")), "fixture", 0)); !errors.Is(err, context.Canceled) {
		t.Fatalf("unknown-size reader ignored cancellation: %v", err)
	}
	path := filepath.Join(t.TempDir(), "memory.raw")
	if err := WriteNew(path, []byte("fixture")); err != nil {
		t.Fatal(err)
	}
	if _, err := fileSHA256Progress(path, "fixture", 0, meter); !errors.Is(err, context.Canceled) {
		t.Fatalf("SHA-256 ignored cancellation: %v", err)
	}
	if _, _, _, _, err := hashFileProgress(path, "fixture", 0, meter); !errors.Is(err, context.Canceled) {
		t.Fatalf("artifact hashing ignored cancellation: %v", err)
	}
	if _, err := scanMemoryFileProgress(path, nil, meter, 0); !errors.Is(err, context.Canceled) {
		t.Fatalf("memory scan ignored cancellation: %v", err)
	}
}
