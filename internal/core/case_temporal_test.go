package core

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTemporalScopeCorrectionsAndPolicyValidation(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	w, err := newCaseIndex(ctx, filepath.Join(dir, "case-index.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer w.close()
	digests := []string{strings.Repeat("a", 64), strings.Repeat("b", 64)}
	start := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	for i, digest := range digests {
		stamp := start.Add(time.Duration(i) * time.Hour)
		ev := Event{Time: stamp, Type: "log", Evidence: "E1", Source: "auth.log", Host: "host", User: "admin", SourceIP: "192.0.2.1", Line: 1}
		if err = w.add(ctx, CaseRow{Kind: "event", Digest: digest, Host: "host", Evidence: "E1", Time: &stamp, Payload: JSON(ev)}, "admin"); err != nil {
			t.Fatal(err)
		}
	}
	if err = w.finish(); err != nil {
		t.Fatal(err)
	}
	p, _ := LoadTemporalPolicy("")
	r, err := CorrelateCase(ctx, dir, "user", time.Minute, p)
	if err != nil || len(r.Groups) != 0 {
		t.Fatalf("same name incorrectly unified: %+v %v", r, err)
	}
	p.Identities = []IdentityMapping{{Digest: digests[0], Field: "user", Original: "admin", Identity: "person-1", Reason: "examiner mapping"}, {Digest: digests[1], Field: "user", Original: "admin", Identity: "person-1", Reason: "examiner mapping"}}
	r, err = CorrelateCase(ctx, dir, "user", time.Minute, p)
	if err != nil || len(r.Groups) != 0 {
		t.Fatalf("out-of-window match: %+v %v", r, err)
	}
	p.Clocks = []ClockEstimate{{Digest: digests[0], Reference: "reference A"}, {Digest: digests[1], OffsetNS: int64(time.Hour), UncertaintyNS: int64(time.Second), Reference: "reference B"}}
	r, err = CorrelateCase(ctx, dir, "user", time.Minute, p)
	if err != nil || len(r.Groups) != 1 || !r.Groups[0].ClockKnown {
		t.Fatalf("correction missing: %+v %v", r, err)
	}
	if !r.Groups[0].References[1].Reference.Time.Equal(start.Add(time.Hour)) || !r.Groups[0].References[1].EstimatedUTC.Equal(start) || r.PolicySHA256 != digestJSON(r.Policy) {
		t.Fatal("source time or policy provenance lost")
	}
	p.Clocks[1].UncertaintyNS = -1
	if _, err = CorrelateCase(ctx, dir, "user", time.Minute, p); err == nil {
		t.Fatal("library accepted invalid policy")
	}
	r, err = CorrelateCase(ctx, dir, "source_ip", 2*time.Hour, TemporalPolicy{Schema: "k957-temporal-policy/1"})
	if err != nil || len(r.Groups) != 1 || r.Groups[0].ClockKnown || r.Groups[0].Scope != "value-only" {
		t.Fatal("NAT/value match became identity or trusted time", err)
	}
}
