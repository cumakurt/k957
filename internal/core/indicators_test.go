package core

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOfflineIndicatorsExactReferencesAndNoVerdicts(t *testing.T) {
	d := t.TempDir()
	list := filepath.Join(d, "iocs.json")
	hash := strings.Repeat("a", 64)
	spec := IndicatorSet{Schema: "k957-indicators/1", Name: "Synthetic indicators", Source: "Examiner fixture", Indicators: []Indicator{{ID: "hash", Kind: "sha256", Value: strings.ToUpper(hash)}, {ID: "ip", Kind: "ip", Value: "2001:0db8::1"}, {ID: "domain", Kind: "domain", Value: "Example.TEST."}}}
	if e := WriteJSONNew(list, spec); e != nil {
		t.Fatal(e)
	}
	s, e := LoadIndicators(list)
	if e != nil {
		t.Fatal(e)
	}
	stamp := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	a := Analysis{Manifest: Manifest{Items: []Item{{ID: "E1", Source: "fixture.bin", SHA256: hash}}}, Timeline: []Event{{Evidence: "E2", Source: "history", Type: "browser_visit", Time: stamp, Detail: "https://example.test/path | Synthetic title", Native: &NativeRecord{Table: "urls", Record: "7"}}, {Evidence: "E3", Source: "capture", Time: stamp, Packet: 4, SourceIP: "2001:db8::1"}, {Evidence: "E4", Source: "text", Detail: "https://example.test is text, not a parsed URL"}}, NetworkInterpretations: []NetworkInterpretation{{Observations: []ProtocolObservation{{Evidence: "E3", Source: "capture", Protocol: "HTTP", HTTP: &HTTPMetadata{Host: "example.test:443"}, References: []PacketReference{{Packet: 8, Time: stamp, ByteOffset: 120}}}, {Evidence: "E3", Source: "capture", Protocol: "DNS", DNS: &DNSMetadata{Questions: []DNSQuestion{{Name: "EXAMPLE.TEST."}}}}, {Evidence: "E3", Source: "capture", Protocol: "TLS", TLS: &TLSMetadata{ServerName: "other.example.test"}}}}}}
	ctx := WithIndicators(context.Background(), s)
	applyConfiguredIndicators(ctx, &a)
	if a.Indicators == nil || len(a.Indicators.Matches) != 5 || len(a.Findings) != 0 {
		t.Fatalf("%#v", a.Indicators)
	}
	if a.Indicators.Matches[1].Event == nil || a.Indicators.Matches[1].Event.Record != "7" {
		t.Fatal("browser reference lost")
	}
	if a.Indicators.Matches[3].Event == nil || a.Indicators.Matches[3].Event.Packet != 8 || !a.Indicators.Matches[3].Event.Time.Equal(stamp) {
		t.Fatal("packet reference lost")
	}
	applyConfiguredIndicators(ctx, &a)
	if len(a.Indicators.Matches) != 5 {
		t.Fatal("reapplication duplicated matches")
	}
	if e := exportIndicators(a, d); e != nil {
		t.Fatal(e)
	}
	for _, body := range []string{`{"schema":"k957-indicators/1","name":"x","source":"y","indicators":[{"id":"a","kind":"ip","value":"bad"}]}`, `{"schema":"k957-indicators/1","name":"x","source":"y","indicators":[{"id":"a","kind":"domain","value":"example.test"},{"id":"a","kind":"ip","value":"192.0.2.1"}]}`, `{"schema":"k957-indicators/1","name":"x","name":"y","source":"z","indicators":[]}`} {
		bad := filepath.Join(t.TempDir(), "bad.json")
		os.WriteFile(bad, []byte(body), 0600)
		if _, e := LoadIndicators(bad); e == nil {
			t.Fatalf("accepted %s", body)
		}
	}
}

func TestExplicitAttackLayerMappings(t *testing.T) {
	d := t.TempDir()
	a := Analysis{EvidenceDigest: strings.Repeat("b", 64), Manifest: Manifest{Case: "Fixture"}, Rules: []Rule{{ID: "r", Contains: "fixture", Techniques: []string{"T1059.001"}}}, Findings: []Finding{{ID: "F1", Rule: "r", Review: "unreviewed"}, {ID: "F2", Rule: "r", Review: "rejected"}}}
	if e := exportAttackLayer(a, d); e != nil {
		t.Fatal(e)
	}
	var layer attackLayer
	body, e := os.ReadFile(filepath.Join(d, "attack-navigator.json"))
	if e != nil {
		t.Fatal(e)
	}
	if e := validateExternalJSON(body); e != nil {
		t.Fatal(e)
	}
	if e := json.Unmarshal(body, &layer); e != nil {
		t.Fatal(e)
	}
	if len(layer.Techniques) != 1 || layer.Techniques[0].Score != 1 || layer.Versions["layer"] != "4.5" {
		t.Fatal(layer)
	}
	if e := exportAttackLayer(Analysis{Rules: []Rule{{ID: "r", Contains: "powershell"}}}, t.TempDir()); e != nil {
		t.Fatal(e)
	}
	for _, techniques := range [][]string{{"T1059.001", "T1059.001"}, {"Tbad"}} {
		path := filepath.Join(t.TempDir(), "rules.json")
		WriteJSONNew(path, []Rule{{ID: "r", Contains: "fixture", Techniques: techniques}})
		if _, e := LoadRules(path); e == nil {
			t.Fatal("invalid mapping accepted")
		}
	}
}
