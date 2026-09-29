package core

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type custodyFixtureData struct {
	dir   string
	p     *Package
	trust CustodyTrust
	keys  map[string]string
}

func custodyFixture(t *testing.T) custodyFixtureData {
	t.Helper()
	d, o := fixture(t, false)
	if _, e := Collect(context.Background(), o); e != nil {
		t.Fatal(e)
	}
	p, e := Open(o.Out, "")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { p.Zip.Close() })
	f := custodyFixtureData{d, p, CustodyTrust{Schema: custodyTrustSchema, Keys: []CustodyIdentity{}}, map[string]string{}}
	for _, name := range []string{"Alice", "Bob", "Carol"} {
		prefix := filepath.Join(d, name)
		if e = Keygen(prefix); e != nil {
			t.Fatal(e)
		}
		b, e := os.ReadFile(prefix + ".pub")
		if e != nil {
			t.Fatal(e)
		}
		f.keys[name] = prefix + ".key"
		f.trust.Keys = append(f.trust.Keys, CustodyIdentity{name, strings.TrimSpace(string(b))})
	}
	return f
}
func (f custodyFixtureData) add(t *testing.T, prev *CustodyLedger, action, actor, to string) CustodyLedger {
	t.Helper()
	head := ""
	if prev != nil {
		head = prev.Events[len(prev.Events)-1].Hash
	}
	l, e := AddCustody(f.p, prev, CustodyRequest{Action: action, Actor: actor, To: to, Location: "Lab", Note: "Synthetic declaration"}, f.keys[actor], f.trust, head)
	if e != nil {
		t.Fatal(e)
	}
	return l
}
func (f custodyFixtureData) validate(l CustodyLedger, head string) (CustodyStatus, error) {
	return ValidateCustody(l, f.p.ManifestSHA256, f.p.Manifest.ID, f.p.Manifest.Case, f.trust, head)
}
func cloneCustody(l CustodyLedger) CustodyLedger {
	var c CustodyLedger
	json.Unmarshal(JSON(l), &c)
	return c
}
func resignCustody(t *testing.T, l *CustodyLedger, i int, key string, change func(*CustodyClaim)) {
	t.Helper()
	entry := &l.Events[i]
	b, e := base64.StdEncoding.DecodeString(entry.Payload)
	if e != nil {
		t.Fatal(e)
	}
	var c CustodyClaim
	if e = json.Unmarshal(b, &c); e != nil {
		t.Fatal(e)
	}
	change(&c)
	k, e := os.ReadFile(key)
	if e != nil {
		t.Fatal(e)
	}
	priv, e := decodePrivate(k)
	if e != nil {
		t.Fatal(e)
	}
	pub := priv.Public().(ed25519.PublicKey)
	payload := JSON(c)
	sig := ed25519.Sign(priv, append([]byte(custodySignDomain), payload...))
	*entry = CustodyEntry{base64.StdEncoding.EncodeToString(payload), hex.EncodeToString(pub), hex.EncodeToString(sig), custodyHead(pub, sig, payload)}
}
func TestCustodyHandoverAndPreservedSignatures(t *testing.T) {
	f := custodyFixture(t)
	first := f.add(t, nil, "register", "Alice", "")
	saved := JSON(first)
	offered := f.add(t, &first, "transfer", "Alice", "Bob")
	s, e := f.validate(offered, offered.Events[1].Hash)
	if e != nil || s.CurrentHolder != "Alice" || s.PendingTo != "Bob" {
		t.Fatalf("%+v %v", s, e)
	}
	accepted := f.add(t, &offered, "accept", "Bob", "")
	final := f.add(t, &accepted, "note", "Bob", "")
	s, e = f.validate(final, final.Events[3].Hash)
	if e != nil || s.CurrentHolder != "Bob" || s.PendingTo != "" || len(s.Events) != 4 {
		t.Fatalf("%+v %v", s, e)
	}
	if !bytes.Equal(saved, JSON(first)) || final.Events[0] != first.Events[0] || final.Events[1] != offered.Events[1] {
		t.Fatal("history/signature replaced")
	}
	// Format has no analysis/app version binding; a verified legacy package works.
	a := Analyze(f.p, nil)
	if e = ApplyCustody(&a, final, f.trust, s.Head); e != nil {
		t.Fatal(e)
	}
	if a.Custody == nil || len(a.Custody.Events) != 4 {
		t.Fatal("missing report history")
	}
}
func TestCustodyCancellationAndTransitionRejections(t *testing.T) {
	f := custodyFixture(t)
	registered := f.add(t, nil, "register", "Alice", "")
	offered := f.add(t, &registered, "transfer", "Alice", "Bob")
	cancelled := f.add(t, &offered, "cancel", "Alice", "")
	s, e := f.validate(cancelled, "")
	if e != nil || s.CurrentHolder != "Alice" || s.PendingTo != "" {
		t.Fatalf("%+v %v", s, e)
	}
	tests := []struct {
		previous          *CustodyLedger
		action, actor, to string
	}{
		{nil, "transfer", "Alice", "Bob"}, {nil, "register", "Alice", "Bob"},
		{&registered, "register", "Alice", ""}, {&registered, "accept", "Bob", ""},
		{&registered, "transfer", "Bob", "Carol"}, {&registered, "transfer", "Alice", "Alice"},
		{&registered, "transfer", "Alice", ""}, {&registered, "note", "Bob", ""},
		{&registered, "note", "Alice", "Bob"}, {&registered, "unknown", "Alice", ""},
		{&offered, "accept", "Carol", ""}, {&offered, "cancel", "Bob", ""},
		{&offered, "transfer", "Alice", "Carol"}, {&offered, "note", "Alice", ""},
	}
	for _, tc := range tests {
		_, e := AddCustody(f.p, tc.previous, CustodyRequest{Action: tc.action, Actor: tc.actor, To: tc.to, Location: "Lab", Note: "Reason"}, f.keys[tc.actor], f.trust, "")
		if e == nil {
			t.Fatalf("accepted %+v", tc)
		}
	}
}
func TestCustodyTrustAndExpectedHead(t *testing.T) {
	f := custodyFixture(t)
	l := f.add(t, nil, "register", "Alice", "")
	full := f.add(t, &l, "transfer", "Alice", "Bob")
	if _, e := f.validate(l, full.Events[1].Hash); e == nil {
		t.Fatal("rollback accepted against external head")
	}
	if _, e := f.validate(l, "garbage"); e == nil {
		t.Fatal("invalid head accepted")
	}
	// Without an independently retained head a valid prefix is indistinguishable.
	if _, e := f.validate(l, ""); e != nil {
		t.Fatal(e)
	}
	wrong := f.trust
	wrong.Keys = append([]CustodyIdentity{}, wrong.Keys...)
	wrong.Keys[0].Actor = "Mallory"
	if _, e := ValidateCustody(l, f.p.ManifestSHA256, f.p.Manifest.ID, f.p.Manifest.Case, wrong, ""); e == nil {
		t.Fatal("actor substitution accepted")
	}
	if _, e := ValidateCustody(l, f.p.ManifestSHA256, f.p.Manifest.ID, f.p.Manifest.Case, CustodyTrust{}, ""); e == nil {
		t.Fatal("missing trust accepted")
	}
	req := CustodyRequest{Action: "register", Actor: "Alice", Location: "Lab", Note: "Reason"}
	if _, e := AddCustody(f.p, nil, req, f.keys["Bob"], f.trust, ""); e == nil {
		t.Fatal("wrong signing identity")
	}
	if _, e := AddCustody(f.p, nil, req, f.keys["Alice"], f.trust, l.Events[0].Hash); e == nil {
		t.Fatal("orphan head")
	}
	if _, e := AddCustody(f.p, &l, CustodyRequest{Action: "note", Actor: "Alice", Location: "Lab", Note: "Reason"}, f.keys["Alice"], f.trust, full.Events[1].Hash); e == nil {
		t.Fatal("append from unexpected head")
	}
}
func TestCustodyTamperAndBinding(t *testing.T) {
	f := custodyFixture(t)
	l := f.add(t, nil, "register", "Alice", "")
	l = f.add(t, &l, "transfer", "Alice", "Bob")
	cases := map[string]func(*CustodyLedger){
		"case":      func(c *CustodyLedger) { c.Case = "Other" },
		"evidence":  func(c *CustodyLedger) { c.EvidenceID = "Other" },
		"digest":    func(c *CustodyLedger) { c.EvidenceDigest = strings.Repeat("0", 64) },
		"order":     func(c *CustodyLedger) { c.Events[0], c.Events[1] = c.Events[1], c.Events[0] },
		"missing":   func(c *CustodyLedger) { c.Events = c.Events[1:] },
		"repeat":    func(c *CustodyLedger) { c.Events = append(c.Events, c.Events[1]) },
		"signature": func(c *CustodyLedger) { c.Events[0].Signature = strings.Repeat("0", 128) },
		"base64":    func(c *CustodyLedger) { c.Events[0].Payload += "!" },
		"hash":      func(c *CustodyLedger) { c.Events[0].Hash = strings.Repeat("0", 64) },
		"rehashed-note": func(c *CustodyLedger) {
			b, _ := base64.StdEncoding.DecodeString(c.Events[0].Payload)
			b = bytes.Replace(b, []byte("Synthetic"), []byte("Fabricated"), 1)
			c.Events[0].Payload = base64.StdEncoding.EncodeToString(b)
			pub, _ := hex.DecodeString(c.Events[0].PublicKey)
			sig, _ := hex.DecodeString(c.Events[0].Signature)
			c.Events[0].Hash = custodyHead(pub, sig, b)
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			c := cloneCustody(l)
			change(&c)
			if _, e := f.validate(c, ""); e == nil {
				t.Fatal("tamper accepted")
			}
		})
	}
	for name, change := range map[string]func(*CustodyClaim){
		"actor":          func(c *CustodyClaim) { c.Actor = "Bob" },
		"from":           func(c *CustodyClaim) { c.From = "Bob" },
		"sequence":       func(c *CustodyClaim) { c.Sequence = 3 },
		"binding":        func(c *CustodyClaim) { c.Case = "Other" },
		"future":         func(c *CustodyClaim) { c.OccurredAt = c.RecordedAt.Add(time.Hour) },
		"empty-location": func(c *CustodyClaim) { c.Location = " " },
		"previous":       func(c *CustodyClaim) { c.Previous = "wrong" },
	} {
		t.Run(name, func(t *testing.T) {
			c := cloneCustody(l)
			resignCustody(t, &c, 1, f.keys["Alice"], change)
			if _, e := f.validate(c, ""); e == nil {
				t.Fatal("signed invalid declaration accepted")
			}
		})
	}
}
func TestCustodyTimeLimitsAndKeyConsistency(t *testing.T) {
	f := custodyFixture(t)
	l := f.add(t, nil, "register", "Alice", "")
	r := CustodyRequest{Action: "note", Actor: "Alice", Location: "Lab", Note: "Reason", OccurredAt: time.Now().Add(time.Hour)}
	if _, e := AddCustody(f.p, &l, r, f.keys["Alice"], f.trust, ""); e == nil {
		t.Fatal("future timestamp")
	}
	r.OccurredAt = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	if _, e := AddCustody(f.p, &l, r, f.keys["Alice"], f.trust, ""); e == nil {
		t.Fatal("time inversion")
	}
	r.OccurredAt = time.Time{}
	r.Note = strings.Repeat("a", 16001)
	if _, e := AddCustody(f.p, &l, r, f.keys["Alice"], f.trust, ""); e == nil {
		t.Fatal("unbounded note")
	}
	r.Note = "Reason"
	b, _ := os.ReadFile(f.keys["Alice"])
	key, _ := hex.DecodeString(strings.TrimSpace(string(b)))
	key[63] ^= 1
	bad := filepath.Join(f.dir, "bad-key")
	os.WriteFile(bad, []byte(hex.EncodeToString(key)), 0600)
	if _, e := AddCustody(f.p, &l, r, bad, f.trust, ""); e == nil {
		t.Fatal("inconsistent key")
	}
}
func TestCustodyJSONAndTrustLoading(t *testing.T) {
	f := custodyFixture(t)
	l := f.add(t, nil, "register", "Alice", "")
	path := filepath.Join(f.dir, "ledger.json")
	if e := WriteNew(path, JSON(l)); e != nil {
		t.Fatal(e)
	}
	if _, e := LoadCustody(path); e != nil {
		t.Fatal(e)
	}
	trust := filepath.Join(f.dir, "trust.json")
	if e := WriteNew(trust, JSON(f.trust)); e != nil {
		t.Fatal(e)
	}
	if _, e := LoadCustodyTrust(trust); e != nil {
		t.Fatal(e)
	}
	if _, e := LoadCustodyTrust(""); e == nil {
		t.Fatal("missing trust path")
	}
	for _, raw := range []string{`{"schema":"x","schema":"y"}`, `{"Schema":"x"}`, `{"schema":"x","extra":1}`, `{} {}`, `{"events":[{"hash":"a","hash":"b"}]}`, strings.Repeat("[", 34) + "0" + strings.Repeat("]", 34)} {
		var l CustodyLedger
		if e := custodyJSON([]byte(raw), &l); e == nil {
			t.Fatal("ambiguous JSON accepted", raw)
		}
	}
	duplicate := f.trust
	duplicate.Keys = append(append([]CustodyIdentity{}, f.trust.Keys...), f.trust.Keys[0])
	if _, e := custodyTrustMap(duplicate); e == nil {
		t.Fatal("duplicate key")
	}
}
func TestCustodyReportEscapesNotes(t *testing.T) {
	f := custodyFixture(t)
	req := CustodyRequest{Action: "register", Actor: "Alice", Location: "=SUM(A1)", Note: "<script>alert(7)</script>"}
	l, e := AddCustody(f.p, nil, req, f.keys["Alice"], f.trust, "")
	if e != nil {
		t.Fatal(e)
	}
	a := Analyze(f.p, nil)
	if e = ApplyCustody(&a, l, f.trust, l.Events[0].Hash); e != nil {
		t.Fatal(e)
	}
	out := filepath.Join(f.dir, "report")
	if e = Export(a, out); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(filepath.Join(out, "report.html"))
	if bytes.Contains(b, []byte("<script>alert(7)</script>")) || !bytes.Contains(b, []byte("&lt;script&gt;")) {
		t.Fatal("HTML escaping")
	}
	b, _ = os.ReadFile(filepath.Join(out, "custody.csv"))
	if !bytes.Contains(b, []byte("'=SUM(A1)")) {
		t.Fatal("CSV formula escaping")
	}
	loaded, e := LoadAnalysis(filepath.Join(out, "analysis.json"))
	if e != nil || loaded.Custody == nil {
		t.Fatal(e)
	}
}
