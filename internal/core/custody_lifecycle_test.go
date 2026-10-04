package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCustodyHistoricalRevocationRotationAndAnchor(t *testing.T) {
	f := custodyFixture(t)
	first := f.add(t, nil, "register", "Alice", "")
	state, err := f.validate(first, "")
	if err != nil {
		t.Fatal(err)
	}
	stamp := state.Events[0].RecordedAt
	after := stamp.Add(time.Millisecond)
	f.trust.Lifecycle = []CustodyKeyPolicy{{PublicKey: f.trust.Keys[0].PublicKey, RevokedAt: &after, RevocationMode: "from_time", Reason: "rotation cutover"}}
	if _, err = f.validate(first, ""); err != nil {
		t.Fatal("valid history rejected", err)
	}
	f.trust.Lifecycle[0].RevokedAt = &stamp
	if _, err = f.validate(first, ""); err == nil {
		t.Fatal("revocation boundary accepted")
	}
	f.trust.Lifecycle[0].RevokedAt = &after
	f.trust.Lifecycle[0].RevocationMode = "all_history"
	if _, err = f.validate(first, ""); err == nil {
		t.Fatal("all-history revocation ignored")
	}
	f.trust.Lifecycle[0].RevocationMode = "from_time"
	prefix := filepath.Join(f.dir, "Alice-rotation")
	if err = Keygen(prefix); err != nil {
		t.Fatal(err)
	}
	pub, err := os.ReadFile(prefix + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	f.trust.Keys = append(f.trust.Keys, CustodyIdentity{Actor: "Alice", PublicKey: strings.TrimSpace(string(pub))})
	f.keys["Alice"] = prefix + ".key"
	second := f.add(t, &first, "note", "Alice", "")
	witness := filepath.Join(f.dir, "witness")
	if err = Keygen(witness); err != nil {
		t.Fatal(err)
	}
	a, err := AnchorCustody(second, f.trust, witness+".key", "Witness", "offline retained current head")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = VerifyCustodyAnchor(a, second, f.trust, witness+".pub"); err != nil {
		t.Fatal(err)
	}
	if _, err = VerifyCustodyAnchor(a, first, f.trust, witness+".pub"); err == nil {
		t.Fatal("rollback accepted by retained current anchor")
	}
	if _, err = VerifyCustodyAnchor(a, second, f.trust, prefix+".pub"); err == nil {
		t.Fatal("unknown witness accepted")
	}
	a.Payload = a.Payload[:len(a.Payload)-4] + "AAAA"
	if _, err = VerifyCustodyAnchor(a, second, f.trust, witness+".pub"); err == nil {
		t.Fatal("anchor tamper accepted")
	}
}
