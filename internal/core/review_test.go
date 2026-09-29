package core

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func reviewFixture(t *testing.T) (string, Analysis) {
	t.Helper()
	d, o := fixture(t, false)
	if _, e := Collect(context.Background(), o); e != nil {
		t.Fatal(e)
	}
	p, e := Open(o.Out, "")
	if e != nil {
		t.Fatal(e)
	}
	defer p.Zip.Close()
	return d, Analyze(p, []Rule{{ID: "R", Contains: "powershell"}})
}
func TestReviewStableIDsAndHistory(t *testing.T) {
	d, a := reviewFixture(t)
	if len(a.Findings) != 1 {
		t.Fatal(a)
	}
	id := a.Findings[0].ID
	l, e := AddReview(a, nil, id, "needs-review", "Alice", "Inspect source", "", "")
	if e != nil {
		t.Fatal(e)
	}
	l2, e := AddReview(a, &l, id, "rejected", "Bob", "Benign test text", "", "")
	if e != nil {
		t.Fatal(e)
	}
	if len(l.Events) != 1 || len(l2.Events) != 2 {
		t.Fatal("mutated old history")
	}
	if e = ApplyReviews(&a, l2, ""); e != nil {
		t.Fatal(e)
	}
	if a.Findings[0].Review != "rejected" || len(a.ReviewHistory) != 2 {
		t.Fatal(a)
	}
	if e = Export(a, filepath.Join(d, "reviewed")); e != nil {
		t.Fatal(e)
	}
	loaded, e := LoadAnalysis(filepath.Join(d, "reviewed", "analysis.json"))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = ValidateLedger(l2, loaded, ""); e != nil {
		t.Fatal("review state changed basis", e)
	}
}
func TestReviewSignatureAndTamper(t *testing.T) {
	d, a := reviewFixture(t)
	Keygen(filepath.Join(d, "key"))
	Keygen(filepath.Join(d, "other"))
	l, e := AddReview(a, nil, a.Findings[0].ID, "confirmed", "Alice", "Manually checked", filepath.Join(d, "key.key"), "")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = ValidateLedger(l, a, filepath.Join(d, "key.pub")); e != nil {
		t.Fatal(e)
	}
	if _, e = ValidateLedger(l, a, filepath.Join(d, "other.pub")); e == nil {
		t.Fatal("wrong key accepted")
	}
	if _, e = AddReview(a, &l, a.Findings[0].ID, "rejected", "Alice", "Changed assessment", "", ""); e == nil {
		t.Fatal("silent signature downgrade")
	}
	l2, e := AddReview(a, &l, a.Findings[0].ID, "needs-review", "Bob", "Further review", filepath.Join(d, "other.key"), filepath.Join(d, "key.pub"))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = ValidateLedger(l2, a, filepath.Join(d, "other.pub")); e != nil {
		t.Fatal(e)
	}
	l.Events[0].Note = "changed"
	if _, e = ValidateLedger(l, a, ""); e == nil {
		t.Fatal("broken chain accepted")
	}
	l.Events[0].Hash = eventHash(l.Basis, l.Events[0])
	if _, e = ValidateLedger(l, a, filepath.Join(d, "key.pub")); e == nil {
		t.Fatal("forged chain accepted with trusted signature")
	}
}
func TestReviewBasisMismatch(t *testing.T) {
	_, a := reviewFixture(t)
	l, e := AddReview(a, nil, a.Findings[0].ID, "confirmed", "Alice", "Reason", "", "")
	if e != nil {
		t.Fatal(e)
	}
	a.Rules[0].Contains = "different"
	if e = ApplyReviews(&a, l, ""); e == nil {
		t.Fatal("different rules accepted")
	}
	_, b := reviewFixture(t)
	if e = ApplyReviews(&b, l, ""); e == nil {
		t.Fatal("different evidence accepted")
	}
}
func TestReviewValidationAndEscaping(t *testing.T) {
	d, a := reviewFixture(t)
	for _, decision := range []string{"", "approved", "malware"} {
		if _, e := AddReview(a, nil, a.Findings[0].ID, decision, "Alice", "Reason", "", ""); e == nil {
			t.Fatal("bad decision")
		}
	}
	if _, e := AddReview(a, nil, "unknown", "confirmed", "Alice", "Reason", "", ""); e == nil {
		t.Fatal("unknown finding")
	}
	if _, e := AddReview(a, nil, a.Findings[0].ID, "confirmed", "Alice", " ", "", ""); e == nil {
		t.Fatal("empty reason")
	}
	l, e := AddReview(a, nil, a.Findings[0].ID, "rejected", "=SUM(A1)", "<script>alert(99)</script>", "", "")
	if e != nil {
		t.Fatal(e)
	}
	ApplyReviews(&a, l, "")
	out := filepath.Join(d, "report")
	Export(a, out)
	html, _ := os.ReadFile(filepath.Join(out, "report.html"))
	if strings.Contains(string(html), "<script>alert(99)</script>") {
		t.Fatal("injection")
	}
	csv, _ := os.ReadFile(filepath.Join(out, "findings.csv"))
	if !strings.Contains(string(csv), "'=SUM(A1)") {
		t.Fatal("CSV formula")
	}
	if _, e = ValidateLedger(l, a, filepath.Join(d, "unused")); e == nil {
		t.Fatal("unsigned trusted")
	}
}
func TestReviewReanalysisStable(t *testing.T) {
	_, o := fixture(t, false)
	Collect(context.Background(), o)
	p, e := Open(o.Out, "")
	if e != nil {
		t.Fatal(e)
	}
	defer p.Zip.Close()
	rules := []Rule{{ID: "R", Contains: "powershell"}}
	a := Analyze(p, rules)
	b := Analyze(p, rules)
	if a.Run == b.Run || a.Findings[0].ID != b.Findings[0].ID || reviewBasis(a) != reviewBasis(b) {
		t.Fatal("unstable IDs/basis")
	}
}
