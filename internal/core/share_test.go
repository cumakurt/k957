package core

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSharedReportEnglishPresentation(t *testing.T) {
	a, _ := sharedFixture(t)
	s, err := BuildSharedReport(a, SharePolicy{Schema: sharePolicySchema})
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "shared")
	if err = ExportShared(s, out); err != nil {
		t.Fatal(err)
	}
	html, err := os.ReadFile(filepath.Join(out, "report.html"))
	if err != nil {
		t.Fatal(err)
	}
	for _, label := range []string{`<html lang="en">`, "Masked sharing report", "Evidence inventory", "Examiner decisions", "Masked custody history summary", "Limitations", "Search the sharing report"} {
		if !strings.Contains(string(html), label) {
			t.Errorf("missing English presentation label %q", label)
		}
	}
	if len(s.Notes) != 5 || !strings.HasPrefix(s.Notes[0], "This is a masked derived report") {
		t.Fatalf("unexpected sharing limitations: %v", s.Notes)
	}
}

func sharedFixture(t *testing.T) (Analysis, []string) {
	t.Helper()
	_, a := reviewFixture(t)
	source := "/PRIVATE_PATH_X/UserPrivateX/PRIVATE_HOST_X/192.0.2.99/access.csv"
	stamp := time.Date(2001, 2, 3, 4, 5, 6, 0, time.UTC)
	a.Manifest.Case = "PRIVATE_CASE_X"
	a.Manifest.ID = "PRIVATE_PACKAGE_X"
	a.Manifest.Host = "PRIVATE_HOST_X"
	a.Manifest.Operator = "ActorPrivateX"
	a.Manifest.Scope = "PRIVATE_SCOPE_X"
	a.Manifest.OS = "PRIVATE_OS_X"
	a.Manifest.Arch = "PRIVATE_ARCH_X"
	a.Manifest.Started = stamp
	a.Manifest.Finished = stamp
	a.Manifest.Items[0].ID = "PRIVATE_ITEM_ID_X"
	a.Manifest.Items[0].Source = source
	a.Manifest.Items[0].SHA256 = strings.Repeat("a", 64)
	a.Manifest.Items[0].Modified = stamp
	a.Manifest.Items[0].Collected = stamp
	a.Manifest.Items[0].Object = "PRIVATE_OBJECT_X"
	a.Manifest.Items[0].Mode = "PRIVATE_MODE_X"
	a.Manifest.Issues = []Issue{{"PRIVATE_ISSUE_PATH_X", "PRIVATE_ERROR_X"}}
	a.Run = "PRIVATE_RUN_X"
	a.EvidenceDigest = strings.Repeat("b", 64)
	a.ReviewDigest = strings.Repeat("c", 64)
	a.Signature = "PRIVATE_SIGNATURE_X"
	a.ReviewSignature = "PRIVATE_REVIEW_SIGNATURE_X"
	a.Rules = []Rule{{ID: "PRIVATE_RULE_X", Description: "PRIVATE_DESCRIPTION_X", Contains: "PRIVATE_RULE_TEXT_X"}}
	a.Findings = []Finding{{ID: "PRIVATE_FINDING_X", Rule: "PRIVATE_RULE_X", Description: "PRIVATE_DESCRIPTION_X", Evidence: "PRIVATE_ITEM_ID_X", Source: source, Line: 4, Excerpt: "PRIVATE_EXCERPT_X", Review: "confirmed", Reviewer: "ActorPrivateX", ReviewNote: "PRIVATE_REVIEW_NOTE_X"}}
	a.Timeline = []Event{{Time: stamp, Type: "log_timestamp", Evidence: "PRIVATE_ITEM_ID_X", Source: source, Line: 4, ByteOffset: 17, User: "UserPrivateX", Host: "PRIVATE_HOST_X", SourceIP: "192.0.2.99", DestinationIP: "2001:db8::99", Detail: "PRIVATE_DETAIL_X", OriginalTime: "PRIVATE_ORIGINAL_TIME_X"}}
	a.Correlations = []Correlation{{Kind: "user", Value: "UserPrivateX", Events: 2, Sources: 2, First: stamp, Last: stamp, References: []Reference{{Evidence: "PRIVATE_ITEM_ID_X", Source: source, Line: 4, Role: "user", Time: stamp}}}}
	a.ReviewHistory = []ReviewEvent{{Sequence: 1, Finding: "PRIVATE_FINDING_X", Decision: "confirmed", Analyst: "ActorPrivateX", Note: "PRIVATE_REVIEW_NOTE_X", Created: stamp, Previous: "PRIVATE_REVIEW_PREV_X", Hash: "PRIVATE_REVIEW_HASH_X"}}
	a.ParseSummaries = []ParseSummary{{Evidence: "PRIVATE_ITEM_ID_X", Format: "CSV", Rows: 2, Parsed: 1, Skipped: 1, Error: "PRIVATE_PARSE_ERROR_X"}}
	a.Custody = &CustodyStatus{EvidenceDigest: a.EvidenceDigest, Head: strings.Repeat("d", 64), TrustDigest: strings.Repeat("e", 64), CurrentHolder: "ActorPrivateX", PendingTo: "ReceiverPrivateX", Trust: "PRIVATE_TRUST_TEXT_X", Events: []CustodyClaim{{Case: a.Manifest.Case, EvidenceID: a.Manifest.ID, EvidenceDigest: a.EvidenceDigest, Sequence: 1, Action: "transfer", Actor: "ActorPrivateX", From: "ActorPrivateX", To: "ReceiverPrivateX", Location: "PRIVATE_LOCATION_X", Note: "PRIVATE_CUSTODY_NOTE_X", OccurredAt: stamp, RecordedAt: stamp, Previous: "PRIVATE_CUSTODY_PREV_X", Signer: "PRIVATE_SIGNER_X"}}}
	a.Notes = []string{"PRIVATE_ANALYSIS_NOTE_X"}
	private := []string{"PRIVATE_", "UserPrivateX", "ActorPrivateX", "ReceiverPrivateX", "192.0.2.99", "2001:db8::99", "2001-02-03", strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), strings.Repeat("d", 64), strings.Repeat("e", 64)}
	return a, private
}
func TestShareDefaultNoSensitiveValuesOrSourceMutation(t *testing.T) {
	a, private := sharedFixture(t)
	before := JSON(a)
	policy, e := LoadSharePolicy("")
	if e != nil {
		t.Fatal(e)
	}
	s, e := BuildSharedReport(a, policy)
	if e != nil {
		t.Fatal(e)
	}
	if len(s.Items) != 1 || len(s.Findings) != 1 || s.SourceIssueCount != 1 || s.SourceNoteCount != 1 || s.Items[0].Size != a.Manifest.Items[0].Size {
		t.Fatal("lost counts")
	}
	if s.Items[0].ID != "E000001" || s.Findings[0].ID != "F000001" || s.Findings[0].Rule != "R0001" || s.Reviews[0].Finding != s.Findings[0].ID {
		t.Fatal("alias links")
	}
	if s.Items[0].Source != s.Timeline[0].Source || s.Timeline[0].User != s.Correlations[0].Value || s.Operator != s.Custody[0].Actor || s.Custody[0].To != s.PendingTo {
		t.Fatal("inconsistent aliases")
	}
	if s.Timeline[0].Time != nil || s.Custody[0].RecordedAt != nil {
		t.Fatal("source times leaked")
	}
	out := filepath.Join(t.TempDir(), "shared")
	if e = ExportShared(s, out); e != nil {
		t.Fatal(e)
	}
	entries, e := os.ReadDir(out)
	if e != nil {
		t.Fatal(e)
	}
	if len(entries) != 10 {
		t.Fatalf("unexpected files: %d", len(entries))
	}
	for _, f := range entries {
		b, e := os.ReadFile(filepath.Join(out, f.Name()))
		if e != nil {
			t.Fatal(e)
		}
		for _, secret := range private {
			if bytes.Contains(b, []byte(secret)) {
				t.Fatalf("secret %q in %s", secret, f.Name())
			}
		}
	}
	if _, e = LoadAnalysis(filepath.Join(out, "shared.json")); e == nil {
		t.Fatal("shared projection accepted as authoritative analysis")
	}
	if !bytes.Equal(before, JSON(a)) {
		t.Fatal("source analysis mutated")
	}
}
func TestShareSelectiveKeepAndCrossFieldRedaction(t *testing.T) {
	a, _ := sharedFixture(t)
	p := SharePolicy{Schema: sharePolicySchema, Keep: []string{"paths", "users", "timestamps"}, Literals: []string{"PRIVATE_PATH_X"}}
	s, e := BuildSharedReport(a, p)
	if e != nil {
		t.Fatal(e)
	}
	if s.Timeline[0].User != "UserPrivateX" || s.Timeline[0].Time == nil || !s.Timeline[0].Time.Equal(a.Timeline[0].Time) {
		t.Fatal("explicit keep ignored")
	}
	source := s.Items[0].Source
	if strings.Contains(source, "PRIVATE_HOST_X") || strings.Contains(source, "192.0.2.99") || strings.Contains(source, "PRIVATE_PATH_X") {
		t.Fatal("sensitive value leaked through retained path", source)
	}
	if !strings.Contains(source, "UserPrivateX") || !strings.Contains(source, "[MASKED]") {
		t.Fatal(source)
	}
	if s.Case == a.Manifest.Case || s.CurrentHolder == a.Custody.CurrentHolder {
		t.Fatal("unselected categories retained")
	}
	if len(s.Policy.Keep) != 3 || s.Policy.LiteralCount != 1 {
		t.Fatal("policy summary")
	}
	// An explicitly retained user is still masked if also a protected actor.
	a.Manifest.Operator = "UserPrivateX"
	s, e = BuildSharedReport(a, p)
	if e != nil || s.Timeline[0].User != "[MASKED]" {
		t.Fatalf("overlapping categories: %s %v", s.Timeline[0].User, e)
	}
}
func TestShareLiteralLongestAndEscaping(t *testing.T) {
	a, _ := sharedFixture(t)
	a.Manifest.Items[0].Source = "/AcmeLong/[secret]/plain"
	p := SharePolicy{Schema: sharePolicySchema, Keep: []string{"paths"}, Literals: []string{"Acme", "AcmeLong", "[secret]"}}
	s, e := BuildSharedReport(a, p)
	if e != nil {
		t.Fatal(e)
	}
	if s.Items[0].Source != "/[MASKED]/[MASKED]/plain" {
		t.Fatal(s.Items[0].Source)
	}
	a.Timeline[0].User = "<script>alert(9)</script>"
	a.Timeline[0].Host = "=SUM(A1)"
	s, e = BuildSharedReport(a, SharePolicy{Schema: sharePolicySchema, Keep: []string{"users", "hosts"}})
	if e != nil {
		t.Fatal(e)
	}
	out := filepath.Join(t.TempDir(), "share")
	if e = ExportShared(s, out); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(filepath.Join(out, "report.html"))
	if bytes.Contains(b, []byte("<script>alert(9)</script>")) || !bytes.Contains(b, []byte("&lt;script&gt;")) {
		t.Fatal("HTML injection")
	}
	b, _ = os.ReadFile(filepath.Join(out, "timeline.csv"))
	if !bytes.Contains(b, []byte("'=SUM(A1)")) {
		t.Fatal("CSV formula")
	}
}
func TestSharePolicyAndExportFailures(t *testing.T) {
	a, _ := sharedFixture(t)
	for _, p := range []SharePolicy{{}, {Schema: sharePolicySchema, Keep: []string{"unknown"}}, {Schema: sharePolicySchema, Keep: []string{"users", "users"}}, {Schema: sharePolicySchema, Literals: []string{" "}}, {Schema: sharePolicySchema, Literals: []string{strings.Repeat("a", 513)}}} {
		if _, e := BuildSharedReport(a, p); e == nil {
			t.Fatal("invalid policy accepted")
		}
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	for _, raw := range []string{`{"schema":"k957-share-policy/1","keep":[],"keep":["paths"]}`, `{"schema":"k957-share-policy/1","include_text":true}`, `{"Schema":"k957-share-policy/1"}`, `{} {}`} {
		os.WriteFile(path, []byte(raw), 0600)
		if _, e := LoadSharePolicy(path); e == nil {
			t.Fatal("invalid JSON policy accepted")
		}
	}
	os.WriteFile(path, []byte(`{"schema":"k957-share-policy/1","keep":["timestamps"]}`), 0600)
	p, e := LoadSharePolicy(path)
	if e != nil {
		t.Fatal(e)
	}
	s, e := BuildSharedReport(a, p)
	if e != nil {
		t.Fatal(e)
	}
	sentinel := filepath.Join(dir, "sentinel")
	os.WriteFile(sentinel, []byte("preserve"), 0600)
	if e = ExportShared(s, dir); e == nil {
		t.Fatal("existing output overwritten")
	}
	b, _ := os.ReadFile(sentinel)
	if string(b) != "preserve" {
		t.Fatal("modified existing directory")
	}
	s.Schema = "wrong"
	out := filepath.Join(dir, "invalid")
	if e = ExportShared(s, out); e == nil {
		t.Fatal("invalid report accepted")
	}
	if _, e = os.Stat(out); !os.IsNotExist(e) {
		t.Fatal("failed schema created output")
	}
	a.Version = "old"
	if _, e = BuildSharedReport(a, p); e == nil {
		t.Fatal("old analysis accepted")
	}
}
func TestShareMatchingBudgetAndEnumProjection(t *testing.T) {
	a, _ := sharedFixture(t)
	a.Timeline[0].Host = strings.Repeat("x", (1<<20)+1)
	if _, e := BuildSharedReport(a, SharePolicy{Schema: sharePolicySchema, Keep: []string{"paths"}}); e == nil {
		t.Fatal("unbounded matching accepted")
	}
	a.Manifest.Items[0].Kind = "PRIVATE_UNKNOWN_X"
	a.Timeline[0].Type = "PRIVATE_UNKNOWN_X"
	a.Correlations[0].References[0].Role = "PRIVATE_UNKNOWN_X"
	a.Findings[0].Review = "PRIVATE_UNKNOWN_X"
	a.ParseSummaries[0].Format = "PRIVATE_UNKNOWN_X"
	s, e := BuildSharedReport(a, SharePolicy{Schema: sharePolicySchema})
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(JSON(s), []byte("PRIVATE_")) {
		t.Fatal("unknown enum copied")
	}
}
