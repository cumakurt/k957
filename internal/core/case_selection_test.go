package core

import (
	"context"
	"path/filepath"
	"testing"
)

func TestSignedSelectionKeepsReferenceAndRejectsTamper(t *testing.T) {
	dir := assistantFixture(t)
	prefix := filepath.Join(t.TempDir(), "examiner")
	if err := Keygen(prefix); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "bookmark")
	r, err := ExportCaseSelection(context.Background(), dir, out, "Selected event", "Examiner", "Check source log", prefix+".key", CaseQuery{Kind: "event", Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Page.Rows) != 1 || r.Page.Rows[0].Evidence != "E1" || r.Page.Rows[0].ID != 1 {
		t.Fatal("bookmark lost locator", r)
	}
	if _, err = VerifyReport(context.Background(), out, prefix+".pub"); err != nil {
		t.Fatal(err)
	}
	if err = WriteNew(filepath.Join(out, "extra"), []byte("unexpected")); err != nil {
		t.Fatal(err)
	}
	if _, err = VerifyReport(context.Background(), out, prefix+".pub"); err == nil {
		t.Fatal("modified bookmark bundle accepted")
	}
}
