package core

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestCollectionExaminationKeepsVerifiedRecordAndSigner(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	source := filepath.Join(dir, "source")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "log"), []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	record, err := CollectFull(ctx, FullOptions{OutputDir: filepath.Join(dir, "store"), Root: source, Case: "ORIGINAL", Operator: "Test", Scope: "Synthetic", MaxFile: 1 << 20, MaxTotal: 1 << 20, MaxFiles: 10})
	if err != nil {
		t.Fatal(err)
	}
	v := verifyCollectionForExamination(ctx, record.Directory, "", nil)
	body, rec, err := verifiedCollectionSnapshot(v)
	if err != nil || rec.Case != "ORIGINAL" || len(body) == 0 {
		t.Fatal(v, rec, err)
	}
	changed := rec
	changed.Case = "UNSIGNED CHANGE"
	encoded, err := MarshalJSON(changed)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(rec.Directory, "collection.json"), encoded, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(rec.Directory, "signing.pub"), []byte("untrusted replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	snapshot, stable, err := verifiedCollectionSnapshot(v)
	if err != nil || stable.Case != "ORIGINAL" || string(snapshot) != string(body) {
		t.Fatal("verified metadata replaced", err)
	}
	p, err := openVerifiedCollectionPackage(ctx, rec.Directory, stable)
	if err != nil {
		t.Fatal("package consulted mutable signer path", err)
	}
	staging := p.stagingDirectory
	a := AnalyzeContext(ctx, p, nil)
	if a.Manifest.Case != "ORIGINAL" {
		t.Fatal("wrong package bound to collection")
	}
	if err = p.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(staging); !os.IsNotExist(err) {
		t.Fatal("private package copy retained", err)
	}
	if err = os.WriteFile(filepath.Join(rec.Directory, rec.Evidence), []byte("replaced"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = openVerifiedCollectionPackage(ctx, rec.Directory, stable); err == nil {
		t.Fatal("changed artifact accepted after collection verification")
	}
	if _, _, err = verifiedCollectionSnapshot(CollectionVerification{Status: "verified"}); err == nil {
		t.Fatal("unretained verification fabricated a snapshot")
	}
}
