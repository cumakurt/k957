package core

import (
	"context"
	"errors"
	"os"
	"path/filepath"
)

type collectionSnapshotKey struct{}

func verifyCollectionForExamination(ctx context.Context, dir, trusted string, meter *verifyMeter) CollectionVerification {
	if ctx == nil {
		ctx = context.Background()
	}
	// Ordinary batch verification does not retain all manifests in memory.
	return verifyCollectionProgress(context.WithValue(ctx, collectionSnapshotKey{}, true), dir, trusted, meter)
}

func verifiedCollectionSnapshot(v CollectionVerification) ([]byte, CollectionRecord, error) {
	if v.Status != "verified" || v.verifiedRecord == nil || len(v.verifiedRecordBytes) == 0 {
		return nil, CollectionRecord{}, errors.New("verified collection record snapshot required")
	}
	return v.verifiedRecordBytes, *v.verifiedRecord, nil
}

// A case/store examination must bind to the already verified collection's
// artifact bytes and signer, rather than reopening mutable record/key paths.
func openVerifiedCollectionPackage(ctx context.Context, dir string, rec CollectionRecord) (p *Package, err error) {
	var expected string
	for _, artifact := range rec.Artifacts {
		if artifact.Name == rec.Evidence {
			expected = artifact.SHA256
		}
	}
	if !collectionFileName(rec.Evidence) || !validHash(expected) {
		return nil, errors.New("signed collection lacks a valid evidence artifact binding")
	}
	staging, err := os.MkdirTemp("", "k957-collection-examination-")
	if err != nil {
		return nil, err
	}
	complete := false
	defer func() {
		if !complete {
			os.RemoveAll(staging)
		}
	}()
	path := filepath.Join(staging, "evidence.k957")
	if _, _, err = stageRawImage(ctx, filepath.Join(dir, rec.Evidence), path, expected, 1<<40); err != nil {
		return nil, err
	}
	key := filepath.Join(staging, "signing.pub")
	if err = WriteNew(key, []byte(rec.PublicKey)); err != nil {
		return nil, err
	}
	p, err = OpenContext(ctx, path, key)
	if err != nil {
		return nil, err
	}
	p.stagingDirectory = staging
	complete = true
	return p, nil
}
