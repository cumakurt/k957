package core

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

func resumePreflightInventory(ctx context.Context, o Options, root, work string, r *PreflightResult) (s WorkState, err error) {
	if err = regularDirectory(work); err != nil {
		return s, err
	}
	if err = regularDirectory(filepath.Join(work, "chunks")); err != nil {
		return s, err
	}
	c, err := newWorkCrypto(o.EncryptionKey)
	if err != nil {
		return s, err
	}
	if err = readWork(work, &s, c); err != nil {
		return s, err
	}
	add := func(code, message string) {
		r.Checks = append(r.Checks, PreflightCheck{code, "blocked", message})
	}
	if s.Root != root || s.MaxFile != o.MaxFile || s.MaxTotal != o.MaxTotal || s.MaxFiles != o.MaxFiles ||
		(o.Case != "" && s.Manifest.Case != o.Case) || (o.Operator != "" && s.Manifest.Operator != o.Operator) || (o.Scope != "" && s.Manifest.Scope != o.Scope) {
		add("RESUME_OPTIONS_MISMATCH", "Source, limits or supplied case/operator/scope differ from the original acquisition")
		return s, nil
	}
	if _, e := os.Lstat(filepath.Join(work, "active.lock")); e == nil {
		add("WORK_LOCK_PRESENT", "Work is locked; confirm no collector is running before manually recovering a stale lock")
	} else if !os.IsNotExist(e) {
		add("WORK_LOCK_UNAVAILABLE", e.Error())
	}
	if len(s.Manifest.Epochs) >= 1000 {
		add("EPOCH_LIMIT_REACHED", "No further acquisition epoch can be appended")
	}
	for _, wf := range s.Files {
		if err = ctx.Err(); err != nil {
			return s, err
		}
		for _, part := range wf.Item.Parts {
			if err = ctx.Err(); err != nil {
				return s, err
			}
			path := filepath.Join(work, "chunks", c.name(part.SHA256))
			st, e := os.Lstat(path)
			size := part.Size
			if c != nil {
				size += stageOverhead
			}
			if e != nil || !st.Mode().IsRegular() || st.Size() != size {
				add("SAVED_CHUNK_UNAVAILABLE", fmt.Sprintf("%s part at byte %d: saved chunk is missing, inaccessible, non-regular or the wrong size", wf.Item.ID, part.Offset))
			}
		}
		if wf.Complete {
			continue
		}
		// As in acquireFile, reject replaced symlinks and metadata changes.
		// Full source-prefix equality is checked only during actual resume.
		path, e := filepath.EvalSymlinks(wf.Item.Source)
		if e != nil || path != wf.Item.Source {
			add("RESUME_SOURCE_CHANGED", wf.Item.ID+": incomplete source is missing, inaccessible or resolves to a different path")
			continue
		}
		st, e := os.Lstat(path)
		if e != nil || !st.Mode().IsRegular() || st.Size() != wf.ExpectedSize || !st.ModTime().Equal(wf.Item.Modified) {
			add("RESUME_SOURCE_CHANGED", wf.Item.ID+": incomplete source type, size or modification time differs from the checkpoint")
		}
	}
	return s, nil
}
