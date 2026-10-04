package core

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

type CaseSelection struct {
	Schema      string            `json:"schema"`
	Created     time.Time         `json:"created"`
	IndexSHA256 string            `json:"index_sha256"`
	Title       string            `json:"title"`
	Analyst     string            `json:"analyst"`
	Note        string            `json:"note"`
	Query       map[string]string `json:"query"`
	Page        CasePage          `json:"page"`
	Coverage    Coverage          `json:"coverage"`
	Limits      []string          `json:"limits"`
}

func ExportCaseSelection(ctx context.Context, dir, out, title, analyst, note, key string, q CaseQuery) (result CaseSelection, err error) {
	if !custodyText(title, 256, false) || !custodyText(analyst, 256, false) || !custodyText(note, 4096, true) {
		return result, errors.New("selection bookmark requires title, analyst and reason")
	}
	path := filepath.Join(dir, "case-index.sqlite")
	before, err := fileSHA256Progress(path, "", 0, &verifyMeter{ctx: ctx})
	if err != nil {
		return result, err
	}
	page, err := QueryCase(ctx, path, q)
	if err != nil {
		return result, err
	}
	query := map[string]string{"kind": q.Kind, "host": q.Host, "digest": q.Digest, "evidence": q.Evidence, "text": q.Text, "limit": strconv.Itoa(q.Limit), "offset": strconv.Itoa(q.Offset)}
	for name, value := range map[string]string{"native-parser": q.NativeParser, "native-record": q.NativeRecord, "usn-file-id": q.USNFileID} {
		if value != "" {
			query[name] = value
		}
	}
	if q.After != nil {
		query["after"] = q.After.UTC().Format(time.RFC3339Nano)
	}
	if q.Before != nil {
		query["before"] = q.Before.UTC().Format(time.RFC3339Nano)
	}
	result = CaseSelection{Schema: "k957-case-selection/1", Created: time.Now().UTC(), IndexSHA256: before, Title: title, Analyst: analyst, Note: note, Query: query, Page: page, Coverage: coverage("case_selection", "rows", int64(len(page.Rows)), int64(len(page.Rows)), int64(q.Limit), !page.More && q.Offset == 0), Limits: []string{"This is an explicitly selected query page, not a full case export. Offset/more states make remaining matching rows unknown; the page retains every selected source payload and scoped evidence identifier.", "The bookmark and examiner note are separate derived records. They do not update signed evidence, findings or review decisions. Signature verification establishes the supplied signer's declaration, not correctness of the note."}}
	body, err := MarshalJSON(result)
	if err != nil {
		return result, err
	}
	if len(body) > 64<<20 {
		return result, errors.New("selection exceeds 64 MiB")
	}
	after, err := fileSHA256Progress(path, "", 0, &verifyMeter{ctx: ctx})
	if err != nil {
		return result, err
	}
	if after != before {
		return result, errors.New("case changed during selection export")
	}
	if err = os.Mkdir(out, 0700); err != nil {
		return result, err
	}
	complete := false
	defer func() {
		if !complete {
			os.RemoveAll(out)
		}
	}()
	if err = WriteNew(filepath.Join(out, "selection.json"), body); err != nil {
		return result, err
	}
	if err = exportSelectionDocuments(ctx, result, out); err != nil {
		return result, err
	}
	if _, err = SealReport(ctx, out, key); err != nil {
		return result, err
	}
	complete = true
	return result, nil
}
