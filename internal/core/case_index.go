package core

import (
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const CaseIndexSchema = "k957-case-index/1"
const caseIndexLimit = 1000000

// CaseRow keeps evidence IDs scoped by the signed collection digest. Payload
// holds the original event/finding projection, never source file contents.
type CaseRow struct {
	ID         int64           `json:"id"`
	Kind       string          `json:"kind"`
	Collection string          `json:"collection"`
	Digest     string          `json:"collection_digest"`
	Host       string          `json:"host"`
	Evidence   string          `json:"evidence"`
	Source     string          `json:"source"`
	Time       *time.Time      `json:"time,omitempty"`
	Payload    json.RawMessage `json:"payload"`
}

type CaseQuery struct {
	NativeParser, NativeRecord, USNFileID string
	Kind, Host, Evidence, Digest, Text    string
	After, Before                         *time.Time
	Limit, Offset                         int
}

type CasePage struct {
	Schema string    `json:"schema"`
	Rows   []CaseRow `json:"rows"`
	Offset int       `json:"offset"`
	Limit  int       `json:"limit"`
	More   bool      `json:"more"`
}

type caseIndexWriter struct {
	db                                         *sql.DB
	tx                                         *sql.Tx
	stmt                                       *sql.Stmt
	count, eligible, events, findings, reviews int64
	limited                                    bool
}

func newCaseIndex(ctx context.Context, path string) (*caseIndexWriter, error) {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return nil, e
	}
	if e = f.Close(); e != nil {
		return nil, e
	}
	abs, e := filepath.Abs(path)
	if e != nil {
		return nil, e
	}
	u := sqliteFileURL(abs)
	db, e := sql.Open("sqlite", u.String()+"?mode=rw&_defensive=true")
	if e != nil {
		return nil, e
	}
	db.SetMaxOpenConns(1)
	good := false
	defer func() {
		if !good {
			db.Close()
		}
	}()
	for _, query := range []string{
		"PRAGMA trusted_schema=OFF", "PRAGMA journal_mode=DELETE", "PRAGMA synchronous=FULL", "PRAGMA cache_size=-8192", "PRAGMA temp_store=FILE", "PRAGMA max_page_count=524288",
		"CREATE TABLE metadata (schema TEXT NOT NULL)",
		"CREATE TABLE entries (id INTEGER PRIMARY KEY, kind TEXT NOT NULL, collection TEXT NOT NULL, digest TEXT NOT NULL, host TEXT NOT NULL, evidence TEXT NOT NULL, source TEXT NOT NULL, seconds INTEGER, nanos INTEGER, payload TEXT NOT NULL, search TEXT NOT NULL)",
		"CREATE INDEX entry_time ON entries(seconds,nanos,id)",
		"CREATE INDEX entry_scope ON entries(digest,evidence,kind,id)",
		"CREATE INDEX entry_host_kind ON entries(host,kind,id)",
	} {
		if _, e = db.ExecContext(ctx, query); e != nil {
			return nil, e
		}
	}
	if _, e = db.ExecContext(ctx, "INSERT INTO metadata(schema) VALUES(?)", CaseIndexSchema); e != nil {
		return nil, e
	}
	// Own rollback synchronously. database/sql otherwise starts an asynchronous
	// rollback on cancellation, which can retain the SQLite handle while the
	// caller removes partial output on Windows. Statements still use ctx.
	if e = ctx.Err(); e != nil {
		return nil, e
	}
	tx, e := db.BeginTx(context.WithoutCancel(ctx), nil)
	if e != nil {
		return nil, e
	}
	stmt, e := tx.PrepareContext(ctx, "INSERT INTO entries(kind,collection,digest,host,evidence,source,seconds,nanos,payload,search) VALUES(?,?,?,?,?,?,?,?,?,?)")
	if e != nil {
		tx.Rollback()
		return nil, e
	}
	good = true
	return &caseIndexWriter{db: db, tx: tx, stmt: stmt}, nil
}

func (w *caseIndexWriter) close() { w.stmt.Close(); w.tx.Rollback(); w.db.Close() }

func (w *caseIndexWriter) add(ctx context.Context, row CaseRow, searchable string) error {
	w.eligible++
	if w.count >= caseIndexLimit {
		w.limited = true
		return nil
	}
	if len(row.Payload) > 256<<10 {
		return errors.New("case row exceeds 256 KiB")
	}
	if !json.Valid(row.Payload) {
		return errors.New("case row payload is not valid JSON")
	}
	var seconds, nanos any
	if row.Time != nil {
		seconds = row.Time.Unix()
		nanos = row.Time.Nanosecond()
	}
	if _, e := w.stmt.ExecContext(ctx, row.Kind, row.Collection, row.Digest, row.Host, row.Evidence, row.Source, seconds, nanos, string(row.Payload), strings.ToLower(searchable)); e != nil {
		return e
	}
	w.count++
	switch row.Kind {
	case "event":
		w.events++
	case "finding":
		w.findings++
	case "review":
		w.reviews++
	}
	return nil
}

func (w *caseIndexWriter) finish() error {
	if e := w.stmt.Close(); e != nil {
		return e
	}
	if e := w.tx.Commit(); e != nil {
		return e
	}
	return w.db.Close()
}

func openCaseIndex(ctx context.Context, path string) (*sql.DB, error) {
	info, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !info.Mode().IsRegular() || info.Size() > 2<<30 {
		return nil, errors.New("case index must be a regular file up to 2 GiB")
	}
	abs, e := filepath.Abs(path)
	if e != nil {
		return nil, e
	}
	u := sqliteFileURL(abs)
	db, e := sql.Open("sqlite", u.String()+"?mode=ro&_defensive=true")
	if e != nil {
		return nil, e
	}
	db.SetMaxOpenConns(1)
	good := false
	defer func() {
		if !good {
			db.Close()
		}
	}()
	for _, pragma := range []string{"PRAGMA trusted_schema=OFF", "PRAGMA query_only=ON", "PRAGMA cache_size=-4096"} {
		if _, e = db.ExecContext(ctx, pragma); e != nil {
			return nil, e
		}
	}
	var schema string
	if e = db.QueryRowContext(ctx, "SELECT schema FROM metadata LIMIT 1").Scan(&schema); e != nil {
		return nil, e
	}
	if schema != CaseIndexSchema {
		return nil, errors.New("unsupported case index")
	}
	good = true
	return db, nil
}

func caseQuerySQL(q CaseQuery) (string, []any, error) {
	if len(q.NativeParser) > 64 || len(q.NativeRecord) > 256 {
		return "", nil, errors.New("native reference search exceeds bounds")
	}
	if q.USNFileID != "" {
		if len(q.USNFileID) != 16 && len(q.USNFileID) != 32 {
			return "", nil, errors.New("USN file ID requires 16 or 32 little-endian hex characters")
		}
		if _, err := hex.DecodeString(q.USNFileID); err != nil {
			return "", nil, errors.New("invalid USN file ID hex")
		}
	}
	hasNativeFilter := q.NativeParser != "" || q.NativeRecord != "" || q.USNFileID != ""
	if hasNativeFilter && q.Kind != "" && q.Kind != "event" {
		return "", nil, errors.New("native reference filters require event rows")
	}
	if q.Limit < 1 || q.Limit > 200 || q.Offset < 0 || q.Offset > caseIndexLimit || len(q.Text) > 256 || len(q.Host) > 256 || len(q.Evidence) > 256 {
		return "", nil, errors.New("invalid case search bounds")
	}
	if q.Kind != "" && q.Kind != "event" && q.Kind != "finding" && q.Kind != "inventory" && q.Kind != "review" && q.Kind != "activity" && q.Kind != "memory_observation" && q.Kind != "indicator_match" && q.Kind != "boundary" {
		return "", nil, errors.New("invalid case row kind")
	}
	if q.Digest != "" && !validHash(q.Digest) {
		return "", nil, errors.New("invalid collection digest")
	}
	where := []string{"1=1"}
	args := []any{}
	if hasNativeFilter {
		where = append(where, "kind='event'")
	}
	// Fixed JSON paths and bound values support existing derived indexes without
	// changing their schema or accepting user-provided SQL/JSON expressions.
	for _, pair := range [][2]string{{"$.native.parser", q.NativeParser}, {"$.native.record", q.NativeRecord}, {"$.usn.file_id_le_hex", strings.ToLower(q.USNFileID)}} {
		if pair[1] != "" {
			where = append(where, "json_type(payload,'"+pair[0]+"')='text' AND json_extract(payload,'"+pair[0]+"')=?")
			args = append(args, pair[1])
		}
	}
	for _, pair := range [][2]string{{"kind", q.Kind}, {"host", q.Host}, {"evidence", q.Evidence}, {"digest", q.Digest}} {
		if pair[1] != "" {
			where = append(where, pair[0]+"=?")
			args = append(args, pair[1])
		}
	}
	// Literal substring search is deliberate: no user-controlled SQL or FTS
	// expression is evaluated. '%' and '_' have no special meaning.
	if q.Text != "" {
		where = append(where, "instr(search,?)>0")
		args = append(args, strings.ToLower(q.Text))
	}
	if q.After != nil {
		where = append(where, "(seconds>? OR (seconds=? AND nanos>=?))")
		args = append(args, q.After.Unix(), q.After.Unix(), q.After.Nanosecond())
	}
	if q.Before != nil {
		where = append(where, "(seconds<? OR (seconds=? AND nanos<=?))")
		args = append(args, q.Before.Unix(), q.Before.Unix(), q.Before.Nanosecond())
	}
	if q.After != nil && q.Before != nil && q.After.After(*q.Before) {
		return "", nil, errors.New("after exceeds before")
	}
	args = append(args, q.Limit+1, q.Offset)
	return "SELECT id,kind,collection,digest,host,evidence,source,seconds,nanos,payload FROM entries WHERE " + strings.Join(where, " AND ") + " ORDER BY seconds,nanos,id LIMIT ? OFFSET ?", args, nil
}

func QueryCase(ctx context.Context, path string, q CaseQuery) (CasePage, error) {
	page := CasePage{Schema: CaseIndexSchema, Rows: []CaseRow{}, Limit: q.Limit, Offset: q.Offset}
	query, args, e := caseQuerySQL(q)
	if e != nil {
		return page, e
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	db, e := openCaseIndex(ctx, path)
	if e != nil {
		return page, e
	}
	defer db.Close()
	rows, e := db.QueryContext(ctx, query, args...)
	if e != nil {
		return page, e
	}
	defer rows.Close()
	for rows.Next() {
		if len(page.Rows) >= q.Limit {
			page.More = true
			break
		}
		var row CaseRow
		var sec, nano sql.NullInt64
		var payload string
		if e = rows.Scan(&row.ID, &row.Kind, &row.Collection, &row.Digest, &row.Host, &row.Evidence, &row.Source, &sec, &nano, &payload); e != nil {
			return page, e
		}
		if len(payload) > 256<<10 || !json.Valid([]byte(payload)) {
			return page, errors.New("invalid case row payload")
		}
		row.Payload = json.RawMessage(payload)
		if sec.Valid && nano.Valid {
			stamp := time.Unix(sec.Int64, nano.Int64).UTC()
			row.Time = &stamp
		}
		page.Rows = append(page.Rows, row)
	}
	return page, rows.Err()
}

func exportCaseIndex(ctx context.Context, path, dest string) error {
	db, e := openCaseIndex(ctx, path)
	if e != nil {
		return e
	}
	defer db.Close()
	rows, e := db.QueryContext(ctx, "SELECT kind,collection,digest,host,evidence,source,seconds,nanos,payload FROM entries WHERE kind IN ('event','finding','review','activity','memory_observation','indicator_match','boundary') ORDER BY seconds,nanos,id")
	if e != nil {
		return e
	}
	defer rows.Close()
	return writeCSVNew(dest, func(w *csv.Writer) error {
		if err := w.Write([]string{"kind", "collection", "collection_digest", "host", "evidence_id", "source", "time_utc", "payload_json"}); err != nil {
			return err
		}
		for rows.Next() {
			var kind, collection, digest, host, evidence, source, payload string
			var sec, nano sql.NullInt64
			if err := rows.Scan(&kind, &collection, &digest, &host, &evidence, &source, &sec, &nano, &payload); err != nil {
				return err
			}
			stamp := ""
			if sec.Valid && nano.Valid {
				stamp = time.Unix(sec.Int64, nano.Int64).UTC().Format(time.RFC3339Nano)
			}
			if err := writeSafeCSVRow(w, []string{kind, collection, digest, host, evidence, source, stamp, payload}); err != nil {
				return err
			}
		}
		return rows.Err()
	})
}

func (w *caseIndexWriter) analysis(ctx context.Context, a Analysis, dir, host string) error {
	for _, ev := range a.Timeline {
		stamp := ev.Time
		if e := w.add(ctx, CaseRow{Kind: "event", Collection: dir, Digest: a.EvidenceDigest, Host: host, Evidence: ev.Evidence, Source: ev.Source, Time: &stamp, Payload: JSON(ev)}, caseEventSearchText(ev)); e != nil {
			return e
		}
	}
	for _, activity := range a.Activities {
		var stamp *time.Time
		if !activity.Time.IsZero() {
			t := activity.Time
			stamp = &t
		}
		if e := w.add(ctx, CaseRow{Kind: "activity", Collection: dir, Digest: a.EvidenceDigest, Host: host, Evidence: activity.Evidence, Source: activity.Source, Time: stamp, Payload: JSON(activity)}, activity.Action+" "+activity.User+" "+activity.Target+" "+activity.Detail); e != nil {
			return e
		}
	}
	for _, memory := range a.Memories {
		for _, observation := range memory.Observations {
			if e := w.add(ctx, CaseRow{Kind: "memory_observation", Collection: dir, Digest: a.EvidenceDigest, Host: host, Evidence: memory.Evidence, Source: memory.Source, Payload: JSON(observation)}, observation.Kind+" "+observation.Detail); e != nil {
				return e
			}
		}
	}
	for _, f := range a.Findings {
		if e := w.add(ctx, CaseRow{Kind: "finding", Collection: dir, Digest: a.EvidenceDigest, Host: host, Evidence: f.Evidence, Source: f.Source, Payload: JSON(f)}, f.Rule+" "+f.Description+" "+f.Excerpt+" "+f.Source); e != nil {
			return e
		}
	}
	if a.Indicators != nil {
		for _, m := range a.Indicators.Matches {
			var stamp *time.Time
			if m.Event != nil && !m.Event.Time.IsZero() {
				t := m.Event.Time
				stamp = &t
			}
			if e := w.add(ctx, CaseRow{Kind: "indicator_match", Collection: dir, Digest: a.EvidenceDigest, Host: host, Evidence: m.Evidence, Source: m.Source, Time: stamp, Payload: JSON(m)}, m.Indicator+" "+m.Kind+" "+m.Value+" "+m.Source); e != nil {
				return e
			}
		}
	}
	for _, review := range a.ReviewHistory {
		stamp := review.Created
		if e := w.add(ctx, CaseRow{Kind: "review", Collection: dir, Digest: a.EvidenceDigest, Host: host, Time: &stamp, Payload: JSON(review)}, review.Finding+" "+review.Decision+" "+review.Analyst+" "+review.Note); e != nil {
			return e
		}
	}
	return nil
}

func caseInventoryRow(dir, digest, host string, it Item) CaseRow {
	return CaseRow{Kind: "inventory", Collection: dir, Digest: digest, Host: host, Evidence: it.ID, Source: it.Source, Payload: JSON(it)}
}

func caseIndexNote(w *caseIndexWriter) string {
	return fmt.Sprintf("case-index.sqlite contains %s scoped rows. It is derived and does not authenticate evidence. Search is a bounded literal substring scan; collection/evidence, host/kind and time filters have indexes.", strconv.FormatInt(w.count, 10))
}

func caseEventSearchText(ev Event) string {
	fields := []string{ev.Type, ev.Detail, ev.User, ev.SourceIP, ev.DestinationIP, ev.Source}
	if ev.Native != nil {
		fields = append(fields, ev.Native.Parser, ev.Native.Table, ev.Native.Record)
	}
	if ev.USN != nil {
		fields = append(fields, ev.USN.FileID, ev.USN.ParentID, ev.USN.USN)
	}
	return strings.Join(fields, " ")
}
