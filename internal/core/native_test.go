package core

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSQLiteBrowserRecordIdentityAndReadOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "History")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{
		"CREATE TABLE urls(id INTEGER PRIMARY KEY,url TEXT,title TEXT,last_visit_time INTEGER)",
		"CREATE TABLE visits(id INTEGER PRIMARY KEY,url INTEGER,visit_time INTEGER)",
		"INSERT INTO urls VALUES(1,'https://example.test/path','Synthetic history',13348540800000000)",
		"INSERT INTO visits VALUES(7,1,13348540800000000)",
	} {
		if _, err = db.Exec(query); err != nil {
			db.Close()
			t.Fatal(err)
		}
	}
	db.Close()
	before, err := fileSHA256(path)
	if err != nil {
		t.Fatal(err)
	}
	events, summary, err := parseSQLite(context.Background(), path, Item{ID: "E1", Source: "History"}, 10)
	if err != nil || len(events) != 1 || summary.Parsed != 1 {
		t.Fatalf("%+v %v", summary, err)
	}
	if events[0].Native.Record != "7" || events[0].Native.Table != "visits" || events[0].Source != "History" || events[0].Time != time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC) {
		t.Fatalf("incorrect native reference/time: %+v", events[0])
	}
	after, err := fileSHA256(path)
	if err != nil || before != after {
		t.Fatal("SQLite parser changed original database")
	}
	_, summary, err = parseSQLite(context.Background(), path, Item{ID: "E1"}, 0)
	if err != nil || !summary.Limited || summary.Parsed != 0 {
		t.Fatalf("zero budget was ignored: %+v %v", summary, err)
	}
}

func TestSQLiteBrowserInvalidRowsStillDiscloseQueryLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "History")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{
		"CREATE TABLE urls(id INTEGER PRIMARY KEY,url TEXT,title TEXT,last_visit_time INTEGER)",
		"CREATE TABLE visits(id INTEGER PRIMARY KEY,url INTEGER,visit_time INTEGER)",
		"INSERT INTO urls VALUES(1,NULL,'invalid visit URL',13348540800000000)",
		"INSERT INTO visits VALUES(1,1,13348540800000000),(2,1,13348540800000000),(3,1,13348540800000000),(4,1,13348540800000000)",
	} {
		if _, err = db.Exec(query); err != nil {
			db.Close()
			t.Fatal(err)
		}
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	events, summary, err := parseSQLite(context.Background(), path, Item{ID: "E1", Source: "History"}, 2)
	if err != nil || len(events) != 0 || summary.Rows != 2 || summary.Skipped != 2 || !summary.Limited || summary.SkipReasons["event_limit"] != 1 {
		t.Fatalf("invalid records hid the bounded query's remaining rows: %+v %v", summary, err)
	}
	for _, row := range analysisCoverage(Analysis{ParseSummaries: []ParseSummary{summary}}) {
		if row.Format == "SQLite" && (row.TotalKnown || row.Status != "partial") {
			t.Fatal("bounded database scan presented as fully enumerated", row)
		}
	}
}

func TestEVTXReferenceAndCorruption(t *testing.T) {
	path := filepath.Join("testdata", "Security_1_record.evtx")
	events, summary, err := parseEVTX(context.Background(), path, Item{ID: "E1", Source: "Security.evtx"}, 10)
	if err != nil || len(events) != 1 || summary.Parsed != 1 {
		t.Fatalf("reference EVTX: %+v %v", summary, err)
	}
	if events[0].Windows.EventID != 1102 || events[0].Windows.RecordID != "33072" || events[0].Native.Record != "33072" || events[0].ByteOffset != 4608 {
		t.Fatalf("reference event identity: %s", JSON(events[0]))
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	body[4608] ^= 1
	bad := filepath.Join(t.TempDir(), "corrupt.evtx")
	if err = os.WriteFile(bad, body, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err = parseEVTX(context.Background(), bad, Item{ID: "E1"}, 10); err == nil {
		t.Fatal("corrupt EVTX checksum accepted")
	}
}
