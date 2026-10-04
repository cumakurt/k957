package core

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"strconv"
	"time"

	_ "modernc.org/sqlite"
)

type NativeRecord struct {
	Parser       string       `json:"parser"`
	Table        string       `json:"table"`
	Record       string       `json:"record"`
	TimeField    string       `json:"time_field,omitempty"`
	TimeEncoding string       `json:"time_encoding,omitempty"`
	OtherTimes   []NativeTime `json:"other_times,omitempty"`
}

type NativeTime struct {
	Field    string `json:"field"`
	Value    string `json:"value"`
	Encoding string `json:"encoding"`
}

type browserQuery struct {
	table, query, field, encoding string
}

func parseSQLite(ctx context.Context, path string, it Item, budget int) (events []Event, summary ParseSummary, err error) {
	summary = ParseSummary{Evidence: it.ID, Format: "SQLite", SkipReasons: map[string]int{}}
	events = []Event{}
	abs, err := filepath.Abs(path)
	if err != nil {
		return
	}
	u := sqliteFileURL(abs)
	q := u.Query()
	q.Set("mode", "ro")
	q.Set("_defensive", "true")
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	for _, pragma := range []string{"PRAGMA trusted_schema=OFF", "PRAGMA query_only=ON", "PRAGMA cache_size=-4096", "PRAGMA temp_store=MEMORY"} {
		if _, err = db.ExecContext(ctx, pragma); err != nil {
			return
		}
	}
	tables := map[string]bool{}
	rows, err := db.QueryContext(ctx, "SELECT name FROM sqlite_schema WHERE type='table' AND name IN ('visits','urls','moz_historyvisits','moz_places','history_visits','history_items') LIMIT 6")
	if err != nil {
		return
	}
	for rows.Next() {
		var name string
		if err = rows.Scan(&name); err != nil {
			rows.Close()
			return
		}
		tables[name] = true
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return
	}
	var queries []browserQuery
	if tables["visits"] && tables["urls"] {
		queries = append(queries, browserQuery{"visits", "SELECT CAST(v.id AS TEXT), v.visit_time, substr(u.url,1,4096), substr(u.title,1,4096) FROM visits v JOIN urls u ON u.id=v.url ORDER BY v.id LIMIT ?", "visit_time", "webkit_microseconds_1601"})
	} else if tables["urls"] {
		queries = append(queries, browserQuery{"urls", "SELECT CAST(id AS TEXT), last_visit_time, substr(url,1,4096), substr(title,1,4096) FROM urls ORDER BY id LIMIT ?", "last_visit_time", "webkit_microseconds_1601"})
	}
	if tables["moz_historyvisits"] && tables["moz_places"] {
		queries = append(queries, browserQuery{"moz_historyvisits", "SELECT CAST(v.id AS TEXT), v.visit_date, substr(p.url,1,4096), substr(p.title,1,4096) FROM moz_historyvisits v JOIN moz_places p ON p.id=v.place_id ORDER BY v.id LIMIT ?", "visit_date", "unix_microseconds"})
	} else if tables["moz_places"] {
		queries = append(queries, browserQuery{"moz_places", "SELECT CAST(id AS TEXT), last_visit_date, substr(url,1,4096), substr(title,1,4096) FROM moz_places ORDER BY id LIMIT ?", "last_visit_date", "unix_microseconds"})
	}
	if tables["history_visits"] && tables["history_items"] {
		queries = append(queries, browserQuery{"history_visits", "SELECT CAST(v.id AS TEXT), v.visit_time, substr(i.url,1,4096), substr(v.title,1,4096) FROM history_visits v JOIN history_items i ON i.id=v.history_item ORDER BY v.id LIMIT ?", "visit_time", "cocoa_seconds_2001"})
	}
	if len(queries) == 0 {
		summary.SkipReasons["unsupported_sqlite_schema"] = 1
		return events, summary, errors.New("SQLite schema is not a supported Chromium, Firefox or Safari history schema")
	}
	for _, query := range queries {
		remaining := max(budget-len(events), 0)
		rows, e := db.QueryContext(ctx, query.query, remaining+1)
		if e != nil {
			return events, summary, fmt.Errorf("browser history schema: %w", e)
		}
		seen := 0
		for rows.Next() {
			// The SQL limit bounds scanned rows, including invalid records.
			// Its lookahead row must disclose truncation even when none of the
			// preceding rows produced a valid event.
			if seen >= remaining {
				summary.Limited = true
				summary.SkipReasons["event_limit"]++
				break
			}
			seen++
			var record string
			var rawTime any
			var address, title sql.NullString
			if e = rows.Scan(&record, &rawTime, &address, &title); e != nil {
				rows.Close()
				return events, summary, e
			}
			summary.Rows++
			stamp, raw, e := browserTimestamp(rawTime, query.encoding)
			if e != nil || !address.Valid {
				summary.Skipped++
				summary.SkipReasons["invalid_browser_record"]++
				continue
			}
			detail := address.String
			if title.Valid && title.String != "" {
				detail += " | " + title.String
			}
			events = append(events, Event{Native: &NativeRecord{Parser: "SQLite", Table: query.table, Record: record, TimeField: query.field, TimeEncoding: query.encoding}, Time: stamp, OriginalTime: raw, Type: "browser_visit", Evidence: it.ID, Source: it.Source, Detail: detail})
			summary.Parsed++
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return events, summary, e
		}
	}
	return events, summary, nil
}

func browserTimestamp(value any, encoding string) (time.Time, string, error) {
	if encoding == "cocoa_seconds_2001" {
		var seconds float64
		switch v := value.(type) {
		case float64:
			seconds = v
		case int64:
			seconds = float64(v)
		default:
			return time.Time{}, "", errors.New("invalid Cocoa timestamp type")
		}
		if math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds < -978307200 || seconds > 253402300799-978307200 {
			return time.Time{}, "", errors.New("Cocoa timestamp outside supported range")
		}
		whole, fraction := math.Modf(seconds)
		return time.Unix(int64(whole)+978307200, int64(fraction*1e9)).UTC(), strconv.FormatFloat(seconds, 'g', -1, 64), nil
	}
	micros, ok := value.(int64)
	if !ok || micros <= 0 {
		return time.Time{}, "", errors.New("invalid microsecond timestamp")
	}
	raw := strconv.FormatInt(micros, 10)
	seconds := micros / 1000000
	if encoding == "webkit_microseconds_1601" {
		seconds -= 11644473600
	}
	stamp := time.Unix(seconds, micros%1000000*1000).UTC()
	if stamp.Year() < 1601 || stamp.Year() > 9999 {
		return time.Time{}, raw, errors.New("timestamp outside supported range")
	}
	return stamp, raw, nil
}
