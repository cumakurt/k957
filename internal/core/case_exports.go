package core

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/csv"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// These additive tables retain the legacy export projection independently of
// the million-row examination limit. Older case-index readers ignore them.
// SQLite sorts timestamps on disk; no second in-memory inventory is retained.
type caseExportWriter struct {
	inventory *sql.Stmt
	boundary  *sql.Stmt
}

func newCaseExports(ctx context.Context, tx *sql.Tx) (*caseExportWriter, error) {
	for _, query := range []string{
		"CREATE TABLE case_inventory (id INTEGER PRIMARY KEY, host TEXT NOT NULL, collection TEXT NOT NULL, evidence TEXT NOT NULL, source TEXT NOT NULL, size INTEGER NOT NULL, sha256 TEXT NOT NULL, media_type TEXT NOT NULL, mismatch INTEGER NOT NULL, seconds INTEGER, nanos INTEGER)",
		"CREATE TABLE case_boundary (id INTEGER PRIMARY KEY, seconds INTEGER NOT NULL, nanos INTEGER NOT NULL, event_type TEXT NOT NULL, host TEXT NOT NULL, collection TEXT NOT NULL, source TEXT NOT NULL)",
	} {
		if _, err := tx.ExecContext(ctx, query); err != nil {
			return nil, err
		}
	}
	inventory, err := tx.PrepareContext(ctx, "INSERT INTO case_inventory(host,collection,evidence,source,size,sha256,media_type,mismatch,seconds,nanos) VALUES(?,?,?,?,?,?,?,?,?,?)")
	if err != nil {
		return nil, err
	}
	boundary, err := tx.PrepareContext(ctx, "INSERT INTO case_boundary(seconds,nanos,event_type,host,collection,source) VALUES(?,?,?,?,?,?)")
	if err != nil {
		inventory.Close()
		return nil, err
	}
	return &caseExportWriter{inventory: inventory, boundary: boundary}, nil
}

func (w *caseExportWriter) close() error {
	first := w.inventory.Close()
	if err := w.boundary.Close(); first == nil {
		first = err
	}
	return first
}

func (w *caseExportWriter) add(ctx context.Context, host, collection string, it Item, id FileIdentity) error {
	var seconds, nanos any
	if !it.Modified.IsZero() {
		seconds, nanos = it.Modified.Unix(), it.Modified.Nanosecond()
	}
	_, err := w.inventory.ExecContext(ctx, host, collection, it.ID, it.Source, it.Size, strings.ToLower(it.SHA256), id.MediaType, id.ExtensionMismatch, seconds, nanos)
	return err
}

func (w *caseExportWriter) boundaries(ctx context.Context, events []CaseEvent) error {
	// The caller's chronological/type order preserves the previous stable CSV
	// tie policy: inventory first, followed by sorted acquisition boundaries.
	for _, ev := range events {
		if _, err := w.boundary.ExecContext(ctx, ev.Time.Unix(), ev.Time.Nanosecond(), ev.Type, ev.Host, ev.Collection, ev.Source); err != nil {
			return err
		}
	}
	return nil
}

func exportLegacyCase(ctx context.Context, indexPath, dir string) error {
	db, err := openCaseIndex(ctx, indexPath)
	if err != nil {
		return err
	}
	defer db.Close()
	if err = exportLegacyInventory(ctx, db, filepath.Join(dir, "inventory.csv")); err != nil {
		return err
	}
	if err = exportLegacyTimeline(ctx, db, filepath.Join(dir, "timeline.csv")); err != nil {
		return err
	}
	return exportLegacyBodyfile(ctx, db, filepath.Join(dir, "bodyfile.txt"))
}

func exportLegacyInventory(ctx context.Context, db *sql.DB, path string) error {
	rows, err := db.QueryContext(ctx, "SELECT host,collection,evidence,source,size,sha256,media_type,mismatch FROM case_inventory ORDER BY id")
	if err != nil {
		return err
	}
	defer rows.Close()
	return writeCSVNew(path, func(w *csv.Writer) error {
		if err := w.Write([]string{"host", "collection", "evidence_id", "source", "size", "sha256", "media_type", "extension_mismatch"}); err != nil {
			return err
		}
		for rows.Next() {
			var host, collection, evidence, source, sum, media string
			var size int64
			var mismatch bool
			if err := rows.Scan(&host, &collection, &evidence, &source, &size, &sum, &media, &mismatch); err != nil {
				return err
			}
			if err := writeSafeCSVRow(w, []string{host, collection, evidence, source, strconv.FormatInt(size, 10), sum, media, strconv.FormatBool(mismatch)}); err != nil {
				return err
			}
		}
		return rows.Err()
	})
}

func exportLegacyTimeline(ctx context.Context, db *sql.DB, path string) error {
	rows, err := db.QueryContext(ctx, `SELECT seconds,nanos,event_type,host,collection,evidence,source FROM (
SELECT seconds,nanos,'file_modified' AS event_type,host,collection,evidence,source,0 AS category,id FROM case_inventory WHERE seconds IS NOT NULL
UNION ALL SELECT seconds,nanos,event_type,host,collection,'' AS evidence,source,1 AS category,id FROM case_boundary
) ORDER BY seconds,nanos,category,id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	return writeCSVNew(path, func(w *csv.Writer) error {
		if err := w.Write([]string{"time_utc", "event_type", "host", "collection", "evidence_id", "source"}); err != nil {
			return err
		}
		for rows.Next() {
			var seconds int64
			var nanos int
			var kind, host, collection, evidence, source string
			if err := rows.Scan(&seconds, &nanos, &kind, &host, &collection, &evidence, &source); err != nil {
				return err
			}
			if err := writeSafeCSVRow(w, []string{time.Unix(seconds, int64(nanos)).UTC().Format(time.RFC3339Nano), kind, host, collection, evidence, source}); err != nil {
				return err
			}
		}
		return rows.Err()
	})
}

func exportLegacyBodyfile(ctx context.Context, db *sql.DB, path string) error {
	rows, err := db.QueryContext(ctx, "SELECT host,source,size,seconds,nanos FROM case_inventory ORDER BY id")
	if err != nil {
		return err
	}
	defer rows.Close()
	return writeFileNew(path, func(output io.Writer) error {
		w := bufio.NewWriter(output)
		for rows.Next() {
			var host, source string
			var size int64
			var seconds, nanos sql.NullInt64
			if err := rows.Scan(&host, &source, &size, &seconds, &nanos); err != nil {
				return err
			}
			var modified time.Time
			if seconds.Valid && nanos.Valid {
				modified = time.Unix(seconds.Int64, nanos.Int64).UTC()
			}
			if err := writeBodyfileRow(w, bodyfileRow{Name: host + "/" + source, Size: size, Modified: modified}); err != nil {
				return err
			}
		}
		if err := rows.Err(); err != nil {
			return err
		}
		return w.Flush()
	})
}

func writeSafeCSVRow(w *csv.Writer, row []string) error {
	for i := range row {
		row[i] = csvSafe(row[i])
	}
	return w.Write(row)
}
