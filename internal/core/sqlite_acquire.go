package core

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"time"

	"modernc.org/sqlite"
)

type SQLiteBackupRequest struct {
	Schema string `json:"schema"`
	Source string `json:"source"`
}
type SQLiteBackupReceipt struct {
	Schema   string         `json:"schema"`
	Source   string         `json:"source"`
	Started  time.Time      `json:"started"`
	Finished time.Time      `json:"finished"`
	SHA256   string         `json:"sha256"`
	Bytes    int64          `json:"bytes"`
	Pages    int            `json:"pages"`
	Security WorkerSecurity `json:"security"`
	Notes    []string       `json:"notes"`
}

const sqliteBackupSchema = "k957-sqlite-logical-backup/1"

func RunSQLiteBackupWorker(input io.Reader, output io.Writer) error {
	debug.SetMemoryLimit(256 << 20)
	body, e := io.ReadAll(io.LimitReader(input, 1<<20+1))
	if e != nil || len(body) > 1<<20 {
		return errors.New("SQLite backup request exceeds bounds")
	}
	var req SQLiteBackupRequest
	if e = custodyJSON(body, &req); e != nil {
		return e
	}
	if req.Schema != sqliteBackupSchema || !filepath.IsAbs(req.Source) {
		return errors.New("invalid SQLite backup request")
	}
	info, e := os.Lstat(req.Source)
	if e != nil {
		return e
	}
	if !info.Mode().IsRegular() || info.Size() > workerInputLimit {
		return errors.New("SQLite source is not a bounded regular file")
	}
	security, e := restrictParserWorker()
	if e != nil {
		return e
	}
	security.MemoryLimit = 256 << 20
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	start := time.Now().UTC()
	pages, e := sqliteOnlineBackup(ctx, req.Source, "snapshot.sqlite")
	if e != nil {
		return e
	}
	info, e = os.Stat("snapshot.sqlite")
	if e != nil {
		return e
	}
	if info.Size() > workerInputLimit {
		return errors.New("SQLite backup output exceeds 128 MiB")
	}
	sum, e := fileSHA256Progress("snapshot.sqlite", "", 0, &verifyMeter{ctx: ctx})
	if e != nil {
		return e
	}
	receipt := SQLiteBackupReceipt{Schema: sqliteBackupSchema, Source: req.Source, Started: start, Finished: time.Now().UTC(), SHA256: sum, Bytes: info.Size(), Pages: pages, Security: security, Notes: []string{"This is a SQLite online logical backup of committed state, not the original main/WAL bytes or a filesystem snapshot.", "The read-only connection can use SQLite shared-memory/locking facilities on the live source. No application table writes are issued.", "Run ordinary collection separately when original database and sidecar bytes are required."}}
	return json.NewEncoder(output).Encode(receipt)
}

func sqliteOnlineBackup(ctx context.Context, source, dest string) (pages int, err error) {
	abs, e := filepath.Abs(source)
	if e != nil {
		return 0, e
	}
	u := sqliteFileURL(abs)
	db, e := sql.Open("sqlite", u.String()+"?mode=ro&_defensive=true&_pragma=trusted_schema%3DOFF&_pragma=busy_timeout%3D1000")
	if e != nil {
		return 0, e
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	var count, size int64
	if e = db.QueryRowContext(ctx, "PRAGMA page_count").Scan(&count); e != nil {
		return 0, e
	}
	if e = db.QueryRowContext(ctx, "PRAGMA page_size").Scan(&size); e != nil {
		return 0, e
	}
	if count <= 0 || size <= 0 || size > 65536 || count > workerInputLimit/size {
		return 0, errors.New("SQLite page count exceeds backup bounds")
	}
	f, e := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return 0, e
	}
	if e = f.Close(); e != nil {
		return 0, e
	}
	conn, e := db.Conn(ctx)
	if e != nil {
		return 0, e
	}
	defer conn.Close()
	err = conn.Raw(func(raw any) error {
		provider, ok := raw.(interface {
			NewBackup(string) (*sqlite.Backup, error)
		})
		if !ok {
			return errors.New("SQLite driver does not expose online backup")
		}
		dst, e := filepath.Abs(dest)
		if e != nil {
			return e
		}
		du := sqliteFileURL(dst)
		backup, e := provider.NewBackup(du.String() + "?mode=rw&_defensive=true")
		if e != nil {
			return e
		}
		finished := false
		defer func() {
			if !finished {
				backup.Finish()
			}
		}()
		for {
			if e = ctx.Err(); e != nil {
				return e
			}
			more, e := backup.Step(128)
			if e != nil {
				return e
			}
			pages = backup.PageCount()
			if int64(pages) > workerInputLimit/size {
				return errors.New("SQLite database grew beyond backup bounds")
			}
			if !more {
				finished = true
				return backup.Finish()
			}
		}
	})
	return pages, err
}

func AcquireSQLite(ctx context.Context, source, executable string, opts Options) (Manifest, error) {
	var empty Manifest
	abs, e := filepath.Abs(source)
	if e != nil {
		return empty, e
	}
	info, e := os.Lstat(abs)
	if e != nil {
		return empty, e
	}
	if !info.Mode().IsRegular() || info.Size() > workerInputLimit {
		return empty, errors.New("SQLite source must be a regular file up to 128 MiB")
	}
	dir, e := os.MkdirTemp("", "k957-sqlite-acquire-")
	if e != nil {
		return empty, e
	}
	defer os.RemoveAll(dir)
	job, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(job, executable, "sqlite-backup-worker")
	configureToolProcess(cmd)
	cmd.WaitDelay = 2 * time.Second
	cmd.Dir = dir
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "SYSTEMROOT=" + os.Getenv("SYSTEMROOT"), "TMPDIR=" + dir, "TEMP=" + dir, "TMP=" + dir, "GOMAXPROCS=1", "GOMEMLIMIT=256MiB"}
	cmd.Stdin = bytes.NewReader(JSON(SQLiteBackupRequest{Schema: sqliteBackupSchema, Source: abs}))
	stdout, stderr := &boundedWorkerOutput{cancel: cancel}, &boundedWorkerOutput{cancel: cancel}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if e = runToolCommand(cmd); e != nil {
		return empty, fmt.Errorf("SQLite logical backup failed: %w: %s", e, stderr.String())
	}
	var receipt SQLiteBackupReceipt
	if e = custodyJSON(stdout.Bytes(), &receipt); e != nil {
		return empty, e
	}
	if receipt.Schema != sqliteBackupSchema || receipt.Source != abs || !validHash(receipt.SHA256) || receipt.Bytes < 0 || receipt.Bytes > workerInputLimit {
		return empty, errors.New("invalid SQLite backup receipt")
	}
	sum, e := fileSHA256Progress(filepath.Join(dir, "snapshot.sqlite"), "", 0, &verifyMeter{ctx: ctx})
	if e != nil {
		return empty, e
	}
	if sum != receipt.SHA256 {
		return empty, errors.New("SQLite snapshot changed after worker completion")
	}
	if e = WriteJSONNew(filepath.Join(dir, "provenance.json"), receipt); e != nil {
		return empty, e
	}
	opts.Root = dir
	opts.Paths = nil
	opts.System = false
	opts.Acquisition = &AcquisitionGuarantees{Method: "sqlite-online-backup", Origin: "logical_backup", SQLiteTransactionConsistent: true, Notes: receipt.Notes}
	if opts.MaxFile == 0 {
		opts.MaxFile = workerInputLimit
	}
	if opts.MaxTotal == 0 {
		opts.MaxTotal = workerInputLimit + 1<<20
	}
	if opts.MaxFiles == 0 {
		opts.MaxFiles = 2
	}
	return Collect(ctx, opts)
}
