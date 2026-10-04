package core

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"
)

const WorkerSchema = "k957-parser-worker/1"
const workerInputLimit = 128 << 20
const workerOutputLimit = 32 << 20

type WorkerSecurity struct {
	ProcessIsolation bool   `json:"process_isolation"`
	NetworkBlocked   bool   `json:"network_blocked"`
	CPULimit         bool   `json:"cpu_limit"`
	MemoryLimit      int64  `json:"go_memory_target_bytes"`
	Filesystem       string `json:"filesystem"`
}

type WorkerRequest struct {
	Schema string `json:"schema"`
	Format string `json:"format"`
	File   string `json:"file"`
	Item   Item   `json:"item"`
	Budget int    `json:"budget"`
}

type WorkerResult struct {
	Schema   string         `json:"schema"`
	Security WorkerSecurity `json:"security"`
	Summary  ParseSummary   `json:"summary"`
	Events   []Event        `json:"events"`
	Error    string         `json:"error,omitempty"`
}

type ParserInput struct {
	Evidence string `json:"evidence"`
	Source   string `json:"source"`
	SHA256   string `json:"sha256"`
	Role     string `json:"role"`
}

type ParserRun struct {
	Evidence string         `json:"evidence"`
	Format   string         `json:"format"`
	Inputs   []ParserInput  `json:"inputs,omitempty"`
	Security WorkerSecurity `json:"security"`
	Error    string         `json:"error,omitempty"`
}

type workerContextKey struct{}

// WithParserWorkers enables native parsers in a separate invocation of the
// current CLI. Library callers must explicitly select a worker executable.
func WithParserWorkers(ctx context.Context, executable string) context.Context {
	return context.WithValue(ctx, workerContextKey{}, executable)
}

func RunParserWorker(input io.Reader, output io.Writer) error {
	debug.SetMemoryLimit(256 << 20)
	b, e := io.ReadAll(io.LimitReader(input, 1<<20+1))
	if e != nil || len(b) > 1<<20 {
		return errors.New("worker request exceeds bounds")
	}
	var req WorkerRequest
	if e = custodyJSON(b, &req); e != nil {
		return e
	}
	if req.Schema != WorkerSchema || req.File != "evidence.bin" || req.Budget < 0 || req.Budget > analysisEventLimit || req.Item.Size < 0 || req.Item.Size > workerInputLimit {
		return errors.New("invalid worker request")
	}
	security, e := restrictParserWorker()
	if e != nil {
		return fmt.Errorf("worker restrictions: %w", e)
	}
	security.MemoryLimit = 256 << 20
	result := WorkerResult{Schema: WorkerSchema, Security: security, Events: []Event{}}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	switch req.Format {
	case "USN":
		result.Events, result.Summary, e = parseUSN(ctx, req.File, req.Item, req.Budget)
	case "SQLite":
		result.Events, result.Summary, e = parseSQLite(ctx, req.File, req.Item, req.Budget)
	case "Registry":
		result.Events, result.Summary, e = parseRegistry(ctx, req.File, req.Item, req.Budget)
	case "BinaryPlist":
		result.Events, result.Summary, e = parseBinaryLaunchd(ctx, req.File, req.Item, req.Budget)
	case "EVTX":
		result.Events, result.Summary, e = parseEVTX(ctx, req.File, req.Item, req.Budget)
	default:
		return errors.New("unsupported worker format")
	}
	if e != nil {
		result.Error = e.Error()
		result.Summary.Error = e.Error()
	}
	return json.NewEncoder(output).Encode(result)
}

func nativeFormat(id FileIdentity) string {
	switch id.MediaType {
	case "application/x-windows-usn-journal":
		return "USN"
	case "application/vnd.sqlite3":
		return "SQLite"
	case "application/x-windows-registry":
		return "Registry"
	case "application/x-apple-binary-plist":
		return "BinaryPlist"
	case "application/x-ms-evtx":
		return "EVTX"
	}
	return ""
}

func stageWorkerObject(ctx context.Context, f *zip.File, item Item, path string) error {
	if f == nil || item.Size > workerInputLimit {
		return errors.New("worker input is absent or exceeds bounds")
	}
	r, e := f.Open()
	if e != nil {
		return e
	}
	defer r.Close()
	out, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	h := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(out, h), io.LimitReader(&contextReader{ctx: ctx, r: r}, item.Size+1))
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if n != item.Size || hex.EncodeToString(h.Sum(nil)) != strings.ToLower(item.SHA256) {
		return errors.New("worker input differs from verified evidence")
	}
	return os.Chmod(path, 0444)
}

type boundedWorkerOutput struct {
	bytes.Buffer
	cancel context.CancelFunc
}

func (w *boundedWorkerOutput) Write(b []byte) (int, error) {
	if w.Len()+len(b) > workerOutputLimit {
		w.cancel()
		return 0, errors.New("worker output limit exceeded")
	}
	return w.Buffer.Write(b)
}

func analyzeNative(ctx context.Context, p *Package, item Item, format string, budget int) (WorkerResult, ParserRun, error) {
	result := WorkerResult{Schema: WorkerSchema, Summary: ParseSummary{Evidence: item.ID, Format: format}}
	run := ParserRun{Evidence: item.ID, Format: format}
	executable, _ := ctx.Value(workerContextKey{}).(string)
	if executable == "" {
		return result, run, errors.New("native parser requires an isolated worker executable")
	}
	if item.Size > workerInputLimit {
		result.Summary.Limited = true
		return result, run, errors.New("native parser input limit exceeded")
	}
	dir, e := os.MkdirTemp("", "k957-parser-")
	if e != nil {
		return result, run, e
	}
	defer os.RemoveAll(dir)
	if e = stageWorkerObject(ctx, p.Files[item.Object], item, filepath.Join(dir, "evidence.bin")); e != nil {
		return result, run, e
	}
	run.Inputs = append(run.Inputs, ParserInput{Evidence: item.ID, Source: item.Source, SHA256: item.SHA256, Role: "main"})
	inputPaths := map[string]string{filepath.Join(dir, "evidence.bin"): item.SHA256}
	if format == "SQLite" {
		for _, suffix := range []string{"-wal", "-journal"} {
			for _, sidecar := range p.Manifest.Items {
				if sidecar.Source == item.Source+suffix {
					if e = stageWorkerObject(ctx, p.Files[sidecar.Object], sidecar, filepath.Join(dir, "evidence.bin"+suffix)); e != nil {
						return result, run, e
					}
					run.Inputs = append(run.Inputs, ParserInput{Evidence: sidecar.ID, Source: sidecar.Source, SHA256: sidecar.SHA256, Role: suffix})
					inputPaths[filepath.Join(dir, "evidence.bin"+suffix)] = sidecar.SHA256
				}
			}
		}
	}
	jobCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	request := WorkerRequest{Schema: WorkerSchema, Format: format, File: "evidence.bin", Item: item, Budget: min(max(budget, 0), analysisEventLimit)}
	cmd := exec.CommandContext(jobCtx, executable, "parser-worker")
	configureToolProcess(cmd)
	cmd.WaitDelay = 2 * time.Second
	cmd.Dir = dir
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "SYSTEMROOT=" + os.Getenv("SYSTEMROOT"), "TMPDIR=" + dir, "TEMP=" + dir, "TMP=" + dir, "GOMAXPROCS=1", "GOMEMLIMIT=256MiB"}
	cmd.Stdin = bytes.NewReader(JSON(request))
	out := &boundedWorkerOutput{cancel: cancel}
	stderr := &boundedWorkerOutput{cancel: cancel}
	cmd.Stdout, cmd.Stderr = out, stderr
	if e = runToolCommand(cmd); e != nil {
		return result, run, fmt.Errorf("parser worker failed: %w", e)
	}
	for path, sum := range inputPaths {
		actual, e := fileSHA256Progress(path, "", 0, &verifyMeter{ctx: ctx})
		if e != nil {
			return result, run, e
		}
		if actual != strings.ToLower(sum) {
			return result, run, errors.New("parser changed its staged evidence input")
		}
	}
	if e = custodyJSON(out.Bytes(), &result); e != nil {
		return result, run, fmt.Errorf("invalid worker response: %w", e)
	}
	run.Security = result.Security
	if result.Schema != WorkerSchema || result.Summary.Evidence != item.ID || result.Summary.Format != format || len(result.Events) > request.Budget {
		return result, run, errors.New("worker response violates protocol bounds")
	}
	for _, event := range result.Events {
		if event.Evidence != item.ID || event.Source != item.Source {
			return result, run, errors.New("worker changed evidence identity")
		}
	}
	if result.Error != "" {
		return result, run, errors.New(result.Error)
	}
	return result, run, nil
}
