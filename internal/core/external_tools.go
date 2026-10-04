package core

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

type ToolInvocation struct {
	Executable     string    `json:"executable"`
	SHA256         string    `json:"executable_sha256"`
	Args           []string  `json:"args"`
	Started        time.Time `json:"started"`
	Finished       time.Time `json:"finished"`
	TimeoutSeconds int       `json:"timeout_seconds"`
	ExitCode       int       `json:"exit_code"`
	StdoutSHA256   string    `json:"stdout_sha256"`
	StderrSHA256   string    `json:"stderr_sha256"`
	Security       string    `json:"security"`
}

type limitedToolWriter struct {
	writer    io.Writer
	remaining int64
	cancel    context.CancelFunc
}

func (w *limitedToolWriter) Write(b []byte) (int, error) {
	if int64(len(b)) > w.remaining {
		w.cancel()
		return 0, errors.New("external tool output exceeds bounds")
	}
	n, e := w.writer.Write(b)
	w.remaining -= int64(n)
	return n, e
}

func runDerivedTool(ctx context.Context, executable string, args []string, dir, stdoutName, stderrName string, limit int64, timeout time.Duration) (invocation ToolInvocation, err error) {
	exe, e := exec.LookPath(executable)
	if e != nil {
		return invocation, e
	}
	exe, e = filepath.Abs(exe)
	if e != nil {
		return invocation, e
	}
	exe, e = filepath.EvalSymlinks(exe)
	if e != nil {
		return invocation, e
	}
	sum, e := fileSHA256Progress(exe, "", 0, &verifyMeter{ctx: ctx})
	if e != nil {
		return invocation, e
	}
	invocation = ToolInvocation{Executable: exe, SHA256: sum, Args: append([]string(nil), args...), Started: time.Now().UTC(), TimeoutSeconds: int(timeout / time.Second), Security: "External examiner-selected tool, bounded wall time/output, minimal environment, private verified input copy. No complete OS filesystem/network/memory sandbox is asserted."}
	stdout, e := os.OpenFile(filepath.Join(dir, stdoutName), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return invocation, e
	}
	defer stdout.Close()
	stderr, e := os.OpenFile(filepath.Join(dir, stderrName), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return invocation, e
	}
	defer stderr.Close()
	job, cancel := context.WithCancel(ctx)
	if timeout > 0 {
		cancel()
		job, cancel = context.WithTimeout(ctx, timeout)
	} else {
		invocation.Security = "External examiner-selected tool, no automatic time/output limits, cancellation supported, minimal environment, private verified input copy. No complete OS sandbox is asserted."
	}
	defer cancel()
	cmd := exec.CommandContext(job, exe, args...)
	configureToolProcess(cmd)
	cmd.WaitDelay = 2 * time.Second
	cmd.Dir = dir
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "SYSTEMROOT=" + os.Getenv("SYSTEMROOT"), "TMPDIR=" + dir, "TMP=" + dir, "TEMP=" + dir, "TZ=UTC", "PYTHONUTF8=1", "PYTHONDONTWRITEBYTECODE=1"}
	if limit > 0 {
		cmd.Stdout = &limitedToolWriter{writer: stdout, remaining: limit, cancel: cancel}
		cmd.Stderr = &limitedToolWriter{writer: stderr, remaining: 64 << 10, cancel: cancel}
	} else {
		cmd.Stdout, cmd.Stderr = stdout, stderr
	}
	runErr := runToolCommand(cmd)
	invocation.Finished = time.Now().UTC()
	invocation.ExitCode = -1
	if cmd.ProcessState != nil {
		invocation.ExitCode = cmd.ProcessState.ExitCode()
	}
	if e = stdout.Close(); e != nil {
		return invocation, e
	}
	if e = stderr.Close(); e != nil {
		return invocation, e
	}
	invocation.StdoutSHA256, e = fileSHA256Progress(filepath.Join(dir, stdoutName), "", 0, &verifyMeter{ctx: ctx})
	if e != nil {
		return invocation, e
	}
	invocation.StderrSHA256, e = fileSHA256Progress(filepath.Join(dir, stderrName), "", 0, &verifyMeter{ctx: ctx})
	if e != nil {
		return invocation, e
	}
	after, e := fileSHA256Progress(exe, "", 0, &verifyMeter{ctx: ctx})
	if e != nil {
		return invocation, e
	}
	if after != sum {
		return invocation, errors.New("external tool changed during execution")
	}
	if runErr != nil {
		return invocation, fmt.Errorf("external tool failed: %w", runErr)
	}
	return invocation, nil
}

func stageRawImage(ctx context.Context, source, dest, expected string, limit int64) (sum string, size int64, err error) {
	info, e := os.Lstat(source)
	if e != nil {
		return "", 0, e
	}
	if !info.Mode().IsRegular() || info.Size() < 0 || (limit > 0 && info.Size() > limit) {
		return "", 0, errors.New("image must be a bounded regular file")
	}
	capacity, e := probeVolume(filepath.Dir(dest))
	if e != nil {
		return "", 0, fmt.Errorf("private staging capacity unavailable: %w", e)
	}
	reserve := int64(64 << 20)
	if limit == 0 {
		reserve = 0
	}
	if capacity.Available < info.Size() || capacity.Available-info.Size() < reserve {
		if reserve == 0 {
			return "", 0, fmt.Errorf("insufficient private staging space: need %d bytes, %d available", info.Size(), capacity.Available)
		}
		return "", 0, errors.New("insufficient private staging space including 64 MiB reserve")
	}
	in, e := os.Open(source)
	if e != nil {
		return "", 0, e
	}
	defer in.Close()
	opened, e := in.Stat()
	if e != nil {
		return "", 0, e
	}
	if !os.SameFile(info, opened) {
		return "", 0, errors.New("image changed before open")
	}
	out, e := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return "", 0, e
	}
	size, e = io.Copy(out, io.LimitReader(&contextReader{ctx: ctx, r: in}, info.Size()+1))
	closeErr := out.Close()
	if e != nil {
		return "", size, e
	}
	if closeErr != nil {
		return "", size, closeErr
	}
	after, e := os.Lstat(source)
	if e != nil {
		return "", size, e
	}
	if size != info.Size() || !os.SameFile(info, after) || info.Size() != after.Size() || !info.ModTime().Equal(after.ModTime()) {
		return "", size, errors.New("image changed while staging")
	}
	sum, e = fileSHA256Progress(dest, "", 0, &verifyMeter{ctx: ctx})
	if e != nil {
		return "", size, e
	}
	if expected != "" && (!validHash(expected) || sum != expected) {
		return "", size, errors.New("image differs from supplied evidence SHA-256")
	}
	if e = os.Chmod(dest, 0444); e != nil {
		return "", size, e
	}
	return sum, size, nil
}
