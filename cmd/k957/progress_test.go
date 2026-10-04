package main

import (
	"bytes"
	"k957/internal/core"
	"strings"
	"testing"
	"time"
)

func TestFailedProgressAndReadWorkloadLabel(t *testing.T) {
	for _, tty := range []bool{false, true} {
		var buf bytes.Buffer
		v := newProgressView(&buf, "analyze", []progressPhase{{ID: "analyze", Weight: 1}})
		v.tty, v.color = tty, false
		v.report(core.Progress{Phase: "analyze", Detail: "memory.lime", Bytes: 50, TotalBytes: 100})
		buf.Reset()
		v.fail()
		v.done()
		v.finish()
		text := buf.String()
		if !strings.Contains(text, "analyze  failed") || !strings.Contains(text, "read workload") || strings.Contains(text, "100%") || strings.Contains(text, "finished") || strings.Contains(text, "✓ analyze") {
			t.Fatalf("misleading failed progress: %q", text)
		}
	}
	var buf bytes.Buffer
	v := newProgressView(&buf, "verify", []progressPhase{{ID: "verify", Weight: 1}})
	v.report(core.Progress{Phase: "verify", Bytes: 100, TotalBytes: 100})
	v.done()
	if !strings.Contains(buf.String(), "read workload 100 B") || !strings.Contains(buf.String(), "finished") {
		t.Fatal(buf.String())
	}
}

func TestProgressFractionAndDisplay(t *testing.T) {
	phases := []progressPhase{{ID: "prepare", Weight: 1}, {ID: "memory", Weight: 3}}
	got, known := overallFraction(phases, core.Progress{Phase: "memory", Bytes: 50, TotalBytes: 100})
	if !known || got < 0.62 || got > 0.63 {
		t.Fatalf("fraction %v known %v", got, known)
	}
	if _, known := overallFraction(phases, core.Progress{Phase: "files"}); known {
		t.Fatal("unknown work must not invent a percent")
	}
	remain, ok := estimateRemaining(4*time.Second, 0.5)
	if !ok || remain < 3*time.Second || remain > 5*time.Second {
		t.Fatalf("eta %s %v", remain, ok)
	}
	if _, ok := estimateRemaining(100*time.Millisecond, 0.5); ok {
		t.Fatal("eta before one second")
	}
	if formatBytes(1536) != "1.5 KiB" || formatDuration(90*time.Second) != "1m30s" {
		t.Fatal(formatBytes(1536), formatDuration(90*time.Second))
	}

	var buf bytes.Buffer
	view := newProgressView(&buf, "collect", phases)
	view.tty = true
	view.color = false
	view.started = time.Now().Add(-2 * time.Second)
	view.report(core.Progress{Phase: "memory", Detail: "physical 0x1000", Bytes: 50, TotalBytes: 100})
	text := buf.String()
	if !strings.Contains(text, "k957 collect") || !strings.Contains(text, "● memory") || !strings.Contains(text, "63%") && !strings.Contains(text, "62%") {
		t.Fatalf("tty frame:\n%s", text)
	}
	if !strings.Contains(text, "est.") || !strings.Contains(text, "physical 0x1000") || !strings.Contains(text, "\x1b[?25l") {
		t.Fatalf("tty frame:\n%s", text)
	}
	view.done()
	view.finish()
	if !strings.Contains(buf.String(), "finished") || !strings.Contains(buf.String(), "\x1b[?25h") {
		t.Fatal(buf.String())
	}

	buf.Reset()
	plain := newProgressView(&buf, "verify", []progressPhase{{ID: "verify", Weight: 1}})
	plain.tty = false
	plain.color = false
	plain.report(core.Progress{Phase: "verify", Detail: "host/stamp", Step: 1, Steps: 4})
	if strings.Contains(buf.String(), "\x1b") || !strings.Contains(buf.String(), "1/4") || !strings.Contains(buf.String(), "25%") {
		t.Fatalf("plain frame: %q", buf.String())
	}
}
