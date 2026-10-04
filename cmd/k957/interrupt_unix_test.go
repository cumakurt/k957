//go:build unix

package main

import (
	"os"
	"os/exec"
	"os/signal"
	"testing"
	"time"
)

func TestInterruptHelper(t *testing.T) {
	if os.Getenv("K957_INTERRUPT_HELPER") != "1" {
		return
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt)
	_, _ = os.Stdout.WriteString("ready\n")
	stopOnInterrupt(signals)
}

func TestProcessStopsOnInterrupt(t *testing.T) {
	if os.Getenv("K957_INTERRUPT_HELPER") == "1" {
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestInterruptHelper$")
	cmd.Env = append(os.Environ(), "K957_INTERRUPT_HELPER=1")
	out, e := cmd.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	buf := make([]byte, 6)
	if _, e = out.Read(buf); e != nil {
		_ = cmd.Process.Kill()
		t.Fatal(e)
	}
	if string(buf) != "ready\n" {
		_ = cmd.Process.Kill()
		t.Fatalf("helper said %q", buf)
	}
	if e = cmd.Process.Signal(os.Interrupt); e != nil {
		_ = cmd.Process.Kill()
		t.Fatal(e)
	}
	wait := make(chan error, 1)
	go func() { wait <- cmd.Wait() }()
	select {
	case e = <-wait:
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("process kept running after interrupt")
	}
	exit, ok := e.(*exec.ExitError)
	if !ok || exit.ExitCode() != 130 {
		t.Fatalf("exit %v", e)
	}
}
