package main

import (
	"os"
	"testing"
	"time"
)

func TestStopOnInterrupt(t *testing.T) {
	code := -1
	old := exitProcess
	exitProcess = func(c int) { code = c }
	defer func() { exitProcess = old }()
	signals := make(chan os.Signal, 1)
	done := make(chan struct{})
	go func() {
		stopOnInterrupt(signals)
		close(done)
	}()
	signals <- os.Interrupt
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("interrupt was not handled")
	}
	if code != 130 {
		t.Fatalf("exit %d", code)
	}
}
