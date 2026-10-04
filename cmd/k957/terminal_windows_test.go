//go:build windows

package main

import (
	"golang.org/x/sys/windows"
	"os"
	"testing"
)

func TestWindowsConsoleVirtualTerminalProcessing(t *testing.T) {
	console, err := os.OpenFile("CONOUT$", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("native console unavailable: %v", err)
	}
	defer console.Close()
	handle := windows.Handle(console.Fd())
	var original uint32
	if err := windows.GetConsoleMode(handle, &original); err != nil {
		t.Fatal(err)
	}
	defer windows.SetConsoleMode(handle, original)
	t.Setenv("TERM", "")
	if err := windows.SetConsoleMode(handle, original&^windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING); err != nil {
		t.Fatal(err)
	}
	if !supportsANSI(console) {
		t.Fatal("VT processing was not enabled")
	}
	var mode uint32
	if err := windows.GetConsoleMode(handle, &mode); err != nil || mode&windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING == 0 {
		t.Fatalf("console mode: %x %v", mode, err)
	}
	t.Setenv("NO_COLOR", "1")
	if newProgressView(console, "analyze", nil).color {
		t.Fatal("NO_COLOR ignored")
	}
	t.Setenv("TERM", "dumb")
	if newProgressView(console, "analyze", nil).tty {
		t.Fatal("TERM=dumb still emits cursor control")
	}
	f, err := os.CreateTemp(t.TempDir(), "redirected")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	t.Setenv("TERM", "")
	if supportsANSI(f) || isTerminal(f) {
		t.Fatal("redirected file treated as console")
	}
}
