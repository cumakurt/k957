//go:build windows

package main

import (
	"io"
	"os"

	"golang.org/x/sys/windows"
)

func terminalFile(file *os.File) bool {
	var mode uint32
	return windows.GetConsoleMode(windows.Handle(file.Fd()), &mode) == nil
}

// A console handle alone does not imply that escape sequences are supported.
// Enable VT processing while preserving the console's existing mode flags.
// Older consoles fall back to plain progress and uncolored summaries.
func supportsANSI(out io.Writer) bool {
	file, ok := out.(*os.File)
	if !ok || os.Getenv("TERM") == "dumb" {
		return false
	}
	handle := windows.Handle(file.Fd())
	var mode uint32
	if windows.GetConsoleMode(handle, &mode) != nil {
		return false
	}
	required := uint32(windows.ENABLE_PROCESSED_OUTPUT | windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING)
	if mode&required == required {
		return true
	}
	return windows.SetConsoleMode(handle, mode|required) == nil
}
