//go:build !windows

package main

import (
	"io"
	"os"
)

func terminalFile(file *os.File) bool {
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func supportsANSI(out io.Writer) bool {
	return os.Getenv("TERM") != "dumb" && isTerminal(out)
}
