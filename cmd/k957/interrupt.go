package main

import (
	"fmt"
	"k957/internal/core"
	"os"
	"os/signal"
)

// watchInterrupt exits the process on the first Ctrl+C. Commands also listen
// so they can cancel work; that registration disables the runtime's default
// termination, so this watcher is what makes the stop unconditional.
func watchInterrupt() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt)
	stopOnInterrupt(signals)
}

func stopOnInterrupt(signals <-chan os.Signal) {
	<-signals
	if supportsANSI(os.Stderr) {
		fmt.Fprint(os.Stderr, "\n\x1b[?25h")
	}
	core.CancelActiveTools()
	exitProcess(130)
}
