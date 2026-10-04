//go:build windows

package core

import (
	"os/exec"
)

// privileged reports whether an elevated command succeeds. A non-elevated
// token cannot open the session list used here.
func privileged() bool {
	cmd := exec.Command("net", "session")
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run() == nil
}
