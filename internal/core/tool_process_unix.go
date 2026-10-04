//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package core

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

// Keep descendants in the tool's own process group so cancellation closes
// inherited output pipes and terminates helpers as well as the direct child.
func configureToolProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
}
