//go:build !linux && !darwin && !freebsd && !openbsd && !netbsd && !dragonfly

package core

import "os/exec"

// CommandContext cancels the direct child. Descendant containment requires
// a native job adapter and is not claimed on these platforms.
func configureToolProcess(cmd *exec.Cmd) {}
