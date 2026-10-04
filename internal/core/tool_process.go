package core

import (
	"os/exec"
	"sync"
)

var activeTools = struct {
	sync.Mutex
	commands map[*exec.Cmd]struct{}
}{commands: map[*exec.Cmd]struct{}{}}

func runToolCommand(cmd *exec.Cmd) error {
	activeTools.Lock()
	if err := cmd.Start(); err != nil {
		activeTools.Unlock()
		return err
	}
	activeTools.commands[cmd] = struct{}{}
	activeTools.Unlock()
	err := cmd.Wait()
	activeTools.Lock()
	delete(activeTools.commands, cmd)
	if cmd.Cancel != nil {
		cmd.Cancel()
	}
	activeTools.Unlock()
	return err
}

// CancelActiveTools is best-effort non-waiting cleanup before the CLI's hard
// interrupt exit. Unix process groups include helpers; other platforms kill
// the direct child and do not claim complete descendant containment.
func CancelActiveTools() {
	activeTools.Lock()
	defer activeTools.Unlock()
	for cmd := range activeTools.commands {
		if cmd.Cancel != nil {
			cmd.Cancel()
		}
	}
}
