package core

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"time"
)

type source struct {
	Name, File, Command string
	Args                []string
}

func systemSources() []source {
	switch runtime.GOOS {
	case "linux":
		return []source{{Name: "proc/version", File: "/proc/version"}, {Name: "proc/meminfo", File: "/proc/meminfo"}, {Name: "proc/mounts", File: "/proc/mounts"}, {Name: "proc/net/tcp", File: "/proc/net/tcp"}, {Name: "proc/net/tcp6", File: "/proc/net/tcp6"}, {Name: "proc/net/route", File: "/proc/net/route"}, {Name: "os-release", File: "/etc/os-release"}, {Name: "processes", Command: "ps", Args: []string{"-eo", "pid,ppid,uid,lstart,args"}}, {Name: "sessions", Command: "who"}, {Name: "sockets", Command: "ss", Args: []string{"-tunap"}}}
	case "windows":
		return []source{{Name: "systeminfo", Command: "systeminfo.exe"}, {Name: "processes", Command: "tasklist.exe", Args: []string{"/V", "/FO", "CSV"}}, {Name: "connections", Command: "netstat.exe", Args: []string{"-ano"}}, {Name: "identity", Command: "whoami.exe", Args: []string{"/all"}}, {Name: "network", Command: "ipconfig.exe", Args: []string{"/all"}}}
	case "darwin":
		return []source{{Name: "system", Command: "/usr/bin/sw_vers"}, {Name: "processes", Command: "/bin/ps", Args: []string{"-axo", "pid,ppid,uid,lstart,command"}}, {Name: "connections", Command: "/usr/sbin/netstat", Args: []string{"-an"}}, {Name: "mounts", Command: "/sbin/mount"}, {Name: "sessions", Command: "/usr/bin/who"}}
	}
	return []source{{Name: "platform", Command: "uname", Args: []string{"-a"}}}
}

type cappedBuffer struct {
	bytes.Buffer
	limit    int
	overflow bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	remain := b.limit - b.Len()
	if len(p) > remain {
		p = p[:remain]
		b.overflow = true
	}
	_, _ = b.Buffer.Write(p)
	return n, nil
}
func snapshot(ctx context.Context, s source) ([]byte, error) {
	if s.File != "" {
		return ReadLimited(s.File, 4<<20)
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, s.Command, s.Args...)
	b := &cappedBuffer{limit: 4 << 20}
	cmd.Stdout = b
	cmd.Stderr = b
	e := cmd.Run()
	if b.overflow {
		return b.Bytes(), fmt.Errorf("command output truncated")
	}
	return b.Bytes(), e
}
