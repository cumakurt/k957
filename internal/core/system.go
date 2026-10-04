package core

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"time"
)

const snapshotLimit = 4 << 20

type source struct {
	Name, File, Command string
	Args                []string
}

// systemGOOS selects the live-command profile. It matches the compiled OS
// unless a test substitutes another profile.
var systemGOOS = runtime.GOOS

func systemSources() []source {
	switch systemGOOS {
	case "linux":
		return []source{
			{Name: "proc/version", File: "/proc/version"},
			{Name: "proc/sys/kernel/osrelease", File: "/proc/sys/kernel/osrelease"},
			{Name: "proc/cmdline", File: "/proc/cmdline"},
			{Name: "proc/uptime", File: "/proc/uptime"},
			{Name: "proc/loadavg", File: "/proc/loadavg"},
			{Name: "proc/cpuinfo", File: "/proc/cpuinfo"},
			{Name: "proc/meminfo", File: "/proc/meminfo"},
			{Name: "proc/swaps", File: "/proc/swaps"},
			{Name: "proc/modules", File: "/proc/modules"},
			{Name: "proc/mounts", File: "/proc/mounts"},
			{Name: "proc/net/tcp", File: "/proc/net/tcp"},
			{Name: "proc/net/tcp6", File: "/proc/net/tcp6"},
			{Name: "proc/net/udp", File: "/proc/net/udp"},
			{Name: "proc/net/udp6", File: "/proc/net/udp6"},
			{Name: "proc/net/arp", File: "/proc/net/arp"},
			{Name: "proc/net/dev", File: "/proc/net/dev"},
			{Name: "proc/net/route", File: "/proc/net/route"},
			{Name: "os-release", File: "/etc/os-release"},
			{Name: "platform", Command: "uname", Args: []string{"-a"}},
			{Name: "processes", Command: "ps", Args: []string{"-eo", "pid,ppid,uid,lstart,args"}},
			{Name: "sessions", Command: "who"},
			{Name: "sockets", Command: "ss", Args: []string{"-tunap"}},
			{Name: "interfaces", Command: "ip", Args: []string{"addr"}},
			{Name: "routes", Command: "ip", Args: []string{"route"}},
			{Name: "services", Command: "systemctl", Args: []string{"list-units", "--all", "--no-pager", "--plain"}},
			{Name: "timers", Command: "systemctl", Args: []string{"list-timers", "--all", "--no-pager", "--plain"}},
			{Name: "logins", Command: "last", Args: []string{"-F", "-n", "400"}},
			{Name: "sessions-w", Command: "w"},
			{Name: "packages-dpkg", Command: "dpkg", Args: []string{"--get-selections"}},
			{Name: "packages-rpm", Command: "rpm", Args: []string{"-qa"}},
			{Name: "journal", Command: "journalctl", Args: []string{"--no-pager", "--utc", "-n", "5000", "-o", "short-iso-precise"}},
		}
	case "windows":
		sources := []source{
			{Name: "systeminfo", Command: "systeminfo.exe"},
			{Name: "processes", Command: "tasklist.exe", Args: []string{"/V", "/FO", "CSV"}},
			{Name: "connections", Command: "netstat.exe", Args: []string{"-ano"}},
			{Name: "identity", Command: "whoami.exe", Args: []string{"/all"}},
			{Name: "network", Command: "ipconfig.exe", Args: []string{"/all"}},
			{Name: "dns-cache", Command: "ipconfig.exe", Args: []string{"/displaydns"}},
			{Name: "arp", Command: "arp.exe", Args: []string{"-a"}},
			{Name: "routes", Command: "route.exe", Args: []string{"print"}},
			{Name: "services", Command: "sc.exe", Args: []string{"query", "state=", "all"}},
			{Name: "drivers", Command: "driverquery.exe", Args: []string{"/V", "/FO", "CSV"}},
			{Name: "scheduled-tasks", Command: "schtasks.exe", Args: []string{"/Query", "/FO", "CSV", "/V"}},
			{Name: "local-users", Command: "net.exe", Args: []string{"user"}},
			{Name: "local-administrators", Command: "net.exe", Args: []string{"localgroup", "administrators"}},
			{Name: "sessions", Command: "quser.exe"},
			{Name: "firewall", Command: "netsh.exe", Args: []string{"advfirewall", "show", "allprofiles"}},
			{Name: "autoruns-hklm-run", Command: "reg.exe", Args: []string{"query", `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`}},
			{Name: "autoruns-hklm-runonce", Command: "reg.exe", Args: []string{"query", `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`}},
			{Name: "autoruns-hklm-runonceex", Command: "reg.exe", Args: []string{"query", `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnceEx`}},
			{Name: "autoruns-hklm-explorer-run", Command: "reg.exe", Args: []string{"query", `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`}},
			{Name: "autoruns-winlogon", Command: "reg.exe", Args: []string{"query", `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon`}},
			{Name: "autoruns-hkcu-run", Command: "reg.exe", Args: []string{"query", `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`}},
			{Name: "autoruns-hkcu-runonce", Command: "reg.exe", Args: []string{"query", `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`}},
		}
		// Rendered event XML fragments are handled by the Windows event XML
		// analyzer; the ".xml" suffix selects that parser.
		for _, channel := range [][2]string{
			{"system", "System"},
			{"security", "Security"},
			{"application", "Application"},
			{"powershell", "Microsoft-Windows-PowerShell/Operational"},
			{"task-scheduler", "Microsoft-Windows-TaskScheduler/Operational"},
			{"sysmon", "Microsoft-Windows-Sysmon/Operational"},
			{"defender", "Microsoft-Windows-Windows Defender/Operational"},
			{"terminal-services", "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"},
			{"bits", "Microsoft-Windows-Bits-Client/Operational"},
			{"firewall", "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"},
		} {
			sources = append(sources, source{Name: "eventlog-" + channel[0] + ".xml", Command: "wevtutil.exe", Args: []string{"qe", channel[1], "/c:2000", "/rd:true", "/f:xml"}})
		}
		return sources
	case "darwin":
		return []source{
			{Name: "system", Command: "/usr/bin/sw_vers"},
			{Name: "platform", Command: "/usr/bin/uname", Args: []string{"-a"}},
			{Name: "processes", Command: "/bin/ps", Args: []string{"-axo", "pid,ppid,uid,lstart,command"}},
			{Name: "connections", Command: "/usr/sbin/netstat", Args: []string{"-an"}},
			{Name: "routes", Command: "/usr/sbin/netstat", Args: []string{"-rn"}},
			{Name: "interfaces", Command: "/sbin/ifconfig", Args: []string{"-a"}},
			{Name: "arp", Command: "/usr/sbin/arp", Args: []string{"-an"}},
			{Name: "mounts", Command: "/sbin/mount"},
			{Name: "sessions", Command: "/usr/bin/who"},
			{Name: "logins", Command: "/usr/bin/last"},
			{Name: "launchd", Command: "/bin/launchctl", Args: []string{"list"}},
			{Name: "kernel-extensions", Command: "/usr/sbin/kextstat"},
			{Name: "system-extensions", Command: "/usr/bin/systemextensionsctl", Args: []string{"list"}},
			{Name: "sip", Command: "/usr/bin/csrutil", Args: []string{"status"}},
			{Name: "packages", Command: "/usr/sbin/pkgutil", Args: []string{"--pkgs"}},
			{Name: "unified-log", Command: "/usr/bin/log", Args: []string{"show", "--last", "30m", "--style", "compact"}},
		}
	}
	return []source{{Name: "platform", Command: "uname", Args: []string{"-a"}}}
}

// cappedBuffer keeps at most limit bytes. The buffer is a named field so
// io.Copy cannot bypass Write through bytes.Buffer.ReadFrom.
type cappedBuffer struct {
	buf      bytes.Buffer
	limit    int
	overflow bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	remain := b.limit - b.buf.Len()
	if remain < 0 {
		remain = 0
	}
	if len(p) > remain {
		if remain == 0 {
			b.overflow = true
			return n, nil
		}
		p = p[:remain]
		b.overflow = true
	}
	_, _ = b.buf.Write(p)
	return n, nil
}

func (b *cappedBuffer) Len() int       { return b.buf.Len() }
func (b *cappedBuffer) Bytes() []byte  { return b.buf.Bytes() }
func (b *cappedBuffer) String() string { return b.buf.String() }
func snapshot(ctx context.Context, s source) ([]byte, string, error) {
	if s.File != "" {
		b, e := readPrefix(s.File, snapshotLimit)
		return b, "", e
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, s.Command, s.Args...)
	b := &cappedBuffer{limit: snapshotLimit}
	cmd.Stdout = b
	cmd.Stderr = b
	e := cmd.Run()
	text, note := normalizeSnapshotText(s.Command, b.Bytes())
	if b.overflow {
		return text, note, fmt.Errorf("command output truncated")
	}
	return text, note, e
}

// readPrefix keeps up to limit bytes and reports truncation instead of
// discarding a large live file entirely.
func readPrefix(path string, limit int64) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if int64(len(b)) > limit {
		return b[:limit], fmt.Errorf("file truncated at %d bytes", limit)
	}
	return b, e
}
