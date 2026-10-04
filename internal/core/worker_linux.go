//go:build linux

package core

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Seccomp TSYNC applies the network denial to every Go runtime thread. The
// process uses private hash-checked copies, but this is not a filesystem sandbox.
func restrictParserWorker() (WorkerSecurity, error) {
	out := WorkerSecurity{ProcessIsolation: true, Filesystem: "private-verified-copies; no filesystem sandbox"}
	if e := syscall.Setrlimit(syscall.RLIMIT_CPU, &syscall.Rlimit{Cur: 25, Max: 26}); e != nil {
		return out, e
	}
	out.CPULimit = true
	if _, _, e := syscall.RawSyscall6(syscall.SYS_PRCTL, 38, 1, 0, 0, 0, 0); e != 0 {
		return out, e
	}
	var arch uint32
	switch runtime.GOARCH {
	case "amd64":
		arch = unix.AUDIT_ARCH_X86_64
	case "arm64":
		arch = unix.AUDIT_ARCH_AARCH64
	default:
		return out, fmt.Errorf("unsupported worker seccomp architecture")
	}
	filter := []syscall.SockFilter{
		{Code: 0x20, K: 4}, // seccomp_data.arch
		{Code: 0x15, Jt: 1, K: arch},
		{Code: 0x06, K: 0x80000000},        // KILL_PROCESS for an unexpected ABI
		{Code: 0x20, K: 0},                 // seccomp_data.nr
		{Code: 0x35, Jf: 1, K: 0x40000000}, // reject the x32 alternate ABI
		{Code: 0x06, K: 0x00050000 | uint32(syscall.EPERM)},
	}
	for _, nr := range []uintptr{unix.SYS_SOCKET, unix.SYS_SOCKETPAIR, unix.SYS_CONNECT, unix.SYS_EXECVE, unix.SYS_EXECVEAT, unix.SYS_PTRACE} {
		filter = append(filter, syscall.SockFilter{Code: 0x15, Jf: 1, K: uint32(nr)}, syscall.SockFilter{Code: 0x06, K: 0x00050000 | uint32(syscall.EPERM)})
	}
	filter = append(filter, syscall.SockFilter{Code: 0x06, K: 0x7fff0000})
	prog := syscall.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	// SECCOMP_SET_MODE_FILTER = 1; SECCOMP_FILTER_FLAG_TSYNC = 1.
	if _, _, e := syscall.RawSyscall(unix.SYS_SECCOMP, 1, 1, uintptr(unsafe.Pointer(&prog))); e != 0 {
		return out, fmt.Errorf("seccomp network denial: %w", e)
	}
	out.NetworkBlocked = true
	return out, nil
}
