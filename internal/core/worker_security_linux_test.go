//go:build linux

package core

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestWorkerRestrictionsSubprocess(t *testing.T) {
	if os.Getenv("K957_WORKER_RESTRICTION_TEST") == "1" {
		security, e := restrictParserWorker()
		if e != nil {
			t.Fatal(e)
		}
		if !security.NetworkBlocked || !security.CPULimit {
			t.Fatal("restrictions not recorded")
		}
		if fd, e := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0); !errors.Is(e, syscall.EPERM) {
			if e == nil {
				unix.Close(fd)
			}
			t.Fatalf("socket was not denied: %v", e)
		}
		if fd, e := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0); !errors.Is(e, syscall.EPERM) {
			if e == nil {
				unix.Close(fd[0])
				unix.Close(fd[1])
			}
			t.Fatalf("socketpair was not denied: %v", e)
		}
		if e := exec.Command("/bin/true").Run(); e == nil {
			t.Fatal("worker may execute another program")
		}
		return
	}
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(exe, "-test.run=^TestWorkerRestrictionsSubprocess$", "-test.timeout="+(15*time.Second).String())
	cmd.Env = append(os.Environ(), "K957_WORKER_RESTRICTION_TEST=1")
	if output, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("worker restrictions: %v %s", e, output)
	}
}
