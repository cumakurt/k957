//go:build unix

package core

import "os"

func privileged() bool { return os.Geteuid() == 0 }
