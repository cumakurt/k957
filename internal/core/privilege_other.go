//go:build !unix && !windows

package core

func privileged() bool { return false }
