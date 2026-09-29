//go:build !windows

package core

import "os"

func replaceCheckpoint(oldpath, newpath string) error {
	return os.Rename(oldpath, newpath)
}
