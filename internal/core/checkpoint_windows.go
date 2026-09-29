//go:build windows

package core

import (
	"errors"
	"os"
	"syscall"
	"time"
)

func replaceCheckpoint(oldpath, newpath string) error {
	// Windows can reject replacement while a status reader briefly holds the
	// destination open. Retry only sharing/access conflicts, with a fixed
	// deadline; never delete the previous checkpoint to make room for the new one.
	const sharingViolation syscall.Errno = 32
	deadline := time.Now().Add(time.Second)
	for {
		err := os.Rename(oldpath, newpath)
		if (!errors.Is(err, syscall.ERROR_ACCESS_DENIED) && !errors.Is(err, sharingViolation)) || !time.Now().Before(deadline) {
			return err
		}
		time.Sleep(10 * time.Millisecond)
	}
}
