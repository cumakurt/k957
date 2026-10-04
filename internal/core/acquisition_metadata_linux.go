//go:build linux

package core

import (
	"os"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func captureFileMetadata(file *os.File, info os.FileInfo) *FileMetadata {
	m := &FileMetadata{Status: "captured"}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		m.Status = "unsupported"
		return m
	}
	m.Device = "device:" + strconv.FormatUint(uint64(st.Dev), 10)
	m.Inode = strconv.FormatUint(st.Ino, 10)
	uid, gid := st.Uid, st.Gid
	m.UID, m.GID = &uid, &gid
	m.Links = uint64(st.Nlink)
	atime := time.Unix(st.Atim.Sec, st.Atim.Nsec).UTC()
	ctime := time.Unix(st.Ctim.Sec, st.Ctim.Nsec).UTC()
	m.Accessed, m.Changed = &atime, &ctime
	var statx unix.Statx_t
	if e := unix.Statx(int(file.Fd()), "", unix.AT_EMPTY_PATH, unix.STATX_BTIME, &statx); e == nil && statx.Mask&unix.STATX_BTIME != 0 {
		stamp := time.Unix(statx.Btime.Sec, int64(statx.Btime.Nsec)).UTC()
		m.Created = &stamp
	}
	captureExtendedAttributes(int(file.Fd()), m)
	return m
}
