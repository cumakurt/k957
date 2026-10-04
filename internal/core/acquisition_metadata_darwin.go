//go:build darwin

package core

import (
	"os"
	"strconv"
	"syscall"
	"time"
)

func captureFileMetadata(file *os.File, info os.FileInfo) *FileMetadata {
	m := &FileMetadata{Status: "partial", Omissions: []string{"native_macos_acl_not_collected"}}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		m.Status = "unsupported"
		return m
	}
	m.Device = "device:" + strconv.FormatUint(uint64(st.Dev), 10)
	m.Inode = strconv.FormatUint(st.Ino, 10)
	m.Links = uint64(st.Nlink)
	uid, gid := st.Uid, st.Gid
	m.UID = &uid
	m.GID = &gid
	atime := time.Unix(st.Atimespec.Sec, st.Atimespec.Nsec).UTC()
	ctime := time.Unix(st.Ctimespec.Sec, st.Ctimespec.Nsec).UTC()
	birth := time.Unix(st.Birthtimespec.Sec, st.Birthtimespec.Nsec).UTC()
	m.Accessed = &atime
	m.Changed = &ctime
	m.Created = &birth
	captureExtendedAttributes(int(file.Fd()), m)
	return m
}
