//go:build windows

package core

import (
	"encoding/base64"
	"os"
	"strconv"
	"time"

	"golang.org/x/sys/windows"
)

func captureFileMetadata(file *os.File, info os.FileInfo) *FileMetadata {
	m := &FileMetadata{Status: "partial", Omissions: []string{"alternate_stream_bytes_not_collected", "sacl_not_requested"}}
	var native windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &native); err != nil {
		m.Omissions = append(m.Omissions, "native_file_information_unavailable")
		return m
	}
	m.Device = "volume_serial:" + strconv.FormatUint(uint64(native.VolumeSerialNumber), 10)
	m.Inode = strconv.FormatUint(uint64(native.FileIndexHigh)<<32|uint64(native.FileIndexLow), 10)
	m.Links = uint64(native.NumberOfLinks)
	m.Accessed = windowsMetadataTime(native.LastAccessTime)
	m.Created = windowsMetadataTime(native.CreationTime)
	if m.Accessed == nil || m.Created == nil {
		m.Omissions = append(m.Omissions, "native_timestamp_unavailable")
	}
	sd, err := windows.GetSecurityInfo(windows.Handle(file.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		m.Omissions = append(m.Omissions, "security_descriptor_unavailable")
		return m
	}
	sddl := sd.String()
	if sddl == "" || len(sddl) > 65536 {
		m.Omissions = append(m.Omissions, "security_descriptor_size_or_conversion")
		return m
	}
	m.Attributes = []ExtendedAttribute{{Name: "windows.security_descriptor_sddl", Value: base64.StdEncoding.EncodeToString([]byte(sddl))}}
	return m
}

func windowsMetadataTime(stamp windows.Filetime) *time.Time {
	ticks := uint64(stamp.HighDateTime)<<32 | uint64(stamp.LowDateTime)
	if ticks == 0 {
		return nil
	}
	value := time.Unix(int64(ticks/10000000)-11644473600, int64(ticks%10000000)*100).UTC()
	if value.Year() < 1 || value.Year() > 9999 {
		return nil
	}
	return &value
}
