//go:build !linux && !darwin && !windows

package core

import "os"

func captureFileMetadata(file *os.File, info os.FileInfo) *FileMetadata {
	return &FileMetadata{Status: "unsupported", Omissions: []string{"native_acl_xattr_stream_metadata_not_implemented_on_this_platform"}}
}
