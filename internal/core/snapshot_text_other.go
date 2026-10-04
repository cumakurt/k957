//go:build !windows

package core

import "errors"

func decodeSnapshotText(string, []byte) ([]byte, string, error) {
	return nil, "", errors.New("command output code page conversion is only performed on Windows")
}
