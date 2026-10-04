package core

import (
	"bytes"
	"strings"
	"unicode/utf8"
)

// normalizeSnapshotText converts live command output to UTF-8 when the
// captured bytes are not already valid UTF-8. File snapshots are not passed
// here. An empty note means the returned bytes are the captured bytes.
func normalizeSnapshotText(command string, raw []byte) ([]byte, string) {
	if len(raw) == 0 || (utf8.Valid(raw) && bytes.IndexByte(raw, 0) < 0) {
		return raw, ""
	}
	text, note, err := decodeSnapshotText(command, raw)
	if err != nil || !utf8.Valid(text) {
		return raw, ""
	}
	return text, note
}

func snapshotUsesANSICodePage(command string) bool {
	base := command
	if i := strings.LastIndexAny(command, `/\`); i >= 0 {
		base = command[i+1:]
	}
	base = strings.ToLower(base)
	return base == "wevtutil.exe" || base == "wevtutil"
}
