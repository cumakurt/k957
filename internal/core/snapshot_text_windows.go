//go:build windows

package core

import (
	"fmt"
	"unicode/utf16"
	"unicode/utf8"

	"golang.org/x/sys/windows"
)

const mbErrInvalidChars = 0x00000008

var procGetOEMCP = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetOEMCP")

// Windows tools write the active code page when stdout is a pipe. wevtutil
// XML uses the ANSI code page; console tools such as systeminfo and tasklist
// use the OEM code page. A single non-UTF-8 byte would otherwise make the
// analyzer skip the whole snapshot.
func decodeSnapshotText(command string, raw []byte) ([]byte, string, error) {
	page := oemCodePage()
	kind := "OEM"
	if snapshotUsesANSICodePage(command) {
		page = windows.GetACP()
		kind = "ANSI"
	}
	text, err := codePageToUTF8(page, raw)
	if err != nil {
		return nil, "", err
	}
	return text, fmt.Sprintf("command output transcoded from Windows %s code page %d to UTF-8; stored text is not the original code-page bytes", kind, page), nil
}

func oemCodePage() uint32 {
	r, _, _ := procGetOEMCP.Call()
	return uint32(r)
}

func codePageToUTF8(page uint32, raw []byte) ([]byte, error) {
	if len(raw) == 0 {
		return raw, nil
	}
	chars, err := multiByteToUTF16(page, mbErrInvalidChars, raw)
	if err != nil {
		chars, err = multiByteToUTF16(page, 0, raw)
		if err != nil {
			return nil, err
		}
	}
	return utf16ToUTF8(chars), nil
}

func multiByteToUTF16(page, flags uint32, raw []byte) ([]uint16, error) {
	n, err := windows.MultiByteToWideChar(page, flags, &raw[0], int32(len(raw)), nil, 0)
	if err != nil || n <= 0 {
		if err == nil {
			err = windows.ERROR_INVALID_PARAMETER
		}
		return nil, err
	}
	out := make([]uint16, n)
	n, err = windows.MultiByteToWideChar(page, flags, &raw[0], int32(len(raw)), &out[0], n)
	if err != nil {
		return nil, err
	}
	return out[:n], nil
}

func utf16ToUTF8(chars []uint16) []byte {
	if len(chars) == 0 {
		return nil
	}
	if chars[len(chars)-1] == 0 {
		chars = chars[:len(chars)-1]
	}
	out := make([]byte, 0, len(chars))
	for _, r := range utf16.Decode(chars) {
		out = utf8.AppendRune(out, r)
	}
	return out
}
