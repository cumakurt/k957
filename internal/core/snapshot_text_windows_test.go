//go:build windows

package core

import (
	"strings"
	"testing"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestWindowsSnapshotCodePageRoundTrip(t *testing.T) {
	const text = "Unicode \u00fc\u00e7\u0130\u015f"
	cases := []struct {
		command string
		page    uint32
		kind    string
	}{
		{"wevtutil.exe", windows.GetACP(), "ANSI"},
		{"systeminfo.exe", oemCodePage(), "OEM"},
	}
	for _, tc := range cases {
		raw, err := utf8ToCodePage(tc.page, text)
		if err != nil {
			t.Fatal(tc.command, err)
		}
		out, note := normalizeSnapshotText(tc.command, raw)
		if string(out) != text {
			t.Fatalf("%s page %d got %q note %q raw %x", tc.command, tc.page, out, note, raw)
		}
		if !strings.Contains(note, tc.kind) {
			t.Fatalf("%s note %q", tc.command, note)
		}
	}
}

var procWideCharToMultiByte = windows.NewLazySystemDLL("kernel32.dll").NewProc("WideCharToMultiByte")

func utf8ToCodePage(page uint32, text string) ([]byte, error) {
	units := utf16.Encode([]rune(text))
	if len(units) == 0 {
		return nil, nil
	}
	n, _, e := procWideCharToMultiByte.Call(uintptr(page), 0, uintptr(unsafe.Pointer(&units[0])), uintptr(len(units)), 0, 0, 0, 0)
	if n == 0 {
		return nil, e
	}
	out := make([]byte, n)
	n, _, e = procWideCharToMultiByte.Call(uintptr(page), 0, uintptr(unsafe.Pointer(&units[0])), uintptr(len(units)), uintptr(unsafe.Pointer(&out[0])), n, 0, 0)
	if n == 0 {
		return nil, e
	}
	return out[:n], nil
}
