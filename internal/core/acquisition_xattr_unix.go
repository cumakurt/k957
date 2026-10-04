//go:build linux || darwin

package core

import (
	"encoding/base64"
	"golang.org/x/sys/unix"
	"sort"
	"strings"
	"unicode/utf8"
)

func captureExtendedAttributes(fd int, m *FileMetadata) {
	omit := func(reason string) { m.Status = "partial"; m.Omissions = append(m.Omissions, reason) }
	n, e := unix.Flistxattr(fd, nil)
	if e != nil {
		omit("extended_attribute_list_unavailable")
		return
	}
	if n > 65536 {
		omit("extended_attribute_name_limit")
		return
	}
	if n == 0 {
		return
	}
	names := make([]byte, n)
	n, e = unix.Flistxattr(fd, names)
	if e != nil || n < 0 || n > len(names) {
		omit("extended_attribute_list_changed")
		return
	}
	keys := strings.Split(strings.TrimSuffix(string(names[:n]), "\x00"), "\x00")
	sort.Strings(keys)
	total := 0
	for i, key := range keys {
		if i >= 128 || len(key) > 1024 {
			omit("extended_attribute_count_or_name_limit")
			break
		}
		size, e := unix.Fgetxattr(fd, key, nil)
		if e != nil {
			omit("extended_attribute_value_unavailable")
			continue
		}
		if size > 65536-total {
			omit("extended_attribute_value_limit")
			continue
		}
		value := make([]byte, size)
		size, e = unix.Fgetxattr(fd, key, value)
		if e != nil || size < 0 || size > len(value) {
			omit("extended_attribute_value_changed")
			continue
		}
		total += size
		attribute := ExtendedAttribute{Value: base64.StdEncoding.EncodeToString(value[:size])}
		if utf8.ValidString(key) {
			attribute.Name = key
		} else {
			attribute.NameBase64 = base64.StdEncoding.EncodeToString([]byte(key))
		}
		m.Attributes = append(m.Attributes, attribute)
	}
}
