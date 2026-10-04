package core

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"time"
)

// writeBodyfile writes a Sleuth Kit body file. Only mtime is known.
// atime, ctime, crtime, uid and gid are zero. The MD5 column is 0 because
// SHA-256 is the authoritative hash. The mode field marks a regular file
// without claiming the original permission bits.
func writeBodyfile(items []bodyfileRow, path string) error {
	return writeFileNew(path, func(output io.Writer) error {
		w := bufio.NewWriter(output)
		for _, it := range items {
			if err := writeBodyfileRow(w, it); err != nil {
				return err
			}
		}
		return w.Flush()
	})
}

var bodyfileSanitizer = strings.NewReplacer("|", "_", "\n", "_", "\r", "_")

func writeBodyfileRow(w io.Writer, it bodyfileRow) error {
	mtime := int64(0)
	if !it.Modified.IsZero() {
		mtime = it.Modified.UTC().Unix()
	}
	_, err := fmt.Fprintf(w, "0|%s|0|r/r--------|0|0|%d|0|%d|0|0\n", bodyfileSanitizer.Replace(it.Name), it.Size, mtime)
	return err
}

type bodyfileRow struct {
	Name     string
	Size     int64
	Modified time.Time
}
