package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// The record-count ceiling and the byte ceiling are independent. Older readers
// with a 16 MiB ceiling cannot open larger packages, even though their schema is
// unchanged. Signing still requires the exact complete manifest in memory.
const manifestLimit = 128 << 20
const checkpointLimit = 256 << 20

// marshalManifest preserves MarshalJSON's exact indent, order and trailing
// newline, but encodes each inventory entry separately. This avoids retaining
// an additional compact JSON encoding of the entire large inventory.
func marshalManifest(m Manifest) ([]byte, error) {
	var buffer bytes.Buffer
	err := writeManifestJSON(&boundedJSONWriter{writer: &buffer, remaining: manifestLimit}, m)
	return buffer.Bytes(), err
}

func writeManifestJSON(w io.Writer, m Manifest) error {
	header := m
	header.Items, header.Issues = nil, nil
	b, err := MarshalJSON(header)
	if err != nil {
		return err
	}
	suffix := []byte("  \"items\": null,\n  \"issues\": null\n}\n")
	if !bytes.HasSuffix(b, suffix) {
		return errors.New("unexpected manifest encoding layout")
	}
	if _, err = w.Write(b[:len(b)-len(suffix)]); err != nil {
		return err
	}
	if _, err = io.WriteString(w, "  \"items\": "); err != nil {
		return err
	}
	if err = writeJSONSlice(w, m.Items); err != nil {
		return err
	}
	if _, err = io.WriteString(w, ",\n  \"issues\": "); err != nil {
		return err
	}
	if err = writeJSONSlice(w, m.Issues); err != nil {
		return err
	}
	_, err = io.WriteString(w, "\n}\n")
	return err
}

func writeJSONSlice[T any](w io.Writer, rows []T) error {
	if rows == nil {
		_, err := io.WriteString(w, "null")
		return err
	}
	if len(rows) == 0 {
		_, err := io.WriteString(w, "[]")
		return err
	}
	if _, err := io.WriteString(w, "[\n"); err != nil {
		return err
	}
	for i, row := range rows {
		encoded, err := json.MarshalIndent(row, "    ", "  ")
		if err != nil {
			return err
		}
		if _, err = io.WriteString(w, "    "); err != nil {
			return err
		}
		if _, err = w.Write(encoded); err != nil {
			return err
		}
		separator := ",\n"
		if i == len(rows)-1 {
			separator = "\n  ]"
		}
		if _, err = io.WriteString(w, separator); err != nil {
			return err
		}
	}
	return nil
}

type boundedJSONWriter struct {
	writer    io.Writer
	remaining int64
}

func (w *boundedJSONWriter) Write(b []byte) (int, error) {
	if int64(len(b)) > w.remaining {
		return 0, errors.New("manifest size limit exceeded")
	}
	n, err := w.writer.Write(b)
	w.remaining -= int64(n)
	if err == nil && n != len(b) {
		err = io.ErrShortWrite
	}
	return n, err
}
