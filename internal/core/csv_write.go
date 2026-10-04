package core

import (
	"encoding/csv"
	"io"
	"os"
)

// CSV exports write directly to an exclusively created file. The csv.Writer's
// fixed buffer avoids retaining a second copy of every serialized row in RAM.
func writeCSVNew(path string, emit func(*csv.Writer) error) error {
	return writeFileNew(path, func(file io.Writer) error {
		writer := csv.NewWriter(file)
		if err := emit(writer); err != nil {
			return err
		}
		writer.Flush()
		return writer.Error()
	})
}

// Publish only a complete, synced export. A failure removes the newly created
// file; an existing file is never opened for writing.
func writeFileNew(path string, emit func(io.Writer) error) (err error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	complete := false
	defer func() {
		file.Close()
		if !complete {
			os.Remove(path)
		}
	}()
	if err = emit(file); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	complete = true
	return nil
}
