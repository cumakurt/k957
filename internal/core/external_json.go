package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// External formats can use mixed-case keys. Still reject ambiguous duplicate
// fields, multiple roots, and excessive nesting before accepting projections.
func validateExternalJSON(body []byte) error {
	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	nodes := 0
	var value func(int) error
	value = func(depth int) error {
		nodes++
		if depth > 64 || nodes > 1000000 {
			return errors.New("external JSON exceeds structural bounds")
		}
		t, err := d.Token()
		if err != nil {
			return err
		}
		delim, compound := t.(json.Delim)
		if !compound {
			return nil
		}
		switch delim {
		case '{':
			keys := map[string]bool{}
			for d.More() {
				keyToken, err := d.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok || keys[key] {
					return errors.New("duplicate external JSON key")
				}
				keys[key] = true
				if err := value(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for d.More() {
				if err := value(depth + 1); err != nil {
					return err
				}
			}
		default:
			return errors.New("invalid external JSON delimiter")
		}
		_, err = d.Token()
		return err
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing external JSON")
	}
	return nil
}
