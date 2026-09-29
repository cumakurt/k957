package core

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCheckpointReaderAllowsReplacement(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		name := "plain"
		if encrypted {
			name = "encrypted"
		}
		t.Run(name, func(t *testing.T) {
			work := t.TempDir()
			var c *workCrypto
			if encrypted {
				key := filepath.Join(t.TempDir(), "key")
				if err := os.WriteFile(key, []byte(strings.Repeat("01", 32)), 0600); err != nil {
					t.Fatal(err)
				}
				var err error
				c, err = newWorkCrypto(key)
				if err != nil {
					t.Fatal(err)
				}
			}
			state := WorkState{Manifest: Manifest{Case: "before"}}
			if err := saveWork(work, state, c); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(work, c.stateName())
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			reader, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			state.Manifest.Case = "after"
			result := make(chan error, 1)
			go func() { result <- saveWork(work, state, c) }()
			// Keep the destination open across a write attempt, as work-status
			// can do while the collector is saving its next checkpoint.
			time.Sleep(50 * time.Millisecond)
			if err = reader.Close(); err != nil {
				t.Fatal(err)
			}
			if err = <-result; err != nil {
				t.Fatalf("temporary status reader prevented checkpoint replacement: %v", err)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(after, before) {
				t.Fatal("checkpoint did not advance")
			}
			decoded, err := c.open("state", after)
			if err != nil || !bytes.Equal(decoded, JSON(state)) {
				t.Fatalf("replacement checkpoint is incorrect: %v", err)
			}
		})
	}
}
