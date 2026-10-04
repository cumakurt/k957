package core

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"howett.net/plist"
)

func FuzzRegistry(f *testing.F) {
	f.Add(registryFixture(), false)
	f.Add(registryFixture(), true)
	f.Add([]byte("regf"), false)
	f.Fuzz(func(t *testing.T, body []byte, repairChecksum bool) {
		if len(body) > 256<<10 {
			return
		}
		// Exercise both rejected headers and deeper cell/key/value paths.
		// Repair only the synthetic input's header checksum; the production
		// parser still applies all format, extent and graph checks.
		if repairChecksum && len(body) >= 8192 && bytes.Equal(body[:4], []byte("regf")) {
			body = bytes.Clone(body)
			registryFixtureChecksum(body)
		}
		path := filepath.Join(t.TempDir(), "fixture.regf")
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
		events, summary, err := parseRegistry(context.Background(), path, Item{ID: "E1", Source: "fixture.regf"}, 5)
		if err == nil && (len(events) > 5 || summary.Parsed != len(events)) {
			t.Fatal("registry projection exceeded its budget", summary)
		}
		for _, event := range events {
			if event.Registry == nil || event.Native == nil || event.ByteOffset < 4096 {
				t.Fatal("registry event lost native identity")
			}
			if _, err := MarshalJSON(event); err != nil {
				t.Fatal("registry event is not serializable", err)
			}
		}
	})
}

func FuzzBinaryPlist(f *testing.F) {
	body, err := plist.Marshal(map[string]any{"Label": "test.agent", "ProgramArguments": []string{"/bin/echo", "Café"}, "RunAtLoad": true}, plist.BinaryFormat)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(body)
	f.Add([]byte("bplist00"))
	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > 256<<10 {
			return
		}
		_, _ = validateBinaryPlist(context.Background(), body)
		path := filepath.Join(t.TempDir(), "fixture.plist")
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
		events, summary, err := parseBinaryLaunchd(context.Background(), path, Item{ID: "E1", Source: "fixture.plist"}, 1)
		if err == nil && (len(events) > 1 || summary.Parsed != len(events)) {
			t.Fatal("binary plist projection exceeded its budget", summary)
		}
		for _, event := range events {
			if event.Launchd == nil || event.Native == nil || event.ByteOffset < 8 {
				t.Fatal("binary plist event lost native identity")
			}
			if _, err := MarshalJSON(event); err != nil {
				t.Fatal("binary plist event is not serializable", err)
			}
		}
	})
}

func FuzzExternalJSON(f *testing.F) {
	for _, body := range []string{`[{"PID":7,"Name":"fixture","__children":[]}]`, `{"Records":[]}`, `[{"PID":1,"PID":2}]`, `[] []`} {
		f.Add([]byte(body))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > 64<<10 {
			return
		}
		if err := validateExternalJSON(body); err == nil && !json.Valid(body) {
			t.Fatal("external JSON validator accepted invalid JSON")
		}
	})
}
