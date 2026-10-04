package core

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"howett.net/plist"
)

func TestNativeBinaryLaunchdProjectionAndBounds(t *testing.T) {
	fields := map[string]any{"Label": "test.agent", "ProgramArguments": []string{"/bin/echo", "Café"}, "UserName": "user", "RunAtLoad": true, "KeepAlive": map[string]any{"SuccessfulExit": false}}
	body, err := plist.Marshal(fields, plist.BinaryFormat)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "agent.plist")
	if err = os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	events, summary, err := parseBinaryLaunchd(context.Background(), path, Item{ID: "E1", Source: "agent.plist"}, 10)
	if err != nil || len(events) != 1 || events[0].Launchd.Arguments[1] != "Café" || events[0].Launchd.OmittedProperties != 1 || events[0].ByteOffset < 8 {
		t.Fatal(events, summary, err)
	}
	_, summary, err = parseBinaryLaunchd(context.Background(), path, Item{ID: "E1"}, 0)
	if err != nil || !summary.Limited || summary.Skipped != 1 {
		t.Fatal(summary, err)
	}
	body[len(body)-32+7] = 0
	if _, err = validateBinaryPlist(context.Background(), body); err == nil {
		t.Fatal("zero reference width accepted")
	}
}

func TestBinaryLaunchdDisclosesUnsupportedKnownStringProperties(t *testing.T) {
	body, err := plist.Marshal(map[string]any{"Label": "test.agent", "Program": 7, "ProgramArguments": []string{"/bin/echo"}, "UserName": strings.Repeat("u", 4097)}, plist.BinaryFormat)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "agent.plist")
	if err = os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	events, summary, err := parseBinaryLaunchd(context.Background(), path, Item{ID: "E1"}, 10)
	if err != nil || len(events) != 1 || events[0].Launchd.OmittedProperties != 2 || summary.SkipReasons["unsupported_string_property"] != 2 {
		t.Fatal("unsupported known fields were silently omitted", events, summary, err)
	}
	rows := analysisCoverage(Analysis{ParseSummaries: []ParseSummary{summary}})
	for _, row := range rows {
		if row.Format == "BinaryPlist" && row.Status != "partial" {
			t.Fatal("property omissions presented as complete", row)
		}
	}
}

func TestBinaryPlistRejectsCyclesAndExpandedDAG(t *testing.T) {
	build := func(objects [][]byte) []byte {
		body := []byte("bplist00")
		offsets := []byte{}
		for _, object := range objects {
			offsets = append(offsets, byte(len(body)))
			body = append(body, object...)
		}
		table := len(body)
		body = append(body, offsets...)
		trailer := make([]byte, 32)
		trailer[6] = 1
		trailer[7] = 1
		binary.BigEndian.PutUint64(trailer[8:16], uint64(len(objects)))
		binary.BigEndian.PutUint64(trailer[16:24], uint64(len(objects)-1))
		binary.BigEndian.PutUint64(trailer[24:], uint64(table))
		return append(body, trailer...)
	}
	cycle := build([][]byte{{0xa1, 0}})
	if _, err := validateBinaryPlist(context.Background(), cycle); err == nil {
		t.Fatal("cycle accepted")
	}
	objects := [][]byte{{0x08}}
	for i := 1; i < 30; i++ {
		objects = append(objects, []byte{0xa2, byte(i - 1), byte(i - 1)})
	}
	if _, err := validateBinaryPlist(context.Background(), build(objects)); err == nil {
		t.Fatal("exponentially expanded graph accepted")
	}
}
