package core

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeCaseExactFilters(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "index.sqlite")
	w, err := newCaseIndex(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer w.close()
	for _, digest := range []string{strings.Repeat("a", 64), strings.Repeat("b", 64)} {
		event := Event{Native: &NativeRecord{Parser: "USN", Record: "4096"}, USN: &USNReference{FileID: "abcdef0123456789"}}
		if err := w.add(ctx, CaseRow{Kind: "event", Digest: digest, Evidence: "E1", Payload: JSON(event)}, caseEventSearchText(event)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.finish(); err != nil {
		t.Fatal(err)
	}
	q := CaseQuery{Limit: 10, NativeParser: "USN", NativeRecord: "4096", USNFileID: "ABCDEF0123456789", Digest: strings.Repeat("a", 64), Evidence: "E1"}
	page, err := QueryCase(ctx, path, q)
	if err != nil || len(page.Rows) != 1 {
		t.Fatalf("scoped exact lookup: %+v %v", page, err)
	}
	q.NativeRecord = "409"
	page, err = QueryCase(ctx, path, q)
	if err != nil || len(page.Rows) != 0 {
		t.Fatalf("record prefix matched: %+v %v", page, err)
	}
	q.NativeRecord = "' OR 1=1 --"
	page, err = QueryCase(ctx, path, q)
	if err != nil || len(page.Rows) != 0 {
		t.Fatalf("literal record failed: %+v %v", page, err)
	}
	for _, invalid := range []CaseQuery{{Limit: 1, USNFileID: "abc"}, {Limit: 1, USNFileID: "zzzzzzzzzzzzzzzz"}, {Limit: 1, Kind: "finding", NativeParser: "USN"}, {Limit: 1, NativeRecord: strings.Repeat("x", 257)}} {
		if _, err := QueryCase(ctx, path, invalid); err == nil {
			t.Fatalf("invalid filter accepted: %+v", invalid)
		}
	}
}

func TestUSNVersionsAndPartialInput(t *testing.T) {
	for _, version := range []uint16{2, 3} {
		offset := 24
		if version == 3 {
			offset = 40
		}
		header := offset + 36
		body := make([]byte, (header+2+7)&^7)
		binary.LittleEndian.PutUint32(body, uint32(len(body)))
		binary.LittleEndian.PutUint16(body[4:], version)
		body[8] = 1
		binary.LittleEndian.PutUint64(body[offset:], 4096)
		binary.LittleEndian.PutUint64(body[offset+8:], 13348540800000000)
		binary.LittleEndian.PutUint32(body[offset+16:], 0x100)
		binary.LittleEndian.PutUint16(body[offset+32:], 2)
		binary.LittleEndian.PutUint16(body[offset+34:], uint16(header))
		binary.LittleEndian.PutUint16(body[header:], 'A')
		name := filepath.Join(t.TempDir(), "journal.usn")
		if err := os.WriteFile(name, body, 0600); err != nil {
			t.Fatal(err)
		}
		item := Item{ID: "E1", Source: "journal.usn", Size: int64(len(body))}
		events, summary, err := parseUSN(context.Background(), name, item, 10)
		if err != nil || summary.Parsed != 1 || len(events) != 1 {
			t.Fatalf("v%d: %+v %v", version, summary, err)
		}
		if events[0].USN.Name != "A" || events[0].Native.Record != "4096" || len(events[0].USN.FileID) != int(version-1)*16 {
			t.Fatal(events[0])
		}
		groups := usnFileGroups(append(events, events...))
		if len(groups) != 1 || groups[0].Records != 2 || len(groups[0].References) != 2 {
			t.Fatal(groups)
		}
		other := events[0]
		other.Evidence = "E2"
		if len(usnFileGroups(append(events, other))) != 2 {
			t.Fatal("cross-evidence grouping")
		}
		_, summary, err = parseUSN(context.Background(), name, item, 0)
		if err != nil || summary.Skipped != 1 || !summary.Limited {
			t.Fatalf("missing limit disclosure: %+v %v", summary, err)
		}
		corrupt := append(append([]byte{}, body...), 1)
		if err := os.WriteFile(name, corrupt, 0600); err != nil {
			t.Fatal(err)
		}
		item.Size = int64(len(corrupt))
		events, _, err = parseUSN(context.Background(), name, item, 10)
		if err == nil || len(events) != 1 {
			t.Fatal("partial records were lost or truncation concealed")
		}
	}
}
