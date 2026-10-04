package core

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

// IDs are the exact little-endian bytes from the record, not resolved paths or
// a cross-volume identity. A journal name alone cannot reconstruct a full path.
type USNReference struct {
	Version      string   `json:"version"`
	USN          string   `json:"usn"`
	FileID       string   `json:"file_id_le_hex"`
	ParentID     string   `json:"parent_id_le_hex"`
	Name         string   `json:"name"`
	Reason       uint32   `json:"reason"`
	Reasons      []string `json:"reasons"`
	SourceInfo   uint32   `json:"source_info"`
	SecurityID   uint32   `json:"security_id"`
	Attributes   uint32   `json:"attributes"`
	RecordLength uint32   `json:"record_length"`
}

func usnCandidate(source string) bool {
	name := strings.ToLower(filepath.Base(strings.ReplaceAll(source, `\`, "/")))
	return strings.HasSuffix(name, ".usn") || name == "$j" || name == "$usnjrnl:$j"
}

func parseUSN(ctx context.Context, name string, item Item, budget int) (events []Event, summary ParseSummary, err error) {
	summary = ParseSummary{Evidence: item.ID, Format: "USN", SkipReasons: map[string]int{}}
	events = []Event{}
	defer func() { summary.Parsed = len(events) }()
	file, err := os.Open(name)
	if err != nil {
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return events, summary, err
	}
	if !info.Mode().IsRegular() || info.Size() != item.Size || info.Size() > workerInputLimit {
		return events, summary, errors.New("invalid USN input size/type")
	}
	reader := bufio.NewReader(&contextReader{ctx: ctx, r: file})
	projectedBytes := 0
	for offset := int64(0); offset < item.Size; {
		if err = ctx.Err(); err != nil {
			return
		}
		var header [8]byte
		count := min(int64(len(header)), item.Size-offset)
		if _, err = io.ReadFull(reader, header[:count]); err != nil {
			return
		}
		if header == [8]byte{} {
			offset += count // Sparse/padding bytes are not journal records.
			continue
		}
		if count != 8 {
			return events, summary, fmt.Errorf("truncated USN header at byte %d", offset)
		}
		length := int64(binary.LittleEndian.Uint32(header[:4]))
		if length < 8 || length%8 != 0 || length > item.Size-offset {
			return events, summary, fmt.Errorf("invalid USN record length at byte %d", offset)
		}
		summary.Rows++
		major, minor := binary.LittleEndian.Uint16(header[4:6]), binary.LittleEndian.Uint16(header[6:8])
		if (major != 2 && major != 3) || minor != 0 {
			if _, err = io.CopyN(io.Discard, reader, length-8); err != nil {
				return
			}
			summary.Skipped++
			summary.SkipReasons["unsupported_usn_version"]++
			offset += length
			continue
		}
		// Filename offset/length are WORD fields; these versions need no larger
		// allocation even if an attacker declares an enormous RecordLength.
		if length > 2*65535+8 {
			return events, summary, fmt.Errorf("invalid USN record extent at byte %d", offset)
		}
		body := make([]byte, int(length))
		copy(body, header[:])
		if _, err = io.ReadFull(reader, body[8:]); err != nil {
			return
		}
		event, reason := decodeUSNRecord(body, item, offset, major)
		if reason != "" {
			summary.Skipped++
			summary.SkipReasons[reason]++
		} else if len(events) >= max(0, budget) {
			summary.Skipped++
			summary.Limited = true
			summary.SkipReasons["event_limit"]++
		} else if size := len(JSON(event)); projectedBytes+size > 8<<20 {
			summary.Skipped++
			summary.Limited = true
			summary.SkipReasons["event_projection_bytes"]++
		} else {
			projectedBytes += size
			events = append(events, event)
		}
		offset += length
	}
	return
}

func decodeUSNRecord(body []byte, item Item, offset int64, major uint16) (Event, string) {
	idBytes := 8
	if major == 3 {
		idBytes = 16
	}
	usnOffset := 8 + 2*idBytes
	headerLength := usnOffset + 36
	if len(body) < headerLength {
		return Event{}, "truncated_usn_fields"
	}
	nameBytes := int(binary.LittleEndian.Uint16(body[usnOffset+32:]))
	nameOffset := int(binary.LittleEndian.Uint16(body[usnOffset+34:]))
	if nameBytes == 0 || nameBytes%2 != 0 || nameOffset%2 != 0 || nameOffset < headerLength || nameOffset > len(body) || nameBytes > len(body)-nameOffset {
		return Event{}, "invalid_usn_filename_extent"
	}
	units := make([]uint16, nameBytes/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(body[nameOffset+2*i:])
	}
	for i := 0; i < len(units); i++ {
		value := units[i]
		if value == 0 {
			return Event{}, "invalid_usn_filename_encoding"
		}
		if value >= 0xd800 && value <= 0xdbff {
			if i+1 >= len(units) || units[i+1] < 0xdc00 || units[i+1] > 0xdfff {
				return Event{}, "invalid_usn_filename_encoding"
			}
			i++
		} else if value >= 0xdc00 && value <= 0xdfff {
			return Event{}, "invalid_usn_filename_encoding"
		}
	}
	name := string(utf16.Decode(units))
	ticks := binary.LittleEndian.Uint64(body[usnOffset+8:])
	stamp := time.Unix(int64(ticks/10000000)-11644473600, int64(ticks%10000000)*100).UTC()
	if ticks == 0 || stamp.Year() < 1 || stamp.Year() > 9999 {
		return Event{}, "unsupported_usn_time"
	}
	usn := int64(binary.LittleEndian.Uint64(body[usnOffset:]))
	if usn < 0 {
		return Event{}, "invalid_usn_number"
	}
	ref := &USNReference{Version: fmt.Sprintf("%d.0", major), USN: strconv.FormatInt(usn, 10),
		FileID: hex.EncodeToString(body[8 : 8+idBytes]), ParentID: hex.EncodeToString(body[8+idBytes : usnOffset]), Name: name,
		Reason: binary.LittleEndian.Uint32(body[usnOffset+16:]), SourceInfo: binary.LittleEndian.Uint32(body[usnOffset+20:]),
		SecurityID: binary.LittleEndian.Uint32(body[usnOffset+24:]), Attributes: binary.LittleEndian.Uint32(body[usnOffset+28:]), RecordLength: uint32(len(body))}
	ref.Reasons = usnReasons(ref.Reason)
	return Event{Time: stamp, OriginalTime: strconv.FormatUint(ticks, 10), Type: "usn_change", Evidence: item.ID, Source: item.Source,
		ByteOffset: offset, Detail: name + " [" + strings.Join(ref.Reasons, ", ") + "]", USN: ref,
		Native: &NativeRecord{Parser: "USN", Table: "USN_RECORD_V" + strconv.Itoa(int(major)), Record: ref.USN,
			TimeField: "TimeStamp", TimeEncoding: "windows_100ns_1601"}}, ""
}

func usnReasons(mask uint32) []string {
	flags := []struct {
		bit  uint32
		name string
	}{
		{0x1, "DATA_OVERWRITE"}, {0x2, "DATA_EXTEND"}, {0x4, "DATA_TRUNCATION"},
		{0x10, "NAMED_DATA_OVERWRITE"}, {0x20, "NAMED_DATA_EXTEND"}, {0x40, "NAMED_DATA_TRUNCATION"},
		{0x100, "FILE_CREATE"}, {0x200, "FILE_DELETE"}, {0x400, "EA_CHANGE"}, {0x800, "SECURITY_CHANGE"},
		{0x1000, "RENAME_OLD_NAME"}, {0x2000, "RENAME_NEW_NAME"}, {0x4000, "INDEXABLE_CHANGE"}, {0x8000, "BASIC_INFO_CHANGE"},
		{0x10000, "HARD_LINK_CHANGE"}, {0x20000, "COMPRESSION_CHANGE"}, {0x40000, "ENCRYPTION_CHANGE"}, {0x80000, "OBJECT_ID_CHANGE"},
		{0x100000, "REPARSE_POINT_CHANGE"}, {0x200000, "STREAM_CHANGE"}, {0x400000, "TRANSACTED_CHANGE"}, {0x800000, "INTEGRITY_CHANGE"},
		{0x80000000, "CLOSE"},
	}
	out := []string{}
	for _, flag := range flags {
		if mask&flag.bit != 0 {
			out = append(out, flag.name)
			mask &^= flag.bit
		}
	}
	if mask != 0 {
		out = append(out, fmt.Sprintf("UNKNOWN_0x%08x", mask))
	}
	return out
}

func exportUSN(ctx context.Context, events []Event, out string) error {
	return writeCSVNew(filepath.Join(out, "usn.csv"), func(c *csv.Writer) error {
		if err := c.Write([]string{"evidence_id", "source", "byte_offset", "version", "usn", "time_utc", "filetime", "file_id_le_hex", "parent_id_le_hex", "name", "reason_mask", "reasons", "source_info", "security_id", "attributes", "record_length"}); err != nil {
			return err
		}
		for _, event := range events {
			if err := ctx.Err(); err != nil {
				return err
			}
			r := event.USN
			if r == nil {
				continue
			}
			if err := c.Write([]string{event.Evidence, csvSafe(event.Source), strconv.FormatInt(event.ByteOffset, 10), r.Version, r.USN, event.Time.Format(time.RFC3339Nano), event.OriginalTime,
				r.FileID, r.ParentID, csvSafe(r.Name), fmt.Sprintf("0x%08x", r.Reason), strings.Join(r.Reasons, "|"), fmt.Sprintf("0x%08x", r.SourceInfo), strconv.FormatUint(uint64(r.SecurityID), 10), fmt.Sprintf("0x%08x", r.Attributes), strconv.FormatUint(uint64(r.RecordLength), 10)}); err != nil {
				return err
			}
		}
		return nil
	})
}
