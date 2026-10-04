package core

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"howett.net/plist"
)

type LaunchdReference struct {
	Label             string   `json:"label"`
	Program           string   `json:"program,omitempty"`
	Arguments         []string `json:"arguments,omitempty"`
	User              string   `json:"user_name,omitempty"`
	RunAtLoad         *bool    `json:"run_at_load,omitempty"`
	Disabled          *bool    `json:"disabled,omitempty"`
	OmittedProperties int      `json:"omitted_properties"`
}

// Validate the object graph before the general decoder sees untrusted lengths
// or cycles. This parser supports bounded bplist00 dictionaries, not arbitrary
// keyed archives or recursive object graphs.
func validateBinaryPlist(ctx context.Context, body []byte) (rootOffset int64, err error) {
	if len(body) < 40 || len(body) > 8<<20 || !bytes.Equal(body[:8], []byte("bplist00")) {
		return 0, errors.New("unsupported binary plist header/size")
	}
	trailer := body[len(body)-32:]
	width, refWidth := int(trailer[6]), int(trailer[7])
	count, root, table := binary.BigEndian.Uint64(trailer[8:16]), binary.BigEndian.Uint64(trailer[16:24]), binary.BigEndian.Uint64(trailer[24:])
	if width < 1 || width > 8 || refWidth < 1 || refWidth > 8 || count == 0 || count > 10000 || root >= count || table < 8 || table > uint64(len(body)-32) || count*uint64(width) > uint64(len(body)-32)-table {
		return 0, errors.New("invalid binary plist trailer")
	}
	readInt := func(b []byte) uint64 {
		var n uint64
		for _, v := range b {
			n = n<<8 | uint64(v)
		}
		return n
	}
	offsets := make([]int, count)
	seen := map[int]bool{}
	for i := range offsets {
		offset := readInt(body[int(table)+i*width : int(table)+(i+1)*width])
		if offset < 8 || offset >= table || seen[int(offset)] {
			return 0, errors.New("invalid or duplicate binary plist object offset")
		}
		offsets[i] = int(offset)
		seen[int(offset)] = true
	}
	sorted := append([]int(nil), offsets...)
	sort.Ints(sorted)
	ends := map[int]int{}
	for i, offset := range sorted {
		end := int(table)
		if i+1 < len(sorted) {
			end = sorted[i+1]
		}
		ends[offset] = end
	}
	refs := make([][]int, count)
	references := 0
	stringsByObject := map[int]string{}
	dictionaries := map[int]int{}
	for object, offset := range offsets {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		kind, small := body[offset]>>4, int(body[offset]&15)
		cursor := offset + 1
		length := uint64(small)
		if small == 15 && (kind == 4 || kind == 5 || kind == 6 || kind == 10 || kind == 12 || kind == 13) {
			if cursor >= ends[offset] || body[cursor]>>4 != 1 || body[cursor]&15 > 3 {
				return 0, errors.New("invalid extended plist length")
			}
			size := 1 << uint(body[cursor]&15)
			cursor++
			if size > ends[offset]-cursor {
				return 0, errors.New("truncated plist length")
			}
			length = readInt(body[cursor : cursor+size])
			cursor += size
		}
		var extent uint64
		switch kind {
		case 0:
			if small != 0 && small != 8 && small != 9 && small != 15 {
				return 0, errors.New("unsupported plist singleton")
			}
		case 1:
			if small > 3 {
				return 0, errors.New("unsupported oversized plist integer")
			}
			extent = 1 << uint(small)
		case 2:
			if small != 2 && small != 3 {
				return 0, errors.New("unsupported plist real")
			}
			extent = 1 << uint(small)
		case 3:
			if small != 3 {
				return 0, errors.New("unsupported plist date")
			}
			extent = 8
		case 4, 5:
			if length > 1<<20 {
				return 0, errors.New("plist data/string limit")
			}
			extent = length
		case 6:
			if length > 65536 {
				return 0, errors.New("plist Unicode string limit")
			}
			extent = length * 2
		case 8:
			if small > 7 {
				return 0, errors.New("oversized plist UID")
			}
			extent = uint64(small + 1)
		case 10, 12, 13:
			if length > 4096 {
				return 0, errors.New("plist collection limit")
			}
			items := length
			if kind == 13 {
				items *= 2
			}
			extent = items * uint64(refWidth)
			if extent > uint64(ends[offset]-cursor) {
				return 0, errors.New("truncated plist references")
			}
			for i := uint64(0); i < items; i++ {
				ref := readInt(body[cursor+int(i)*refWidth : cursor+int(i+1)*refWidth])
				if ref >= count {
					return 0, errors.New("invalid plist object reference")
				}
				refs[object] = append(refs[object], int(ref))
				references++
			}
		default:
			return 0, errors.New("unsupported binary plist object kind")
		}
		if extent > uint64(ends[offset]-cursor) || references > 100000 {
			return 0, errors.New("plist object extent/reference limit")
		}
		if kind == 5 {
			value := body[cursor : cursor+int(extent)]
			for _, v := range value {
				if v > 127 {
					return 0, errors.New("non-ASCII byte in ASCII plist string")
				}
			}
			stringsByObject[object] = string(value)
		}
		if kind == 6 {
			units := make([]uint16, int(length))
			for i := range units {
				units[i] = binary.BigEndian.Uint16(body[cursor+i*2 : cursor+i*2+2])
			}
			for i := 0; i < len(units); i++ {
				u := units[i]
				if u >= 0xd800 && u <= 0xdbff {
					if i+1 >= len(units) || units[i+1] < 0xdc00 || units[i+1] > 0xdfff {
						return 0, errors.New("invalid plist Unicode surrogate")
					}
					i++
				} else if u >= 0xdc00 && u <= 0xdfff {
					return 0, errors.New("invalid plist Unicode surrogate")
				}
			}
			value := string(utf16.Decode(units))
			if !utf8.ValidString(value) {
				return 0, errors.New("invalid plist Unicode")
			}
			stringsByObject[object] = value
		}
		if kind == 13 {
			dictionaries[object] = int(length)
		}
	}
	for object, length := range dictionaries {
		keys := map[string]bool{}
		for _, ref := range refs[object][:length] {
			key, ok := stringsByObject[ref]
			if !ok || keys[key] {
				return 0, errors.New("non-string or duplicate binary plist dictionary key")
			}
			keys[key] = true
		}
	}
	state := make([]byte, count)
	heights := make([]int, count)
	weights := make([]int64, count)
	var visit func(int, int) error
	visit = func(index, depth int) error {
		if depth > 32 || state[index] == 1 {
			return errors.New("binary plist cycle/depth limit")
		}
		if state[index] == 2 {
			if depth+heights[index] > 32 {
				return errors.New("binary plist depth limit")
			}
			return nil
		}
		state[index] = 1
		weights[index] = 1
		for _, ref := range refs[index] {
			if err := visit(ref, depth+1); err != nil {
				return err
			}
			heights[index] = max(heights[index], heights[ref]+1)
			weights[index] += weights[ref]
			if weights[index] > 50000 {
				return errors.New("binary plist expanded object graph limit")
			}
		}
		state[index] = 2
		if depth+heights[index] > 32 {
			return errors.New("binary plist depth limit")
		}
		return nil
	}
	for i := range offsets {
		if err := visit(i, 0); err != nil {
			return 0, err
		}
	}
	return int64(offsets[root]), nil
}

func parseBinaryLaunchd(ctx context.Context, path string, item Item, budget int) (events []Event, summary ParseSummary, err error) {
	summary = ParseSummary{Evidence: item.ID, Format: "BinaryPlist", Rows: 1, SkipReasons: map[string]int{}}
	defer func() {
		if recover() != nil {
			err = errors.New("binary plist decoder rejected malformed input")
		}
	}()
	body, err := ReadLimited(path, 8<<20)
	if err != nil {
		return nil, summary, err
	}
	offset, err := validateBinaryPlist(ctx, body)
	if err != nil {
		return nil, summary, err
	}
	var values map[string]any
	if _, err = plist.Unmarshal(body, &values); err != nil {
		return nil, summary, err
	}
	omittedStrings := 0
	text := func(key string) string {
		raw, exists := values[key]
		if !exists {
			return ""
		}
		value, valid := raw.(string)
		if !valid || len(value) > 4096 {
			omittedStrings++
			summary.SkipReasons["unsupported_string_property"]++
			return ""
		}
		return value
	}
	label, program, user := text("Label"), text("Program"), text("UserName")
	var args []string
	if raw, exists := values["ProgramArguments"]; exists {
		if _, ok := raw.([]any); !ok {
			return nil, summary, errors.New("launchd ProgramArguments must be a string array")
		}
	}
	if raw, ok := values["ProgramArguments"].([]any); ok {
		if len(raw) > 32 {
			return nil, summary, errors.New("launchd argument count limit")
		}
		for _, value := range raw {
			arg, ok := value.(string)
			if !ok || len(arg) > 4096 {
				return nil, summary, errors.New("unsupported launchd argument")
			}
			args = append(args, arg)
		}
	}
	if label == "" || (program == "" && len(args) == 0) {
		summary.Skipped = 1
		summary.SkipReasons["not_supported_launchd_dictionary"] = 1
		return nil, summary, nil
	}
	if budget <= 0 {
		summary.Limited = true
		summary.Skipped = 1
		summary.SkipReasons["event_limit"] = 1
		return nil, summary, nil
	}
	boolean := func(key string) *bool {
		if value, ok := values[key].(bool); ok {
			return &value
		}
		return nil
	}
	ref := &LaunchdReference{Label: label, Program: program, Arguments: args, User: user, RunAtLoad: boolean("RunAtLoad"), Disabled: boolean("Disabled"), OmittedProperties: omittedStrings}
	for _, key := range []string{"RunAtLoad", "Disabled"} {
		if raw, exists := values[key]; exists {
			if _, ok := raw.(bool); !ok {
				return nil, summary, errors.New("unsupported launchd boolean property")
			}
		}
	}
	command := program
	if command == "" {
		command = args[0]
	}
	detail := fmt.Sprintf("%s: %s; argv=%s", label, command, strings.Join(args, " "))
	events = []Event{{Time: evidenceTime(item), Type: eventLaunchAgent, Evidence: item.ID, Source: item.Source, User: user, Detail: detail, ByteOffset: offset, Native: &NativeRecord{Parser: "binaryplist", Record: "root_object", TimeField: "file_metadata", TimeEncoding: "UTC projection"}, Launchd: ref}}
	summary.Parsed = 1
	known := map[string]bool{"Label": true, "Program": true, "ProgramArguments": true, "UserName": true, "RunAtLoad": true, "Disabled": true}
	for key := range values {
		if !known[key] {
			ref.OmittedProperties++
		}
	}
	if ref.OmittedProperties > omittedStrings {
		summary.SkipReasons["unprojected_properties"] = ref.OmittedProperties - omittedStrings
	}
	return events, summary, nil
}
