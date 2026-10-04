package core

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

type RegistryValue struct {
	Name           string `json:"name"`
	Type           uint32 `json:"type"`
	CellOffset     int64  `json:"cell_offset"`
	DataBytes      uint32 `json:"data_bytes"`
	DataSHA256     string `json:"data_sha256,omitempty"`
	RawData        string `json:"raw_data_base64,omitempty"`
	Text           string `json:"text,omitempty"`
	Number         string `json:"number,omitempty"`
	Omitted        bool   `json:"omitted"`
	OmissionReason string `json:"omission_reason,omitempty"`
}
type RegistryReference struct {
	Key                    string          `json:"key"`
	Filetime               string          `json:"last_write_filetime"`
	Values                 []RegistryValue `json:"values"`
	ValuesOmitted          uint32          `json:"values_omitted"`
	VolatileSubkeysOmitted uint32          `json:"volatile_subkeys_omitted"`
}

func registryName(body []byte, compressed bool) (string, error) {
	if len(body) > 4096 {
		return "", errors.New("registry string exceeds bounds")
	}
	if compressed {
		runes := make([]rune, len(body))
		for i, v := range body {
			runes[i] = rune(v)
		}
		return string(runes), nil
	}
	if len(body)%2 != 0 {
		return "", errors.New("invalid registry UTF-16 length")
	}
	units := make([]uint16, len(body)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(body[i*2:])
	}
	for i := 0; i < len(units); i++ {
		u := units[i]
		if u >= 0xd800 && u <= 0xdbff {
			if i+1 >= len(units) || units[i+1] < 0xdc00 || units[i+1] > 0xdfff {
				return "", errors.New("invalid registry Unicode surrogate")
			}
			i++
		} else if u >= 0xdc00 && u <= 0xdfff {
			return "", errors.New("invalid registry Unicode surrogate")
		}
	}
	return string(utf16.Decode(units)), nil
}

func registryCells(ctx context.Context, body []byte) (map[uint32][]byte, error) {
	if len(body) < 8192 || len(body) > workerInputLimit || !bytes.Equal(body[:4], []byte("regf")) {
		return nil, errors.New("invalid registry hive header/size")
	}
	u32 := binary.LittleEndian.Uint32
	if u32(body[4:]) != u32(body[8:]) {
		return nil, errors.New("dirty registry hive requires independently recovered transaction logs")
	}
	if u32(body[20:]) != 1 || u32(body[24:]) < 3 || u32(body[24:]) > 6 || u32(body[28:]) != 0 || u32(body[32:]) != 1 || uint64(u32(body[40:]))+4096 != uint64(len(body)) {
		return nil, errors.New("unsupported registry hive version/layout")
	}
	var checksum uint32
	for offset := 0; offset < 508; offset += 4 {
		checksum ^= u32(body[offset:])
	}
	if checksum == 0 {
		checksum = 1
	}
	if checksum == 0xffffffff {
		checksum = 0xfffffffe
	}
	if checksum != u32(body[508:]) {
		return nil, errors.New("registry header checksum mismatch")
	}
	cells := map[uint32][]byte{}
	for bin := 4096; bin < len(body); {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if len(body)-bin < 32 || !bytes.Equal(body[bin:bin+4], []byte("hbin")) || int64(u32(body[bin+4:])) != int64(bin-4096) {
			return nil, errors.New("invalid registry hive bin")
		}
		size := int64(u32(body[bin+8:]))
		if size < 4096 || size%4096 != 0 || size > int64(len(body)-bin) {
			return nil, errors.New("invalid registry hive bin extent")
		}
		end := bin + int(size)
		for offset := bin + 32; offset < end; {
			if end-offset < 4 {
				return nil, errors.New("truncated registry cell")
			}
			signed := int32(u32(body[offset:]))
			extent := int64(signed)
			if extent < 0 {
				extent = -extent
			}
			if extent < 8 || extent%8 != 0 || extent > int64(end-offset) {
				return nil, errors.New("invalid registry cell extent")
			}
			if signed < 0 {
				if len(cells) >= 250000 {
					return nil, errors.New("registry allocated cell limit")
				}
				cells[uint32(offset-4096)] = body[offset+4 : offset+int(extent)]
			}
			offset += int(extent)
		}
		bin = end
	}
	return cells, nil
}

func registrySubkeys(cells map[uint32][]byte, index uint32, expected uint32) ([]uint32, error) {
	if expected == 0 {
		return nil, nil
	}
	if expected > 20000 {
		return nil, errors.New("registry subkey count limit")
	}
	queue := []uint32{index}
	seen := map[uint32]bool{}
	keys := []uint32{}
	for len(queue) > 0 {
		current := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		if seen[current] || len(seen) >= 20000 {
			return nil, errors.New("registry subkey index cycle/limit")
		}
		seen[current] = true
		cell, ok := cells[current]
		if !ok || len(cell) < 4 {
			return nil, errors.New("missing registry subkey index")
		}
		signature := string(cell[:2])
		count := int(binary.LittleEndian.Uint16(cell[2:]))
		stride := 4
		if signature == "lf" || signature == "lh" {
			stride = 8
		} else if signature != "li" && signature != "ri" {
			return nil, errors.New("unsupported registry subkey index")
		}
		if count > (len(cell)-4)/stride {
			return nil, errors.New("truncated registry subkey index")
		}
		for i := 0; i < count; i++ {
			ref := binary.LittleEndian.Uint32(cell[4+i*stride:])
			if signature == "ri" {
				queue = append(queue, ref)
			} else {
				keys = append(keys, ref)
			}
			if len(queue)+len(keys) > 20000 {
				return nil, errors.New("registry subkey expansion limit")
			}
		}
	}
	if len(keys) != int(expected) {
		return nil, errors.New("registry subkey count mismatch")
	}
	return keys, nil
}

func registryValue(cells map[uint32][]byte, offset uint32) (value RegistryValue, err error) {
	cell, ok := cells[offset]
	if !ok || len(cell) < 20 || string(cell[:2]) != "vk" {
		return value, errors.New("invalid registry value cell")
	}
	nameBytes := int(binary.LittleEndian.Uint16(cell[2:]))
	if nameBytes > len(cell)-20 {
		return value, errors.New("truncated registry value name")
	}
	value.Name, err = registryName(cell[20:20+nameBytes], binary.LittleEndian.Uint16(cell[16:])&1 != 0)
	if err != nil {
		return value, err
	}
	length := binary.LittleEndian.Uint32(cell[4:])
	inline := length&0x80000000 != 0
	length &= 0x7fffffff
	value.Type = binary.LittleEndian.Uint32(cell[12:])
	value.CellOffset = int64(offset) + 4100
	value.DataBytes = length
	var data []byte
	if inline {
		if length > 4 {
			return value, errors.New("invalid inline registry value")
		}
		data = cell[8 : 8+length]
	} else if length > 0 {
		stored, exists := cells[binary.LittleEndian.Uint32(cell[8:])]
		if !exists || uint64(length) > uint64(len(stored)) || length > 16344 {
			value.Omitted = true
			value.OmissionReason = "unsupported_or_missing_data_extent"
			return value, nil
		}
		data = stored[:length]
	}
	value.DataSHA256 = digestBytes(data)
	if len(data) > 4096 {
		value.Omitted = true
		value.OmissionReason = "value_data_projection_limit"
		return value, nil
	}
	value.RawData = base64.StdEncoding.EncodeToString(data)
	switch value.Type {
	case 1, 2:
		value.Text, err = registryName(data, false)
		value.Text = strings.TrimSuffix(value.Text, "\x00")
	case 4:
		if len(data) != 4 {
			err = errors.New("invalid REG_DWORD length")
		} else {
			value.Number = strconv.FormatUint(uint64(binary.LittleEndian.Uint32(data)), 10)
		}
	case 5:
		if len(data) != 4 {
			err = errors.New("invalid REG_DWORD_BIG_ENDIAN length")
		} else {
			value.Number = strconv.FormatUint(uint64(binary.BigEndian.Uint32(data)), 10)
		}
	case 11:
		if len(data) != 8 {
			err = errors.New("invalid REG_QWORD length")
		} else {
			value.Number = strconv.FormatUint(binary.LittleEndian.Uint64(data), 10)
		}
	}
	return value, err
}

func parseRegistry(ctx context.Context, path string, item Item, budget int) (events []Event, summary ParseSummary, err error) {
	summary = ParseSummary{Evidence: item.ID, Format: "Registry", SkipReasons: map[string]int{}}
	events = []Event{}
	defer func() { summary.Parsed = len(events) }()
	body, err := ReadLimited(path, workerInputLimit)
	if err != nil {
		return events, summary, err
	}
	cells, err := registryCells(ctx, body)
	if err != nil {
		return events, summary, err
	}
	type keyRef struct {
		offset       uint32
		parent       string
		depth        int
		parentOffset uint32
	}
	queue := []keyRef{{offset: binary.LittleEndian.Uint32(body[36:])}}
	seen := map[uint32]bool{}
	valueBytes, eventBytes := 0, 0
	for len(queue) > 0 {
		if err = ctx.Err(); err != nil {
			return events, summary, err
		}
		if summary.Rows >= 20000 {
			summary.Limited = true
			break
		}
		ref := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		if seen[ref.offset] || ref.depth > 64 {
			return events, summary, errors.New("registry key tree cycle/depth limit")
		}
		seen[ref.offset] = true
		cell, ok := cells[ref.offset]
		if !ok || len(cell) < 76 || string(cell[:2]) != "nk" {
			return events, summary, errors.New("invalid registry key cell")
		}
		if ref.depth > 0 && binary.LittleEndian.Uint32(cell[16:]) != ref.parentOffset {
			return events, summary, errors.New("registry child/parent binding mismatch")
		}
		nameLength := int(binary.LittleEndian.Uint16(cell[72:]))
		if nameLength > len(cell)-76 {
			return events, summary, errors.New("truncated registry key name")
		}
		name, e := registryName(cell[76:76+nameLength], binary.LittleEndian.Uint16(cell[2:])&0x20 != 0)
		if e != nil {
			return events, summary, e
		}
		key := name
		if ref.parent != "" {
			key = ref.parent + "\\" + name
		}
		if len(key) > 4096 {
			return events, summary, errors.New("registry key path limit")
		}
		summary.Rows++
		volatile := binary.LittleEndian.Uint32(cell[24:])
		if volatile > 0 {
			summary.SkipReasons["volatile_subkeys_unsupported"]++
		}
		children, e := registrySubkeys(cells, binary.LittleEndian.Uint32(cell[28:]), binary.LittleEndian.Uint32(cell[20:]))
		if e != nil {
			return events, summary, e
		}
		for i := len(children) - 1; i >= 0; i-- {
			if len(queue) >= 20000 {
				summary.Limited = true
				summary.SkipReasons["key_queue_limit"]++
				break
			}
			queue = append(queue, keyRef{children[i], key, ref.depth + 1, ref.offset})
		}
		if len(events) >= max(0, budget) {
			summary.Skipped++
			summary.Limited = true
			summary.SkipReasons["event_limit"]++
			continue
		}
		ticks := binary.LittleEndian.Uint64(cell[4:])
		stamp := time.Unix(int64(ticks/10000000)-11644473600, int64(ticks%10000000)*100).UTC()
		if ticks == 0 || stamp.Year() < 1 || stamp.Year() > 9999 {
			summary.Skipped++
			summary.SkipReasons["unsupported_last_write_time"]++
			continue
		}
		values := []RegistryValue{}
		count := binary.LittleEndian.Uint32(cell[36:])
		omitted := uint32(0)
		if count > 0 {
			list, ok := cells[binary.LittleEndian.Uint32(cell[40:])]
			if !ok || uint64(count)*4 > uint64(len(list)) {
				return events, summary, errors.New("truncated registry value list")
			}
			for i := uint32(0); i < count; i++ {
				if i >= 256 || valueBytes >= 1<<20 {
					omitted = count - i
					summary.SkipReasons["value_projection_limit"]++
					break
				}
				value, e := registryValue(cells, binary.LittleEndian.Uint32(list[i*4:]))
				if e != nil {
					omitted++
					summary.SkipReasons["unsupported_value"]++
					continue
				}
				if value.Omitted {
					summary.SkipReasons[value.OmissionReason]++
				}
				valueBytes += len(JSON(value))
				values = append(values, value)
			}
		}
		filetime := strconv.FormatUint(ticks, 10)
		event := Event{Time: stamp, OriginalTime: filetime, Type: "registry_key_modified", Evidence: item.ID, Source: item.Source, Detail: key, ByteOffset: int64(ref.offset) + 4100, Native: &NativeRecord{Parser: "registry", Record: fmt.Sprintf("nk@%d", int64(ref.offset)+4100), TimeField: "last_write", TimeEncoding: "Windows FILETIME 100ns"}, Registry: &RegistryReference{Key: key, Filetime: filetime, Values: values, ValuesOmitted: omitted, VolatileSubkeysOmitted: volatile}}
		size := len(JSON(event))
		if eventBytes+size > 8<<20 {
			summary.Skipped++
			summary.Limited = true
			summary.SkipReasons["event_projection_bytes"]++
			continue
		}
		eventBytes += size
		events = append(events, event)
	}
	summary.Parsed = len(events)
	return events, summary, nil
}
