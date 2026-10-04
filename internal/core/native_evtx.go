package core

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	evtx "www.velocidex.com/golang/evtx"
)

func parseEVTX(ctx context.Context, path string, it Item, budget int) (events []Event, summary ParseSummary, err error) {
	summary = ParseSummary{Evidence: it.ID, Format: "EVTX", SkipReasons: map[string]int{}}
	events = []Event{}
	defer func() {
		if recovered := recover(); recovered != nil {
			err = errors.New("EVTX parser rejected malformed binary XML")
		}
	}()
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return
	}
	header := make([]byte, 128)
	if _, err = f.ReadAt(header, 0); err != nil {
		return
	}
	if !bytes.Equal(header[:8], []byte("ElfFile\x00")) || binary.LittleEndian.Uint16(header[40:42]) != 4096 || binary.LittleEndian.Uint16(header[38:40]) != 3 || binary.LittleEndian.Uint16(header[36:38]) > 2 || info.Size() < 4096 || info.Size() > workerInputLimit {
		return events, summary, errors.New("unsupported or invalid EVTX header")
	}
	if (info.Size()-4096)%65536 != 0 {
		return events, summary, errors.New("truncated EVTX chunk")
	}
	if crc32.ChecksumIEEE(header[:120]) != binary.LittleEndian.Uint32(header[124:128]) {
		return events, summary, errors.New("EVTX file header checksum mismatch")
	}
	for offset := int64(4096); offset < info.Size(); offset += 65536 {
		if err = ctx.Err(); err != nil {
			return
		}
		if len(events) >= budget {
			summary.Limited = true
			break
		}
		block := make([]byte, 65536)
		if _, e := f.ReadAt(block, offset); e != nil {
			return events, summary, e
		}
		if bytes.Equal(block, make([]byte, 65536)) {
			continue
		}
		free := int(binary.LittleEndian.Uint32(block[48:52]))
		if free < 512 || free > len(block) {
			return events, summary, errors.New("invalid EVTX free-space offset")
		}
		check := crc32.NewIEEE()
		check.Write(block[:120])
		check.Write(block[128:512])
		if check.Sum32() != binary.LittleEndian.Uint32(block[124:128]) || crc32.ChecksumIEEE(block[512:free]) != binary.LittleEndian.Uint32(block[52:56]) {
			return events, summary, errors.New("EVTX chunk checksum mismatch")
		}
		chunk, e := evtx.NewChunk(f, offset)
		if e != nil || string(chunk.Header.Magic[:]) != "ElfChnk\x00" {
			return events, summary, errors.New("invalid EVTX chunk header")
		}
		if chunk.Header.LastEventRecID == ^uint64(0) {
			continue
		}
		if chunk.Header.LastEventRecNumber < chunk.Header.FirstEventRecNumber || chunk.Header.LastEventRecNumber-chunk.Header.FirstEventRecNumber > 10000 {
			return events, summary, errors.New("EVTX chunk record count exceeds bounds")
		}
		records, e := chunk.Parse(0)
		if e != nil {
			return events, summary, e
		}
		if uint64(len(records)) != chunk.Header.LastEventRecNumber-chunk.Header.FirstEventRecNumber+1 {
			return events, summary, errors.New("EVTX chunk records are incomplete")
		}
		recordOffset := offset + 512
		for _, record := range records {
			if record.Header.Size < 28 || recordOffset+int64(record.Header.Size) > offset+65536 {
				return events, summary, errors.New("invalid EVTX record extent")
			}
			end := int(recordOffset-offset) + int(record.Header.Size)
			if end > free || binary.LittleEndian.Uint32(block[end-4:end]) != record.Header.Size {
				return events, summary, errors.New("EVTX record trailer mismatch")
			}
			if len(events) >= budget {
				summary.Limited = true
				break
			}
			summary.Rows++
			event, e := nativeEVTXEvent(record, it, recordOffset)
			recordOffset += int64(record.Header.Size)
			if e != nil {
				summary.Skipped++
				summary.SkipReasons["unsupported_event_payload"]++
				continue
			}
			events = append(events, event)
			summary.Parsed++
		}
	}
	return
}

func nativeEVTXEvent(record *evtx.EventRecord, it Item, offset int64) (Event, error) {
	body, e := json.Marshal(record.Event)
	if e != nil || len(body) > 256<<10 {
		return Event{}, errors.New("EVTX payload exceeds bounds")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var root map[string]any
	if e = dec.Decode(&root); e != nil {
		return Event{}, e
	}
	if wrapped, ok := root["Event"].(map[string]any); ok {
		root = wrapped
	}
	system, ok := root["System"].(map[string]any)
	if !ok {
		return Event{}, errors.New("missing EVTX System")
	}
	provider, _ := system["Provider"].(map[string]any)
	idValue := system["EventID"]
	if wrapped, ok := idValue.(map[string]any); ok {
		idValue = wrapped["Value"]
	}
	id, e := strconv.ParseUint(nativeScalar(idValue), 10, 16)
	if e != nil || provider == nil {
		return Event{}, errors.New("invalid EVTX event identity")
	}
	if record.Header.FileTime < 116444736000000000 {
		return Event{}, errors.New("unsupported EVTX timestamp")
	}
	ticks := record.Header.FileTime - 116444736000000000
	stamp := time.Unix(int64(ticks/10000000), int64(ticks%10000000)*100).UTC()
	if stamp.Year() > 9999 {
		return Event{}, errors.New("EVTX timestamp outside supported range")
	}
	w := &WindowsEventContext{Provider: nativeScalar(provider["Name"]), ProviderGUID: nativeScalar(provider["Guid"]), EventID: uint16(id), RecordID: nativeScalar(system["EventRecordID"]), Channel: nativeScalar(system["Channel"])}
	// The binary record header and XML System identifiers can differ. Preserve
	// both rather than substituting one for the other.
	native := &NativeRecord{Parser: "EVTX", Table: "EventRecord", Record: strconv.FormatUint(record.Header.RecordID, 10), TimeField: "FileTime", TimeEncoding: "windows_100ns_1601"}
	if created, ok := system["TimeCreated"].(map[string]any); ok {
		native.OtherTimes = []NativeTime{{Field: "System.TimeCreated.SystemTime", Value: nativeScalar(created["SystemTime"]), Encoding: "unix_seconds_float"}}
	}
	event := Event{Native: native, Windows: w, Time: stamp, OriginalTime: strconv.FormatUint(record.Header.FileTime, 10), Type: "windows_event", Evidence: it.ID, Source: it.Source, ByteOffset: offset, Host: strings.ToLower(strings.TrimSuffix(nativeScalar(system["Computer"]), "."))}
	data, _ := root["EventData"].(map[string]any)
	keys := make([]string, 0, len(data))
	for key := range data {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if len(w.Data) >= 64 {
			w.PayloadOmitted = true
			break
		}
		value := nativeScalar(data[key])
		if value == "" && data[key] != "" {
			w.PayloadOmitted = true
		}
		if len(key) > 256 || len(value) > 4096 {
			w.PayloadOmitted = true
			continue
		}
		w.Data = append(w.Data, WindowsEventData{Name: key, Value: value})
	}
	if _, ok := root["UserData"]; ok {
		w.PayloadOmitted = true
	}
	if event.Host == "" || len(event.Host) > 256 || w.Provider == "" {
		return Event{}, fmt.Errorf("invalid EVTX host or provider")
	}
	return event, nil
}

func nativeScalar(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	case bool:
		return strconv.FormatBool(v)
	}
	return ""
}
