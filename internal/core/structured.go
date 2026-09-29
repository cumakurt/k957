package core

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

type ParseSummary struct {
	SkipReasons map[string]int `json:"skip_reasons,omitempty"`
	Evidence    string         `json:"evidence"`
	Format      string         `json:"format"`
	Rows        int            `json:"rows"`
	Parsed      int            `json:"parsed"`
	Skipped     int            `json:"skipped"`
	Limited     bool           `json:"limited"`
	Error       string         `json:"error,omitempty"`
}

func parseLogData(data []byte, it Item, budget int) (events []Event, s ParseSummary) {
	s = ParseSummary{Evidence: it.ID, Format: "text/RFC3339"}
	ext := strings.ToLower(filepath.Ext(it.Source))
	if ext == ".csv" {
		return parseCSV(data, it, budget)
	}
	strict := ext == ".jsonl" || ext == ".ndjson"
	if strict {
		s.Format = "JSONL"
	}
	if budget <= 0 {
		s.Limited = true
		return
	}

	offset := 0
	line := 0
	for offset < len(data) {
		start := offset
		end := bytes.IndexByte(data[start:], '\n')
		if end < 0 {
			offset = len(data)
		} else {
			offset = start + end + 1
		}
		raw := data[start:offset]
		raw = bytes.TrimSuffix(raw, []byte{'\n'})
		line++
		if len(bytes.TrimSpace(raw)) == 0 {
			continue
		}
		if len(events) >= budget {
			s.Limited = true
			break
		}
		s.Rows++
		var ev Event
		var ok bool
		if strict {
			if len(raw) <= 65536 {
				v, valid := decodeRecord(strings.TrimSpace(string(raw)))
				if valid {
					ev, ok = eventFromFields(v, it, line, int64(start))
				}
			}
		} else {
			ev, ok = parseLogLine(string(raw), it, line)
			ev.ByteOffset = int64(start)
		}
		if ok {
			events = append(events, ev)
			s.Parsed++
		} else {
			s.Skipped++
		}
	}

	return
}
func parseCSV(data []byte, it Item, budget int) (events []Event, s ParseSummary) {
	s = ParseSummary{Evidence: it.ID, Format: "CSV"}
	if budget <= 0 {
		s.Limited = true
		return
	}
	r := csv.NewReader(bytes.NewReader(data))
	header, e := r.Read()
	if e != nil {
		s.Error = "CSV header: " + e.Error()
		return
	}
	if len(header) > 128 {
		s.Error = "CSV exceeds 128 columns"
		return
	}
	seen := map[string]bool{}
	hasTime := false
	for i, k := range header {
		k = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(k, "\ufeff")))
		if k == "" || seen[k] {
			s.Error = "empty/duplicate normalized CSV header"
			return
		}
		seen[k] = true
		header[i] = k
		for _, ts := range fieldGroups[0] {
			if k == ts {
				hasTime = true
			}
		}
	}
	if !hasTime {
		s.Error = "CSV requires timestamp, time or @timestamp column"
		return
	}
	for {
		offset := r.InputOffset()
		for offset < int64(len(data)) {
			if data[offset] == '\n' {
				offset++
				continue
			}
			if offset+1 < int64(len(data)) && data[offset] == '\r' && data[offset+1] == '\n' {
				offset += 2
				continue
			}
			break
		}
		row, e := r.Read()
		if e == io.EOF {
			break
		}
		if len(events) >= budget {
			s.Limited = true
			break
		}
		s.Rows++
		if e != nil {
			s.Skipped++
			s.Error = fmt.Sprintf("CSV parsing stopped: %v", e)
			break
		}
		line, _ := r.FieldPos(0)
		v := map[string]string{}
		large := false
		for i, value := range row {
			if len(value) > 65536 {
				large = true
				break
			}
			if recognizedField(header[i]) {
				v[header[i]] = value
			}
		}
		if large {
			s.Skipped++
			continue
		}
		ev, ok := eventFromFields(v, it, line, offset)
		if !ok {
			s.Skipped++
			continue
		}
		events = append(events, ev)
		s.Parsed++
	}
	return
}
