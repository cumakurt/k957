package core

import (
	"encoding/json"
	"io"
	"net/netip"
	"strings"
	"time"
)

var fieldGroups = [][]string{{"timestamp", "time", "@timestamp"}, {"message", "event"}, {"user", "username"}, {"host", "hostname"}, {"src_ip", "source_ip"}, {"dst_ip", "destination_ip"}}

func recognizedField(k string) bool {
	for _, g := range fieldGroups {
		for _, v := range g {
			if k == v {
				return true
			}
		}
	}
	return false
}
func fieldValue(v map[string]string, keys []string) (string, bool) {
	value := ""
	for _, key := range keys {
		if s := strings.TrimSpace(v[key]); s != "" {
			if value != "" && s != value {
				return "", false
			}
			value = s
		}
	}
	return value, true
}
func decodeRecord(s string) (map[string]string, bool) {
	d := json.NewDecoder(strings.NewReader(s))
	tok, e := d.Token()
	if e != nil || tok != json.Delim('{') {
		return nil, false
	}
	v := map[string]string{}
	seen := map[string]bool{}
	for d.More() {
		t, e := d.Token()
		if e != nil {
			return nil, false
		}
		k, ok := t.(string)
		if !ok || seen[k] {
			return nil, false
		}
		seen[k] = true
		var raw json.RawMessage
		if d.Decode(&raw) != nil {
			return nil, false
		}
		if recognizedField(k) {
			var val string
			if json.Unmarshal(raw, &val) != nil {
				return nil, false
			}
			v[k] = val
		}
	}
	if _, e = d.Token(); e != nil {
		return nil, false
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return nil, false
	}
	return v, true
}
func eventFromFields(v map[string]string, it Item, line int, offset int64) (Event, bool) {
	values := make([]string, len(fieldGroups))
	for i, g := range fieldGroups {
		val, ok := fieldValue(v, g)
		if !ok {
			return Event{}, false
		}
		values[i] = val
	}
	t, e := time.Parse(time.RFC3339Nano, values[0])
	if e != nil {
		return Event{}, false
	}
	for _, i := range []int{2, 3, 4, 5} {
		if len(values[i]) > 256 {
			return Event{}, false
		}
	}
	for _, i := range []int{4, 5} {
		if values[i] != "" {
			ip, e := netip.ParseAddr(values[i])
			if e != nil {
				return Event{}, false
			}
			values[i] = ip.Unmap().String()
		}
	}
	detail := []rune(values[1])
	if len(detail) > 400 {
		detail = detail[:400]
	}
	return Event{Time: t.UTC(), Type: "log_timestamp", Evidence: it.ID, Source: it.Source, Line: line, ByteOffset: offset, OriginalTime: values[0], Detail: string(detail), User: values[2], Host: strings.ToLower(strings.TrimSuffix(values[3], ".")), SourceIP: values[4], DestinationIP: values[5]}, true
}

// Explicit-zone RFC3339 only; duplicate/ambiguous JSON fields are rejected.
func parseLogLine(line string, it Item, ln int) (Event, bool) {
	s := strings.TrimSpace(line)
	if len(s) == 0 || len(s) > 65536 {
		return Event{}, false
	}
	if strings.HasPrefix(s, "{") {
		v, ok := decodeRecord(s)
		if !ok {
			return Event{}, false
		}
		return eventFromFields(v, it, ln, 0)
	}
	stamp := strings.Fields(s)[0]
	return eventFromFields(map[string]string{"timestamp": stamp, "message": s}, it, ln, 0)
}
