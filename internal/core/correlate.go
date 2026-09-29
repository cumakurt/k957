package core

import (
	"sort"
	"time"
)

type Reference struct {
	CaptureContext
	Packet   int       `json:"packet,omitempty"`
	Evidence string    `json:"evidence"`
	Source   string    `json:"source"`
	Line     int       `json:"line"`
	Offset   int64     `json:"byte_offset"`
	Role     string    `json:"role"`
	Time     time.Time `json:"time"`
}
type Correlation struct {
	Kind       string      `json:"kind"`
	Value      string      `json:"value"`
	Events     int         `json:"events"`
	Sources    int         `json:"sources"`
	First      time.Time   `json:"first"`
	Last       time.Time   `json:"last"`
	References []Reference `json:"references"`
	Truncated  bool        `json:"references_truncated"`
}

func correlate(events []Event) ([]Correlation, []string) {
	type bucket struct {
		c   Correlation
		ids map[string]bool
	}
	index := map[string]*bucket{}
	limited := false
	for _, e := range events {
		if e.Type != "log_timestamp" && e.Type != "pcap_packet" && e.Type != "windows_event" {
			continue
		}
		entities := []struct{ kind, value, role string }{{"user", e.User, "user"}, {"host", e.Host, "host"}, {"ip", e.SourceIP, "source_ip"}, {"ip", e.DestinationIP, "destination_ip"}}
		if e.SourceIP != "" && e.SourceIP == e.DestinationIP {
			entities[2].role = "source_ip,destination_ip"
		}
		seen := map[string]bool{}
		for _, v := range entities {
			if v.value == "" {
				continue
			}
			key := v.kind + "\x00" + v.value
			if seen[key] {
				continue
			}
			seen[key] = true
			b := index[key]
			if b == nil {
				if len(index) >= 20000 {
					limited = true
					continue
				}
				b = &bucket{c: Correlation{Kind: v.kind, Value: v.value, First: e.Time, Last: e.Time, References: []Reference{}}, ids: map[string]bool{}}
				index[key] = b
			}
			b.c.Events++
			b.ids[e.Evidence] = true
			if e.Time.Before(b.c.First) {
				b.c.First = e.Time
			}
			if e.Time.After(b.c.Last) {
				b.c.Last = e.Time
			}
			if len(b.c.References) < 200 {
				b.c.References = append(b.c.References, Reference{CaptureContext: e.CaptureContext, Packet: e.Packet, Evidence: e.Evidence, Source: e.Source, Line: e.Line, Offset: e.ByteOffset, Role: v.role, Time: e.Time})
			} else {
				b.c.Truncated = true
			}
		}
	}
	out := []Correlation{}
	for _, b := range index {
		if len(b.ids) < 2 {
			continue
		}
		b.c.Sources = len(b.ids)
		out = append(out, b.c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Value < out[j].Value
	})
	notes := []string{"Correlations are shared field values across at least two evidence objects, not independent-source corroboration or identity attribution. NAT, shared accounts and duplicate logs can produce matches. User names are case-sensitive; host names lowercased; IPs canonicalized. No network enrichment is performed."}
	if limited {
		notes = append(notes, "Entity index reached 20,000 unique values; new values omitted.")
	}
	return out, notes
}
