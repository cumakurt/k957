package core

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strings"
)

// IndicatorSet is an offline, examiner-supplied list. Matching observes a value;
// it neither contacts a provider nor turns an indicator into a malware verdict.
type IndicatorSet struct {
	Schema     string      `json:"schema"`
	Name       string      `json:"name"`
	Source     string      `json:"source"`
	Indicators []Indicator `json:"indicators"`
	digest     string
	byValue    map[string][]Indicator
}
type Indicator struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	Value       string `json:"value"`
	Description string `json:"description,omitempty"`
}
type IndicatorMatch struct {
	Indicator string          `json:"indicator_id"`
	Kind      string          `json:"kind"`
	Value     string          `json:"value"`
	Evidence  string          `json:"evidence"`
	Source    string          `json:"source"`
	Basis     string          `json:"basis"`
	Event     *EventReference `json:"event,omitempty"`
}
type IndicatorSummary struct {
	Name    string           `json:"name"`
	Source  string           `json:"source"`
	SHA256  string           `json:"sha256"`
	Entries int              `json:"entries"`
	Matches []IndicatorMatch `json:"matches"`
}

func LoadIndicators(path string) (*IndicatorSet, error) {
	if path == "" {
		return nil, nil
	}
	body, e := ReadLimited(path, 32<<20)
	if e != nil {
		return nil, e
	}
	var s IndicatorSet
	if e = custodyJSON(body, &s); e != nil {
		return nil, e
	}
	if s.Schema != "k957-indicators/1" || !custodyText(s.Name, 256, false) || !custodyText(s.Source, 4096, false) {
		return nil, errors.New("invalid offline indicator list identity")
	}
	s.digest = digestBytes(body)
	s.byValue = map[string][]Indicator{}
	ids := map[string]bool{}
	for i, v := range s.Indicators {
		if !custodyText(v.ID, 256, false) || ids[v.ID] || len(v.Description) > 4096 {
			return nil, errors.New("indicator ids must be unique and bounded")
		}
		ids[v.ID] = true
		value, e := normalizeIndicator(v.Kind, v.Value)
		if e != nil {
			return nil, fmt.Errorf("indicator %s: %w", v.ID, e)
		}
		v.Value = value
		s.Indicators[i] = v
		s.byValue[v.Kind+":"+value] = append(s.byValue[v.Kind+":"+value], v)
	}
	return &s, nil
}
func normalizeIndicator(kind, value string) (string, error) {
	switch kind {
	case "sha256":
		value = strings.ToLower(value)
		if validHash(value) {
			return value, nil
		}
	case "ip":
		if ip := net.ParseIP(value); ip != nil {
			return ip.String(), nil
		}
	case "domain":
		value = strings.ToLower(strings.TrimSuffix(value, "."))
		if len(value) > 253 || !strings.Contains(value, ".") || net.ParseIP(value) != nil {
			break
		}
		for _, label := range strings.Split(value, ".") {
			if len(label) == 0 || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
				return "", errors.New("invalid domain label")
			}
			for _, r := range label {
				if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
					return "", errors.New("use ASCII/punycode domain labels")
				}
			}
		}
		return value, nil
	}
	return "", errors.New("indicator must be an exact sha256, ip or domain value")
}

type indicatorContextKey struct{}

func WithIndicators(ctx context.Context, set *IndicatorSet) context.Context {
	return context.WithValue(ctx, indicatorContextKey{}, set)
}
func applyConfiguredIndicators(ctx context.Context, a *Analysis) {
	set, _ := ctx.Value(indicatorContextKey{}).(*IndicatorSet)
	if set == nil {
		return
	}
	summary := IndicatorSummary{Name: set.Name, Source: set.Source, SHA256: set.digest, Entries: len(set.Indicators), Matches: []IndicatorMatch{}}
	seen := map[string]bool{}
	add := func(kind, value, evidence, source, basis string, event *EventReference) {
		normalized, e := normalizeIndicator(kind, value)
		if e != nil {
			return
		}
		for _, indicator := range set.byValue[kind+":"+normalized] {
			key := digestJSON(struct {
				ID, Evidence, Source, Basis string
				Event                       *EventReference
			}{indicator.ID, evidence, source, basis, event})
			if seen[key] {
				continue
			}
			seen[key] = true
			summary.Matches = append(summary.Matches, IndicatorMatch{indicator.ID, kind, normalized, evidence, source, basis, event})
		}
	}
	for _, item := range a.Manifest.Items {
		add("sha256", item.SHA256, item.ID, item.Source, "exact collected object SHA-256", nil)
	}
	for _, m := range a.Memories {
		add("sha256", m.SHA256, m.Evidence, m.Source, "exact memory image SHA-256", nil)
	}
	for _, ev := range a.Timeline {
		reference := referenceEvent(ev)
		add("ip", ev.SourceIP, ev.Evidence, ev.Source, "normalized source IP field", reference)
		add("ip", ev.DestinationIP, ev.Evidence, ev.Source, "normalized destination IP field", reference)
		if ev.Type == "browser_visit" {
			token, _, _ := strings.Cut(ev.Detail, " | ")
			if u, e := url.Parse(token); e == nil && (u.Scheme == "http" || u.Scheme == "https") {
				add("domain", u.Hostname(), ev.Evidence, ev.Source, "parsed browser URL hostname", reference)
			}
		}
	}
	for _, network := range a.NetworkInterpretations {
		for _, observation := range network.Observations {
			var reference *EventReference
			if len(observation.References) > 0 {
				r := observation.References[0]
				reference = &EventReference{Evidence: observation.Evidence, Source: observation.Source, Packet: r.Packet, ByteOffset: r.ByteOffset, Time: r.Time, Type: observation.Protocol}
			}
			if observation.DNS != nil {
				for _, q := range observation.DNS.Questions {
					add("domain", q.Name, observation.Evidence, observation.Source, "exact DNS question name", reference)
				}
			}
			if observation.HTTP != nil {
				host := observation.HTTP.Host
				if h, _, e := net.SplitHostPort(host); e == nil {
					host = h
				}
				add("domain", host, observation.Evidence, observation.Source, "exact HTTP Host field", reference)
			}
			if observation.TLS != nil {
				add("domain", observation.TLS.ServerName, observation.Evidence, observation.Source, "exact TLS server name", reference)
			}
		}
	}
	a.Indicators = &summary
}

func indicatorMatchCount(a Analysis) int {
	if a.Indicators == nil {
		return 0
	}
	return len(a.Indicators.Matches)
}
func exportIndicators(a Analysis, out string) error {
	if a.Indicators == nil {
		return nil
	}
	if e := WriteJSONNew(filepath.Join(out, "indicators.json"), a.Indicators); e != nil {
		return e
	}
	return writeCSVNew(filepath.Join(out, "indicator-matches.csv"), func(c *csv.Writer) error {
		if e := c.Write([]string{"indicator_id", "kind", "value", "evidence_id", "source", "basis", "line", "packet", "native_table", "native_record"}); e != nil {
			return e
		}
		for _, m := range a.Indicators.Matches {
			line, packet, table, record := "", "", "", ""
			if m.Event != nil {
				line = fmt.Sprint(m.Event.Line)
				packet = fmt.Sprint(m.Event.Packet)
				table = m.Event.Table
				record = m.Event.Record
			}
			if e := c.Write([]string{csvSafe(m.Indicator), m.Kind, csvSafe(m.Value), m.Evidence, csvSafe(m.Source), m.Basis, line, packet, csvSafe(table), csvSafe(record)}); e != nil {
				return e
			}
		}
		return nil
	})
}
