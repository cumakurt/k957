package core

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type EventRule struct {
	All []FieldCondition `json:"all,omitempty"`
	Any []FieldCondition `json:"any,omitempty"`
}

type FieldCondition struct {
	Field string `json:"field"`
	Op    string `json:"op"`
	Value string `json:"value"`
}

type EventReference struct {
	Evidence      string    `json:"evidence"`
	Source        string    `json:"source"`
	Type          string    `json:"type"`
	Time          time.Time `json:"time"`
	Line          int       `json:"line,omitempty"`
	ByteOffset    int64     `json:"byte_offset,omitempty"`
	Packet        int       `json:"packet,omitempty"`
	Table         string    `json:"table,omitempty"`
	Record        string    `json:"record,omitempty"`
	WindowsRecord string    `json:"windows_record,omitempty"`
}

type RuleEvaluation struct {
	Rule      string `json:"rule"`
	Evaluated int    `json:"evaluated"`
	Matched   int    `json:"matched"`
	Emitted   int    `json:"emitted"`
	Limited   bool   `json:"limited"`
	Error     string `json:"error,omitempty"`
}

type preparedCondition struct {
	FieldCondition
	regex  *regexp.Regexp
	prefix netip.Prefix
}

func prepareEventRule(rule EventRule) (all, any []preparedCondition, err error) {
	if len(rule.All)+len(rule.Any) == 0 || len(rule.All)+len(rule.Any) > 32 {
		return nil, nil, errors.New("event rules require 1..32 field conditions")
	}
	for group, conditions := range [][]FieldCondition{rule.All, rule.Any} {
		for _, c := range conditions {
			if len(c.Value) == 0 || len(c.Value) > 4096 {
				return nil, nil, errors.New("invalid event condition value length")
			}
			switch c.Field {
			case "usn.name", "usn.file_id", "usn.parent_id", "usn.number", "usn.reasons":
			case "type", "user", "host", "source", "source_ip", "destination_ip", "protocol", "detail", "windows.event_id", "windows.provider", "windows.channel", "windows.record_id", "native.table", "native.record", "cloud.event_name", "cloud.event_source", "cloud.account", "cloud.region", "cloud.event_id", "source_port", "destination_port":
			default:
				return nil, nil, fmt.Errorf("unsupported event rule field %q", c.Field)
			}
			p := preparedCondition{FieldCondition: c}
			switch c.Op {
			case "equals", "contains", "contains_fold":
			case "regex":
				if len(c.Value) > 1024 {
					return nil, nil, errors.New("regex exceeds 1024 bytes")
				}
				p.regex, err = regexp.Compile(c.Value)
				if err != nil {
					return nil, nil, err
				}
			case "cidr":
				if c.Field != "source_ip" && c.Field != "destination_ip" {
					return nil, nil, errors.New("CIDR condition requires an IP field")
				}
				p.prefix, err = netip.ParsePrefix(c.Value)
				if err != nil {
					return nil, nil, err
				}
			default:
				return nil, nil, fmt.Errorf("unsupported event condition operator %q", c.Op)
			}
			if group == 0 {
				all = append(all, p)
			} else {
				any = append(any, p)
			}
		}
	}
	return all, any, nil
}

func eventField(ev Event, field string) (string, bool) {
	switch field {
	case "usn.name", "usn.file_id", "usn.parent_id", "usn.number", "usn.reasons":
		if ev.USN != nil {
			switch field {
			case "usn.name":
				return ev.USN.Name, true
			case "usn.file_id":
				return ev.USN.FileID, true
			case "usn.parent_id":
				return ev.USN.ParentID, true
			case "usn.number":
				return ev.USN.USN, true
			case "usn.reasons":
				return strings.Join(ev.USN.Reasons, "|"), len(ev.USN.Reasons) > 0
			}
		}
	case "type":
		return ev.Type, ev.Type != ""
	case "user":
		return ev.User, ev.User != ""
	case "host":
		return ev.Host, ev.Host != ""
	case "source":
		return ev.Source, ev.Source != ""
	case "source_ip":
		return ev.SourceIP, ev.SourceIP != ""
	case "destination_ip":
		return ev.DestinationIP, ev.DestinationIP != ""
	case "protocol":
		return ev.Protocol, ev.Protocol != ""
	case "detail":
		return ev.Detail, ev.Detail != ""
	case "source_port":
		return strconv.Itoa(int(ev.SourcePort)), ev.Protocol == "TCP" || ev.Protocol == "UDP"
	case "destination_port":
		return strconv.Itoa(int(ev.DestinationPort)), ev.Protocol == "TCP" || ev.Protocol == "UDP"
	case "windows.event_id":
		if ev.Windows != nil {
			return strconv.Itoa(int(ev.Windows.EventID)), true
		}
	case "windows.provider":
		if ev.Windows != nil {
			return ev.Windows.Provider, ev.Windows.Provider != ""
		}
	case "windows.channel":
		if ev.Windows != nil {
			return ev.Windows.Channel, ev.Windows.Channel != ""
		}
	case "windows.record_id":
		if ev.Windows != nil {
			return ev.Windows.RecordID, ev.Windows.RecordID != ""
		}
	case "cloud.event_name", "cloud.event_source", "cloud.account", "cloud.region", "cloud.event_id":
		if ev.Cloud != nil {
			value := ""
			switch field {
			case "cloud.event_name":
				value = ev.Cloud.EventName
			case "cloud.event_source":
				value = ev.Cloud.EventSource
			case "cloud.account":
				value = ev.Cloud.Account
			case "cloud.region":
				value = ev.Cloud.Region
			case "cloud.event_id":
				value = ev.Cloud.EventID
			}
			return value, value != ""
		}
	case "native.table":
		if ev.Native != nil {
			return ev.Native.Table, ev.Native.Table != ""
		}
	case "native.record":
		if ev.Native != nil {
			return ev.Native.Record, ev.Native.Record != ""
		}
	}
	return "", false
}

func (c preparedCondition) matches(ev Event) bool {
	value, present := eventField(ev, c.Field)
	if !present {
		return false
	}
	switch c.Op {
	case "equals":
		return value == c.Value
	case "contains":
		return strings.Contains(value, c.Value)
	case "contains_fold":
		return strings.Contains(strings.ToLower(value), strings.ToLower(c.Value))
	case "regex":
		return c.regex.MatchString(value)
	case "cidr":
		ip, e := netip.ParseAddr(value)
		return e == nil && c.prefix.Contains(ip)
	}
	return false
}

func eventRuleMatches(ev Event, all, any []preparedCondition) bool {
	for _, c := range all {
		if !c.matches(ev) {
			return false
		}
	}
	if len(any) == 0 {
		return true
	}
	for _, c := range any {
		if c.matches(ev) {
			return true
		}
	}
	return false
}

func referenceEvent(ev Event) *EventReference {
	r := &EventReference{Evidence: ev.Evidence, Source: ev.Source, Type: ev.Type, Time: ev.Time, Line: ev.Line, ByteOffset: ev.ByteOffset, Packet: ev.Packet}
	if ev.Native != nil {
		r.Table = ev.Native.Table
		r.Record = ev.Native.Record
	}
	if ev.Windows != nil {
		r.WindowsRecord = ev.Windows.RecordID
	}
	return r
}

func evaluateEventRules(ctx context.Context, a *Analysis) {
	for _, rule := range a.Rules {
		if rule.Event == nil {
			continue
		}
		result := RuleEvaluation{Rule: rule.ID}
		all, any, e := prepareEventRule(*rule.Event)
		if e != nil {
			result.Error = e.Error()
			a.RuleEvaluations = append(a.RuleEvaluations, result)
			continue
		}
		for _, ev := range a.Timeline {
			if ctx.Err() != nil {
				a.Canceled = true
				result.Limited = true
				break
			}
			result.Evaluated++
			if !eventRuleMatches(ev, all, any) {
				continue
			}
			result.Matched++
			if len(a.Findings) >= findingLimit {
				markFindingsTruncated(a)
				result.Limited = true
				continue
			}
			excerpt := []rune(ev.Detail)
			if len(excerpt) > 400 {
				excerpt = excerpt[:400]
			}
			f := Finding{Rule: rule.ID, Description: rule.Description, Evidence: ev.Evidence, Source: ev.Source, Line: ev.Line, Excerpt: string(excerpt), Review: "unreviewed", Event: referenceEvent(ev)}
			appendFinding(a, f)
			result.Emitted++
		}
		a.RuleEvaluations = append(a.RuleEvaluations, result)
	}
}
