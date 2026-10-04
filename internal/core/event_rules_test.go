package core

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestStructuredRulesReferencesAndEvaluation(t *testing.T) {
	rules, e := LoadRules("../../examples/event-rules.json")
	if e != nil {
		t.Fatal(e)
	}
	a := Analysis{EvidenceDigest: strings.Repeat("a", 64), Rules: rules, Timeline: []Event{{Type: "windows_event", Evidence: "E1", Source: "Security.evtx", Time: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC), ByteOffset: 4608, Windows: &WindowsEventContext{EventID: 1102, RecordID: "33072"}, Native: &NativeRecord{Table: "EventRecord", Record: "33072"}}, {Type: "packet", Protocol: "TCP", SourceIP: "10.2.3.4", Evidence: "E2", Source: "capture", Packet: 1}}}
	evaluateEventRules(context.Background(), &a)
	if len(a.Findings) != 2 || len(a.RuleEvaluations) != 3 {
		t.Fatalf("%+v", a)
	}
	f := a.Findings[0]
	if f.Event == nil || f.Event.Record != "33072" || f.Event.ByteOffset != 4608 {
		t.Fatal("missing source reference", f)
	}
	one := findingID(a.EvidenceDigest, f)
	f.Event = &EventReference{Record: "other"}
	if findingID(a.EvidenceDigest, f) == one {
		t.Fatal("different records share a finding ID")
	}
	all, any, e := prepareEventRule(EventRule{All: []FieldCondition{{Field: "detail", Op: "regex", Value: "(?i)marker"}}})
	if e != nil || !eventRuleMatches(Event{Detail: "MARKER"}, all, any) {
		t.Fatal(e)
	}
	if _, _, e = prepareEventRule(EventRule{All: []FieldCondition{{Field: "source", Op: "cidr", Value: "10.0.0.0/8"}}}); e == nil {
		t.Fatal("unsupported field/operator pairing")
	}
}

func TestStructuredRuleFindingLimitRetainsCounts(t *testing.T) {
	a := Analysis{Findings: make([]Finding, findingLimit), Rules: []Rule{{ID: "r", Event: &EventRule{All: []FieldCondition{{Field: "type", Op: "equals", Value: "marker"}}}}}, Timeline: []Event{{Type: "marker"}, {Type: "marker"}}}
	evaluateEventRules(context.Background(), &a)
	if !a.FindingsTruncated || a.RuleEvaluations[0].Matched != 2 || a.RuleEvaluations[0].Emitted != 0 {
		t.Fatal("finding limit concealed matches")
	}
}
