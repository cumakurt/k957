package core

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStructuredCSVMultiline(t *testing.T) {
	header := "timestamp,user,host,src_ip,dst_ip,message\r\n"
	row := "2026-09-27T14:00:00+03:00,Alice,HOST.,::ffff:192.0.2.1,2001:db8::1,\"first\nsecond\"\r\n"
	data := []byte(header + "\r\n" + row)
	ev, s := parseLogData(data, Item{ID: "E1", Source: "events.csv"}, 10)
	if len(ev) != 1 || s.Skipped != 0 || ev[0].Line != 3 || ev[0].ByteOffset != int64(len(header)+2) || ev[0].Time.Hour() != 11 || ev[0].SourceIP != "192.0.2.1" || ev[0].Host != "host" || ev[0].Detail != "first\nsecond" {
		t.Fatalf("%+v %+v", ev, s)
	}
}
func TestStructuredRejectedRecords(t *testing.T) {
	cases := []string{`{"timestamp":"2026-09-27T00:00:00Z","timestamp":"2026-09-28T00:00:00Z"}`, `{"timestamp":"2026-09-27T00:00:00","user":"a"}`, `{"timestamp":"2026-09-27T00:00:00Z","user":42}`, `{"timestamp":"2026-09-27T00:00:00Z","user":"a","username":"b"}`, `{"timestamp":"2026-09-27T00:00:00Z","src_ip":"invalid"}`, `{"timestamp":"2026-09-27T00:00:00Z"} trailing`}
	for _, s := range cases {
		ev, summary := parseLogData([]byte(s), Item{ID: "E", Source: "a.jsonl"}, 10)
		if len(ev) != 0 || summary.Skipped != 1 {
			t.Fatal(s, summary)
		}
	}
}
func TestStructuredCSVHeadersAndErrors(t *testing.T) {
	for _, s := range []string{"time, TIME\n1,2\n", "user,message\na,b\n", "timestamp,message\n2026-09-27T00:00:00Z,\"unclosed\n"} {
		_, summary := parseLogData([]byte(s), Item{ID: "E", Source: "a.csv"}, 10)
		if summary.Error == "" {
			t.Fatal("error hidden", s)
		}
	}
	_, s := parseLogData([]byte("timestamp,message\n2026-09-27T00:00:00Z,x\ninvalid,y\n"), Item{ID: "E", Source: "a.csv"}, 10)
	if s.Rows != 2 || s.Parsed != 1 || s.Skipped != 1 {
		t.Fatal(s)
	}
}
func TestStructuredOffsetsAndLimits(t *testing.T) {
	one := `{"timestamp":"2026-09-27T00:00:00Z","user":"alice"}`
	data := []byte("\n" + one + "\n\n" + one + "\n")
	events, s := parseLogData(data, Item{ID: "E", Source: "a.jsonl"}, 5)
	if len(events) != 2 || events[1].Line != 4 || events[1].ByteOffset != int64(len(one)+3) {
		t.Fatal(events, s)
	}
	events, s = parseLogData(data, Item{ID: "E", Source: "a.jsonl"}, 1)
	if len(events) != 1 || !s.Limited {
		t.Fatal(s)
	}
	events, s = parseLogData(data, Item{ID: "E", Source: "a.csv"}, 0)
	if len(events) != 0 || !s.Limited {
		t.Fatal(s)
	}
}
func TestCorrelationSemantics(t *testing.T) {
	now := time.Now().UTC()
	events := []Event{{Type: "log_timestamp", Evidence: "E1", Line: 1, Time: now, User: "Alice", SourceIP: "192.0.2.1", DestinationIP: "192.0.2.1"}, {Type: "log_timestamp", Evidence: "E2", Line: 2, Time: now.Add(time.Second), User: "alice", DestinationIP: "192.0.2.1"}}
	c, _ := correlate(events)
	if len(c) != 1 || c[0].Kind != "ip" || c[0].Events != 2 || c[0].Sources != 2 || c[0].References[0].Role != "source_ip,destination_ip" {
		t.Fatal(c)
	}
	c, _ = correlate(events[:1])
	if len(c) != 0 {
		t.Fatal("same-source correlation")
	}
}
func TestCorrelationReferenceLimit(t *testing.T) {
	var events []Event
	for i := 0; i < 205; i++ {
		events = append(events, Event{Type: "log_timestamp", Evidence: fmt.Sprintf("E%d", i%2), Line: i + 1, Time: time.Now(), User: "shared"})
	}
	c, _ := correlate(events)
	if len(c) != 1 || c[0].Events != 205 || !c[0].Truncated || len(c[0].References) != 200 {
		t.Fatal(c)
	}
}
func TestStructuredEndToEnd(t *testing.T) {
	d, o := fixture(t, false)
	os.WriteFile(filepath.Join(o.Root, "a.csv"), []byte("timestamp,user,src_ip\n2026-09-27T00:00:00Z,alice,192.0.2.1\n"), 0600)
	os.WriteFile(filepath.Join(o.Root, "b.jsonl"), []byte(`{"timestamp":"2026-09-27T00:01:00Z","user":"alice","dst_ip":"192.0.2.1"}`), 0600)
	if _, e := Collect(context.Background(), o); e != nil {
		t.Fatal(e)
	}
	p, e := Open(o.Out, "")
	if e != nil {
		t.Fatal(e)
	}
	defer p.Zip.Close()
	a := Analyze(p, nil)
	if len(a.Correlations) != 2 {
		t.Fatal(a.Correlations)
	}
	out := filepath.Join(d, "report")
	if e = Export(a, out); e != nil {
		t.Fatal(e)
	}
	csv, _ := os.ReadFile(filepath.Join(out, "correlations.csv"))
	if !strings.Contains(string(csv), "192.0.2.1") {
		t.Fatal("missing correlation export")
	}
}
func FuzzStructuredLogs(f *testing.F) {
	f.Add("timestamp,message\n2026-09-27T00:00:00Z,ok\n", true)
	f.Add(`{"timestamp":"2026-09-27T00:00:00Z","user":"alice"}`, false)
	f.Fuzz(func(t *testing.T, data string, csv bool) {
		if len(data) > 65536 {
			t.Skip()
		}
		name := "test.jsonl"
		if csv {
			name = "test.csv"
		}
		events, s := parseLogData([]byte(data), Item{ID: "E", Source: name}, 100)
		if len(events) > 100 || s.Parsed != len(events) {
			t.Fatal("parser budget/count")
		}
		correlate(events)
	})
}
