package core

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/csv"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

const testWindowsEvent = `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="ProviderSecret" Guid="GUIDSecret" EventSourceName="LegacySecret"/><EventID Qualifiers="65535">4624</EventID><Version>0</Version><Level>4</Level><TimeCreated SystemTime="2026-09-29T14:02:03.1234567+03:00"/><EventRecordID>18446744073709551615</EventRecordID><Channel>ChannelSecret</Channel><Computer>HOST.</Computer><Security UserID="S-1-5-21-123"/></System><EventData><Data Name="Repeated">DataSecret</Data><Data Name="Repeated">Café 😀</Data><Data>unnamed</Data></EventData><RenderingInfo><Message>&lt;script&gt;MessageSecret&lt;/script&gt;</Message></RenderingInfo></Event>`

func windowsUTF16(s string, order binary.ByteOrder) []byte {
	units := utf16.Encode([]rune(s))
	b := make([]byte, 2+2*len(units))
	order.PutUint16(b, 0xfeff)
	for i, u := range units {
		order.PutUint16(b[2+2*i:], u)
	}
	return b
}

func TestWindowsXMLMetadataAndEncodings(t *testing.T) {
	prefix := "<?xml version=\"1.0\"?>\n<Events>\n<!--" + strings.Repeat("😀é", 1100) + "-->\n"
	prefix = strings.ReplaceAll(prefix, "\n", "\r\n")
	suffix := "\r\n</Events>"
	for name, encode := range map[string]func(string) []byte{
		"utf8":    func(s string) []byte { return []byte(s) },
		"utf8bom": func(s string) []byte { return append([]byte{0xef, 0xbb, 0xbf}, []byte(s)...) },
		"utf16le": func(s string) []byte { return windowsUTF16(s, binary.LittleEndian) },
		"utf16be": func(s string) []byte { return windowsUTF16(s, binary.BigEndian) },
	} {
		t.Run(name, func(t *testing.T) {
			raw := encode(prefix + testWindowsEvent + suffix)
			events, s, decoded := parseWindowsXML(raw, Item{ID: "E1", Source: "source.xml"}, 20)
			if s.Error != "" || s.Rows != 1 || s.Parsed != 1 || s.Skipped != 0 || s.Limited || len(events) != 1 {
				t.Fatalf("%+v", s)
			}
			e := events[0]
			w := e.Windows
			if e.ByteOffset != int64(len(encode(prefix))) || e.Line != 4 || e.Evidence != "E1" || e.Source != "source.xml" {
				t.Fatalf("provenance: %+v", e)
			}
			if e.Time.Format(time.RFC3339Nano) != "2026-09-29T11:02:03.1234567Z" || e.OriginalTime != "2026-09-29T14:02:03.1234567+03:00" || e.Host != "host" || e.User != "S-1-5-21-123" {
				t.Fatalf("fields: %+v", e)
			}
			if w.Provider != "ProviderSecret" || w.ProviderGUID != "GUIDSecret" || w.EventSource != "LegacySecret" || w.EventID != 4624 || *w.Qualifiers != 65535 || w.RecordID != "18446744073709551615" || *w.Version != 0 || *w.Level != 4 || w.Channel != "ChannelSecret" {
				t.Fatalf("metadata: %+v", w)
			}
			if len(w.Data) != 3 || w.Data[0].Name != w.Data[1].Name || w.Data[1].Value != "Café 😀" || w.Data[2].Name != "" || e.Detail != "<script>MessageSecret</script>" || w.PayloadOmitted || w.MessageTruncated {
				t.Fatalf("payload: %+v", w)
			}
			if string(decoded) != prefix+testWindowsEvent+suffix {
				t.Fatal("decoded text changed")
			}
		})
	}
	// XML prefixes are aliases for the namespace, not literal element names.
	prefixed := strings.ReplaceAll(testWindowsEvent, "xmlns=", "xmlns:w=")
	for _, tag := range []string{"Event", "System", "Provider", "EventID", "Version", "Level", "TimeCreated", "EventRecordID", "Channel", "Computer", "Security", "EventData", "Data", "RenderingInfo", "Message"} {
		// Include delimiters so Event does not change EventID/EventData.
		for _, end := range []string{" ", ">", "/"} {
			prefixed = strings.ReplaceAll(prefixed, "<"+tag+end, "<w:"+tag+end)
		}
		prefixed = strings.ReplaceAll(prefixed, "</"+tag+">", "</w:"+tag+">")
	}
	ev, s, _ := parseWindowsXML([]byte(prefixed+"\n"+testWindowsEvent), Item{}, 3)
	if len(ev) != 2 || s.Error != "" || ev[1].ByteOffset != int64(len(prefixed)+1) {
		t.Fatalf("prefix/fragments: %+v", s)
	}
}

func TestWindowsXMLSemanticRejectionsContinue(t *testing.T) {
	cases := []struct{ old, new, reason string }{
		{"<System>", "<System>text", "invalid_system"},
		{"<EventID Qualifiers=\"65535\">4624</EventID>", "<EventID>65536</EventID>", "invalid_event_id"},
		{"Qualifiers=\"65535\"", "Qualifiers=\"65536\"", "invalid_qualifiers"},
		{"18446744073709551615", "18446744073709551616", "invalid_record_id"},
		{"18446744073709551615", "", "invalid_record_id"},
		{"<Level>4</Level>", "<Level>256</Level>", "invalid_level_or_version"},
		{"<Version>0</Version>", "<Version/>", "invalid_level_or_version"},
		{"2026-09-29T14:02:03.1234567+03:00", "2026-09-29T14:02:03", "unsupported_timestamp"},
		{"2026-09-29T14:02:03.1234567+03:00", "2026-09-29T14:02:03.1234567891Z", "unsupported_timestamp"},
		{"2026-09-29T14:02:03.1234567+03:00", "2026-09-29T14:02:03+24:00", "unsupported_timestamp"},
		{"<TimeCreated ", "<TimeCreated RawTime=\"\" ", "unsupported_timestamp"},
		{"<Computer>HOST.</Computer>", "<Computer/>", "invalid_host_or_user_length"},
		{"<Computer>HOST.</Computer>", "<Computer>a</Computer><Computer>b</Computer>", "ambiguous_system_field"},
		{"<Level>4</Level>", "<Level><Other>4</Other></Level>", "ambiguous_system_field"},
		{"<Security UserID=\"S-1-5-21-123\"/>", "<Security/><Security/>", "ambiguous_security"},
		{"<EventData>", "<EventData/><EventData>", "ambiguous_event_data"},
		{"DataSecret", "<Nested/>", "unsupported_event_data"},
		{"<RenderingInfo>", "<RenderingInfo/><RenderingInfo>", "ambiguous_rendering_info"},
		{"</Message>", "</Message><Message>second</Message>", "ambiguous_message"},
		{"<System>", "unexpected<System>", "unexpected_event_text"},
		{"<EventData>", "<EventData>unexpected", "invalid_event_data"},
		{"<Data>unnamed</Data>", strings.Repeat("<Data>x</Data>", 65), "unsupported_event_data"},
	}
	for _, c := range cases {
		t.Run(c.reason+"/"+c.new, func(t *testing.T) {
			bad := strings.Replace(testWindowsEvent, c.old, c.new, 1)
			ev, s, _ := parseWindowsXML([]byte("<Events>"+bad+testWindowsEvent+"</Events>"), Item{}, 10)
			if s.Error != "" || s.Rows != 2 || s.Parsed != 1 || s.Skipped != 1 || s.SkipReasons[c.reason] != 1 || len(ev) != 1 {
				t.Fatalf("%+v", s)
			}
		})
	}
}

func TestWindowsXMLStructureAndResourceBounds(t *testing.T) {
	cases := []struct {
		name, input string
		limited     bool
	}{
		{"wrong_namespace", strings.ReplaceAll(testWindowsEvent, windowsEventNS, "urn:other"), false},
		{"unrelated_root", "<Report>" + testWindowsEvent + "</Report>", false},
		{"doctype", "<!DOCTYPE Event [<!ENTITY x SYSTEM \"file:///etc/passwd\">]>" + testWindowsEvent, false},
		{"custom_entity", strings.Replace(testWindowsEvent, "DataSecret", "&unknown;", 1), false},
		{"processing_instruction", "<?fetch resource?>" + testWindowsEvent, false},
		{"duplicate_attribute", strings.Replace(testWindowsEvent, "Name=\"ProviderSecret\"", "Name=\"a\" Name=\"b\"", 1), false},
		{"text_limit", strings.Replace(testWindowsEvent, "DataSecret", strings.Repeat("x", 4097), 1), true},
		{"attribute_limit", strings.Replace(testWindowsEvent, "ProviderSecret", strings.Repeat("x", 4097), 1), true},
		{"attribute_count", strings.Replace(testWindowsEvent, "<System>", "<System "+func() string {
			var b strings.Builder
			for i := 0; i < 33; i++ {
				b.WriteString("a" + strconv.Itoa(i) + "=\"x\" ")
			}
			return b.String()
		}()+">", 1), true},
		{"depth", strings.Replace(testWindowsEvent, "DataSecret", strings.Repeat("<n>", 33)+strings.Repeat("</n>", 33), 1), true},
		{"nodes", strings.Replace(testWindowsEvent, "DataSecret", strings.Repeat("<n/>", 2049), 1), true},
		{"record_bytes", strings.Replace(testWindowsEvent, "DataSecret", "<!--"+strings.Repeat("x", 256<<10)+"-->", 1), true},
		{"file_bytes", strings.Repeat(" ", 8<<20) + testWindowsEvent, true},
		{"tokens", strings.Repeat("<!--x-->", windowsXMLTokenLimit) + testWindowsEvent, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev, s, _ := parseWindowsXML([]byte(c.input), Item{}, 20000)
			if s.Error == "" || s.Limited != c.limited || len(ev) != 0 || s.Rows != s.Parsed+s.Skipped {
				t.Fatalf("%+v", s)
			}
		})
	}
	for _, tail := range []string{"<Event xmlns=\"" + windowsEventNS + "\"><System>", "<Events>", "trailing text"} {
		ev, s, _ := parseWindowsXML([]byte(testWindowsEvent+tail), Item{}, 10)
		if len(ev) != 1 || s.Error == "" || s.Rows != s.Parsed+s.Skipped {
			t.Fatalf("valid prefix lost: %+v", s)
		}
	}
	ev, s, _ := parseWindowsXML([]byte(testWindowsEvent+testWindowsEvent), Item{}, 1)
	if len(ev) != 1 || !s.Limited || s.Error != "" || s.Rows != 1 {
		t.Fatalf("budget: %+v", s)
	}
	_, s, decoded := parseWindowsXML(windowsUTF16(testWindowsEvent, binary.LittleEndian), Item{}, 0)
	if !s.Limited || s.Rows != 0 || string(decoded) != testWindowsEvent {
		t.Fatal(s)
	}
	_, s, _ = parseWindowsXML([]byte(strings.Repeat(`<Event xmlns="`+windowsEventNS+`"/>`, windowsXMLRecordLimit+1)), Item{}, windowsXMLRecordLimit+1)
	if s.Rows != windowsXMLRecordLimit || s.Skipped != windowsXMLRecordLimit || !s.Limited || s.Error != "" {
		t.Fatalf("per-file record bound: %+v", s)
	}
	empty, s, _ := parseWindowsXML([]byte("<Events/>"), Item{}, 10)
	if len(empty) != 0 || s.Error != "" {
		t.Fatal(s)
	}
}

func TestWindowsXMLInvalidEncodingsAndDeclarations(t *testing.T) {
	invalid := [][]byte{{0xff}, {0xff, 0xfe, 0}, {0xff, 0xfe, 0, 0xd8}, {0xfe, 0xff, 0xdc, 0}, {0xff, 0xfe, 0, 0xd8, 0, 0}, []byte("a\x00b")}
	for _, raw := range invalid {
		_, s, _ := parseWindowsXML(raw, Item{}, 1)
		if s.Error == "" {
			t.Fatalf("accepted %x", raw)
		}
	}
	for _, enc := range []string{"UTF-16", "UTF-16LE", "UTF-16BE", "UTF-8", "iso-8859-1"} {
		declaration := `<?xml version="1.0" encoding="` + enc + `"?>`
		for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
			_, s, _ := parseWindowsXML(windowsUTF16(declaration+testWindowsEvent, order), Item{}, 1)
			supported := enc == "UTF-16" || (enc == "UTF-16LE" && order == binary.LittleEndian) || (enc == "UTF-16BE" && order == binary.BigEndian)
			if (s.Error == "") != supported {
				t.Fatalf("%s %T: %+v", enc, order, s)
			}
		}
		_, s, _ := parseWindowsXML([]byte(declaration+testWindowsEvent), Item{}, 1)
		if (s.Error == "") != (enc == "UTF-8") {
			t.Fatalf("utf8/%s: %+v", enc, s)
		}
	}
}

func TestWindowsXMLPayloadAndMessageLimits(t *testing.T) {
	raw := strings.Replace(testWindowsEvent, "&lt;script&gt;MessageSecret&lt;/script&gt;", strings.Repeat("é", 401), 1)
	raw = strings.Replace(raw, "</EventData>", "<Binary>0011</Binary><ComplexData><Unknown/></ComplexData></EventData><UserData>"+testWindowsEvent+"</UserData>", 1)
	ev, s, _ := parseWindowsXML([]byte(raw), Item{}, 20)
	if len(ev) != 1 || s.Parsed != 1 || !ev[0].Windows.PayloadOmitted || !ev[0].Windows.MessageTruncated || len([]rune(ev[0].Detail)) != 400 {
		t.Fatalf("%+v %+v", s, ev)
	}
}

func TestWindowsXMLAnalysisExportAndShare(t *testing.T) {
	d, o := fixture(t, false)
	raw := windowsUTF16(strings.Replace(testWindowsEvent, "ProviderSecret", "=ProviderSecret", 1), binary.LittleEndian)
	if err := os.WriteFile(filepath.Join(o.Root, "events.XML"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(o.Root, "peer.jsonl"), []byte(`{"timestamp":"2026-09-29T11:02:03Z","user":"S-1-5-21-123","host":"host"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Collect(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	p, err := Open(o.Out, "")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Zip.Close()
	a := Analyze(p, []Rule{{ID: "unicode", Contains: "Café"}})
	ev := windowsEvents(a.Timeline)
	if len(ev) != 1 || len(a.Correlations) != 2 || len(a.Findings) != 1 {
		t.Fatalf("events=%d correlations=%d findings=%d", len(ev), len(a.Correlations), len(a.Findings))
	}
	for _, c := range a.Correlations {
		if c.Sources != 2 || c.Events != 2 {
			t.Fatal(c)
		}
	}
	out := filepath.Join(d, "windows-report")
	if err := Export(a, out); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAnalysis(filepath.Join(out, "analysis.json")); err != nil {
		t.Fatal(err)
	}
	csvBytes, err := os.ReadFile(filepath.Join(out, "windows-events.csv"))
	if err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(bytes.NewReader(csvBytes)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[1][6] != "'=ProviderSecret" || rows[1][11] != "18446744073709551615" {
		t.Fatalf("%v", rows)
	}
	html, err := os.ReadFile(filepath.Join(out, "report.html"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(html, []byte("Windows event XML records")) || bytes.Contains(html, []byte("<script>MessageSecret")) || !bytes.Contains(html, []byte("&lt;script&gt;MessageSecret")) {
		t.Fatal("HTML missing/unsafe")
	}
	before := JSON(a)
	for _, keep := range [][]string{nil, {"users", "hosts", "timestamps", "paths"}} {
		shared, err := BuildSharedReport(a, SharePolicy{Schema: sharePolicySchema, Keep: keep})
		if err != nil {
			t.Fatal(err)
		}
		encoded := JSON(shared)
		for _, secret := range []string{"ProviderSecret", "GUIDSecret", "LegacySecret", "ChannelSecret", "DataSecret", "MessageSecret", "18446744073709551615", "Café"} {
			if bytes.Contains(encoded, []byte(secret)) {
				t.Fatalf("shared context leak %s", secret)
			}
		}
		if !bytes.Contains(encoded, []byte("windows_event")) || !bytes.Contains(encoded, []byte(windowsXMLFormat)) {
			t.Fatal("shared count/type missing")
		}
	}
	if !bytes.Equal(before, JSON(a)) {
		t.Fatal("analysis mutated by sharing")
	}
	a.Timeline = nil
	out = filepath.Join(d, "no-windows-report")
	if err := Export(a, out); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(out, "windows-events.csv")); !os.IsNotExist(err) {
		t.Fatal("empty Windows CSV created")
	}
	html, _ = os.ReadFile(filepath.Join(out, "report.html"))
	if bytes.Contains(html, []byte("Windows event XML records")) {
		t.Fatal("empty Windows section rendered")
	}
}

func FuzzWindowsXML(f *testing.F) {
	for _, raw := range [][]byte{[]byte(testWindowsEvent), windowsUTF16(testWindowsEvent, binary.LittleEndian), windowsUTF16(testWindowsEvent, binary.BigEndian), []byte("<Events/>"), []byte("<!DOCTYPE x>"), []byte(testWindowsEvent + "<broken>")} {
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 8<<20 {
			t.Skip()
		}
		ev, s, _ := parseWindowsXML(raw, Item{ID: "E1"}, 100)
		if s.Rows != s.Parsed+s.Skipped || s.Parsed != len(ev) || s.Rows > 100 {
			t.Fatalf("count invariant: %+v", s)
		}
		for _, e := range ev {
			if e.Windows == nil || e.Type != "windows_event" || e.ByteOffset < 0 || e.ByteOffset >= int64(len(raw)) || e.Line < 1 || e.Host == "" {
				t.Fatalf("invalid provenance %+v", e)
			}
		}
	})
}
