package core

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

const windowsEventNS = "http://schemas.microsoft.com/win/2004/08/events/event"
const windowsXMLFormat = "WindowsEventXML"
const windowsXMLRecordLimit = 20000
const windowsXMLTokenLimit = 250000

// Reject zone-less and sub-nanosecond values instead of guessing a zone or
// silently dropping timestamp precision accepted by time.Parse.
var windowsXMLTime = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]([01]\d|2[0-3]):[0-5]\d)$`)
var errWindowsXMLLimit = errors.New("XML resource limit exceeded")

// Record IDs stay decimal strings so consumers do not lose uint64 precision.
type WindowsEventContext struct {
	Provider         string             `json:"provider"`
	ProviderGUID     string             `json:"provider_guid,omitempty"`
	EventSource      string             `json:"event_source,omitempty"`
	EventID          uint16             `json:"event_id"`
	Qualifiers       *uint16            `json:"qualifiers,omitempty"`
	RecordID         string             `json:"record_id,omitempty"`
	Channel          string             `json:"channel,omitempty"`
	Level            *uint8             `json:"level,omitempty"`
	Version          *uint8             `json:"version,omitempty"`
	Data             []WindowsEventData `json:"data,omitempty"`
	PayloadOmitted   bool               `json:"payload_omitted"`
	MessageTruncated bool               `json:"message_truncated"`
}

type WindowsEventData struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type xmlOffset struct{ decoded, original int }
type eventXMLText struct {
	data     []byte
	encoding string
	bom      int
	offsets  []xmlOffset
}

// Decode UTF-16 once, retaining sparse offset anchors. Mapping a token back to
// the evidence scans at most one small anchor interval, not the whole prefix.
func decodeEventXML(raw []byte) (out eventXMLText, err error) {
	if len(raw) > 8<<20 {
		return out, fmt.Errorf("%w: file exceeds 8 MiB", errWindowsXMLLimit)
	}
	out.encoding = "utf-8"
	var order binary.ByteOrder
	switch {
	case bytes.HasPrefix(raw, []byte{0xff, 0xfe}):
		order, out.encoding, out.bom = binary.LittleEndian, "utf-16le", 2
	case bytes.HasPrefix(raw, []byte{0xfe, 0xff}):
		order, out.encoding, out.bom = binary.BigEndian, "utf-16be", 2
	case bytes.HasPrefix(raw, []byte{0xef, 0xbb, 0xbf}):
		out.bom = 3
	}
	if order == nil {
		out.data = raw[out.bom:]
		if !utf8.Valid(out.data) || bytes.IndexByte(out.data, 0) >= 0 {
			return out, errors.New("XML requires UTF-8 or BOM-marked UTF-16")
		}
		return out, nil
	}
	if (len(raw)-2)%2 != 0 {
		return out, errors.New("incomplete UTF-16 code unit")
	}
	out.offsets = []xmlOffset{{0, 2}}
	for i := 2; i < len(raw); {
		if len(out.data)-out.offsets[len(out.offsets)-1].decoded >= 4096 {
			out.offsets = append(out.offsets, xmlOffset{len(out.data), i})
		}
		r := rune(order.Uint16(raw[i:]))
		i += 2
		if utf16.IsSurrogate(r) {
			if r < 0xd800 || r > 0xdbff || i+2 > len(raw) {
				return out, errors.New("unpaired UTF-16 surrogate")
			}
			next := rune(order.Uint16(raw[i:]))
			if next < 0xdc00 || next > 0xdfff {
				return out, errors.New("unpaired UTF-16 surrogate")
			}
			i += 2
			r = utf16.DecodeRune(r, next)
		}
		out.data = utf8.AppendRune(out.data, r)
	}
	return out, nil
}

func (x eventXMLText) sourceOffset(decoded int64) int64 {
	if len(x.offsets) == 0 {
		return decoded + int64(x.bom)
	}
	i := sort.Search(len(x.offsets), func(i int) bool { return x.offsets[i].decoded > int(decoded) }) - 1
	anchor := x.offsets[max(i, 0)]
	for anchor.decoded < int(decoded) {
		r, n := utf8.DecodeRune(x.data[anchor.decoded:])
		anchor.decoded += n
		anchor.original += 2
		if r > 0xffff {
			anchor.original += 2
		}
	}
	return int64(anchor.original)
}

type eventXMLNode struct {
	name     xml.Name
	attrs    map[xml.Name]string
	children []*eventXMLNode
	text     strings.Builder
}

func newEventXMLNode(start xml.StartElement) (*eventXMLNode, error) {
	if len(start.Attr) > 32 {
		return nil, fmt.Errorf("%w: element exceeds 32 attributes", errWindowsXMLLimit)
	}
	n := &eventXMLNode{name: start.Name, attrs: map[xml.Name]string{}}
	for _, a := range start.Attr {
		if _, exists := n.attrs[a.Name]; exists {
			return nil, errors.New("duplicate XML attribute")
		}
		if len(a.Value) > 4096 {
			return nil, fmt.Errorf("%w: attribute exceeds 4096 bytes", errWindowsXMLLimit)
		}
		n.attrs[a.Name] = a.Value
	}
	return n, nil
}
func (n *eventXMLNode) attr(name string) string { return n.attrs[xml.Name{Local: name}] }
func (n *eventXMLNode) child(name string) (*eventXMLNode, error) {
	var found *eventXMLNode
	for _, c := range n.children {
		if c.name == (xml.Name{Space: windowsEventNS, Local: name}) {
			if found != nil {
				return nil, fmt.Errorf("duplicate %s element", name)
			}
			found = c
		}
	}
	return found, nil
}
func (n *eventXMLNode) scalar(name string) (string, error) {
	child, err := n.child(name)
	if err != nil || child == nil {
		return "", err
	}
	if len(child.children) != 0 {
		return "", errors.New("nested content in scalar field")
	}
	return strings.TrimSpace(child.text.String()), nil
}
func xmlUnsigned(s string, bits int) (uint64, error) {
	if s == "" || strings.Trim(s, "0123456789") != "" {
		return 0, errors.New("unsigned decimal field required")
	}
	return strconv.ParseUint(s, 10, bits)
}

func windowsEventFromXML(root *eventXMLNode, it Item, line int, offset int64) (Event, string) {
	system, err := root.child("System")
	if err != nil || system == nil || strings.TrimSpace(system.text.String()) != "" {
		return Event{}, "invalid_system"
	}
	provider, pe := system.child("Provider")
	created, te := system.child("TimeCreated")
	idNode, ie := system.child("EventID")
	if pe != nil || te != nil || ie != nil || provider == nil || created == nil || idNode == nil || len(provider.children) != 0 || len(created.children) != 0 || strings.TrimSpace(provider.text.String()) != "" || strings.TrimSpace(created.text.String()) != "" {
		return Event{}, "missing_or_ambiguous_system_field"
	}
	w := &WindowsEventContext{Provider: provider.attr("Name"), ProviderGUID: provider.attr("Guid"), EventSource: provider.attr("EventSourceName")}
	if w.Provider == "" && w.ProviderGUID == "" && w.EventSource == "" {
		return Event{}, "missing_provider"
	}
	values := map[string]string{}
	for _, key := range []string{"EventID", "EventRecordID", "Channel", "Computer", "Level", "Version"} {
		value, err := system.scalar(key)
		if err != nil {
			return Event{}, "ambiguous_system_field"
		}
		values[key] = value
	}
	id, err := xmlUnsigned(values["EventID"], 16)
	if err != nil {
		return Event{}, "invalid_event_id"
	}
	w.EventID = uint16(id)
	if q, exists := idNode.attrs[xml.Name{Local: "Qualifiers"}]; exists {
		value, err := xmlUnsigned(q, 16)
		if err != nil {
			return Event{}, "invalid_qualifiers"
		}
		v := uint16(value)
		w.Qualifiers = &v
	}
	if recordNode, _ := system.child("EventRecordID"); recordNode != nil {
		record := values["EventRecordID"]
		value, err := xmlUnsigned(record, 64)
		if err != nil {
			return Event{}, "invalid_record_id"
		}
		w.RecordID = strconv.FormatUint(value, 10)
	}
	for key, ptr := range map[string]**uint8{"Level": &w.Level, "Version": &w.Version} {
		if node, _ := system.child(key); node != nil {
			value := values[key]
			n, err := xmlUnsigned(value, 8)
			if err != nil {
				return Event{}, "invalid_level_or_version"
			}
			v := uint8(n)
			*ptr = &v
		}
	}
	stamp := created.attr("SystemTime")
	tm, err := time.Parse(time.RFC3339Nano, stamp)
	_, rawTime := created.attrs[xml.Name{Local: "RawTime"}]
	if err != nil || rawTime || !windowsXMLTime.MatchString(stamp) {
		return Event{}, "unsupported_timestamp"
	}
	computer := strings.ToLower(strings.TrimSuffix(values["Computer"], "."))
	security, err := system.child("Security")
	if err != nil || (security != nil && (len(security.children) != 0 || strings.TrimSpace(security.text.String()) != "")) {
		return Event{}, "ambiguous_security"
	}
	user := ""
	if security != nil {
		user = security.attr("UserID")
	}
	if computer == "" || len(computer) > 256 || len(user) > 256 {
		return Event{}, "invalid_host_or_user_length"
	}
	w.Channel = values["Channel"]
	ev := Event{Windows: w, Time: tm.UTC(), OriginalTime: stamp, Type: "windows_event", Evidence: it.ID, Source: it.Source, Line: line, ByteOffset: offset, Host: computer, User: user}
	payload, err := root.child("EventData")
	if err != nil {
		return Event{}, "ambiguous_event_data"
	}
	if payload != nil {
		if strings.TrimSpace(payload.text.String()) != "" {
			return Event{}, "invalid_event_data"
		}
		for _, field := range payload.children {
			if field.name != (xml.Name{Space: windowsEventNS, Local: "Data"}) {
				w.PayloadOmitted = true
				continue
			}
			if len(w.Data) >= 64 || len(field.attr("Name")) > 256 || len(field.children) != 0 {
				return Event{}, "unsupported_event_data"
			}
			w.Data = append(w.Data, WindowsEventData{Name: field.attr("Name"), Value: field.text.String()})
		}
	}
	rendering, err := root.child("RenderingInfo")
	if err != nil {
		return Event{}, "ambiguous_rendering_info"
	}
	if rendering != nil {
		message, err := rendering.scalar("Message")
		if err != nil {
			return Event{}, "ambiguous_message"
		}
		runes := []rune(message)
		w.MessageTruncated = len(runes) > 400
		ev.Detail = string(runes[:min(len(runes), 400)])
	}
	for _, child := range root.children {
		if child.name.Space != windowsEventNS || (child.name.Local != "System" && child.name.Local != "EventData" && child.name.Local != "RenderingInfo") {
			w.PayloadOmitted = true
		}
	}
	return ev, ""
}

// parseWindowsXML accepts an Events wrapper or a sequence of Event fragments.
// No directives, custom entities, external resources or provider code are used.
func parseWindowsXML(raw []byte, it Item, budget int) (events []Event, s ParseSummary, decoded []byte) {
	s = ParseSummary{Evidence: it.ID, Format: windowsXMLFormat, SkipReasons: map[string]int{}}
	x, err := decodeEventXML(raw)
	if err != nil {
		s.Error = err.Error()
		s.Limited = errors.Is(err, errWindowsXMLLimit)
		return
	}
	decoded = x.data
	// Timeline exhaustion must not suppress the independent literal-rule scan.
	if budget <= 0 {
		s.Limited = true
		return
	}
	d := xml.NewDecoder(bytes.NewReader(decoded))
	d.CharsetReader = func(label string, input io.Reader) (io.Reader, error) {
		label = strings.ToLower(label)
		if x.encoding != "utf-8" && (label == x.encoding || label == "utf-16") {
			return input, nil // The bytes were already decoded with offset tracking.
		}
		return nil, errors.New("XML encoding declaration disagrees with supported input encoding")
	}
	var stack []*eventXMLNode
	var root *eventXMLNode
	var start int64
	var line, nodes int
	mode := ""
	closed := false
	fail := func(message string, limited bool) {
		s.Error, s.Limited = message, limited
		if root != nil {
			s.Skipped++
			s.SkipReasons["incomplete_or_invalid_xml"]++
		}
	}
	for tokens := 0; ; tokens++ {
		if tokens >= windowsXMLTokenLimit {
			fail("XML token budget exceeded", true)
			return
		}
		offset := d.InputOffset()
		currentLine, _ := d.InputPos()
		token, e := d.Token()
		if e == io.EOF {
			if mode == "" || (mode == "events" && !closed) || root != nil {
				fail("incomplete Windows event XML", false)
			}
			return
		}
		if e != nil {
			fail("XML parsing stopped: "+e.Error(), false)
			return
		}
		if root != nil && d.InputOffset()-start > 256<<10 {
			fail("XML event exceeds 256 KiB decoded bytes", true)
			return
		}
		switch v := token.(type) {
		case xml.Directive:
			fail("XML directives and DTDs are not supported", false)
			return
		case xml.ProcInst:
			if v.Target != "xml" || offset != 0 || len(v.Inst) > 4096 {
				fail("unsupported XML processing instruction", false)
				return
			}
			// Inspect declaration attributes after decoding, including the UTF-8
			// declaration path for which encoding/xml does not call CharsetReader.
			declaration := xml.NewDecoder(strings.NewReader("<declaration " + string(v.Inst) + "/>"))
			t, e := declaration.Token()
			startTag, ok := t.(xml.StartElement)
			if e != nil || !ok {
				fail("invalid XML declaration", false)
				return
			}
			n, e := newEventXMLNode(startTag)
			if e != nil {
				fail("invalid XML declaration", false)
				return
			}
			enc := strings.ToLower(n.attr("encoding"))
			if enc != "" && enc != x.encoding && !(enc == "utf-16" && x.encoding != "utf-8") {
				fail("XML encoding declaration mismatch", false)
				return
			}
		case xml.StartElement:
			n, e := newEventXMLNode(v)
			if e != nil {
				fail(e.Error(), errors.Is(e, errWindowsXMLLimit))
				return
			}
			if root == nil {
				if mode == "" && v.Name.Local == "Events" && (v.Name.Space == "" || v.Name.Space == windowsEventNS) {
					mode = "events"
					continue
				}
				if closed || v.Name != (xml.Name{Space: windowsEventNS, Local: "Event"}) {
					fail("expected Windows Event namespace and Event/Events structure", false)
					return
				}
				if mode == "" {
					mode = "fragments"
				}
				if s.Rows >= min(budget, windowsXMLRecordLimit) {
					s.Limited = true
					return
				}
				s.Rows++
				root, start, line, nodes = n, offset, currentLine, 0
			} else {
				stack[len(stack)-1].children = append(stack[len(stack)-1].children, n)
			}
			nodes++
			stack = append(stack, n)
			if len(stack) > 32 || nodes > 2048 {
				fail("XML event depth/node limit exceeded", true)
				return
			}
		case xml.CharData:
			if len(stack) == 0 {
				if len(bytes.TrimSpace(v)) > 0 {
					fail("unexpected text outside Event", false)
					return
				}
			} else {
				n := stack[len(stack)-1]
				if n.text.Len()+len(v) > 4096 {
					fail("XML field text exceeds 4096 bytes", true)
					return
				}
				n.text.Write(v)
			}
		case xml.EndElement:
			if len(stack) == 0 {
				if mode != "events" || closed || v.Name.Local != "Events" {
					fail("unexpected XML closing element", false)
					return
				}
				closed = true
				continue
			}
			stack = stack[:len(stack)-1]
			if len(stack) == 0 {
				if strings.TrimSpace(root.text.String()) != "" {
					s.Skipped++
					s.SkipReasons["unexpected_event_text"]++
				} else if event, reason := windowsEventFromXML(root, it, line, x.sourceOffset(start)); reason != "" {
					s.Skipped++
					s.SkipReasons[reason]++
				} else {
					events = append(events, event)
					s.Parsed++
				}
				root = nil
			}
		}
	}
}
