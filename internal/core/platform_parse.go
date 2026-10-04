package core

import (
	"bytes"
	"encoding/binary"
	"encoding/csv"
	"encoding/xml"
	"io"
	"sort"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	eventScheduledTask = "scheduled_task"
	eventLaunchAgent   = "launch_agent"
	eventSystemdExec   = "systemd_exec"
	eventPrefetch      = "prefetch"
	taskNamespace      = "http://schemas.microsoft.com/windows/2004/02/mit/task"
)

// prefetchEvent reads the executable name from a Windows Prefetch header.
// Run counts are not reported; their offset depends on the Windows version.
func prefetchEvent(b []byte, it Item) (Event, bool) {
	if len(b) < 76 || !bytes.Equal(b[4:8], []byte("SCCA")) {
		return Event{}, false
	}
	switch binary.LittleEndian.Uint32(b[0:4]) {
	case 17, 23, 26, 30:
	default:
		return Event{}, false
	}
	name := utf16LEString(b[16:], 29)
	if !validPrefetchName(name) {
		return Event{}, false
	}
	return Event{Time: evidenceTime(it), Type: eventPrefetch, Evidence: it.ID, Source: it.Source, Detail: name}, true
}

func validPrefetchName(name string) bool {
	if name == "" || len(name) > 60 || !strings.Contains(name, ".") {
		return false
	}
	for _, r := range name {
		if r < 32 || r == '/' || r == '\\' || r == utf8.RuneError {
			return false
		}
	}
	return true
}

// parsePersistence extracts commands from Windows Task Scheduler XML, XML
// launchd plists and systemd unit files. ok is false when the bytes are a
// different format.
func parsePersistence(b []byte, it Item, budget int) ([]Event, ParseSummary, bool) {
	text := decodeBOM(b)
	switch {
	case bytes.Contains(text, []byte(taskNamespace)):
		return parseScheduledTask(text, it, budget)
	case bytes.Contains(text, []byte("<plist")) && bytes.Contains(text, []byte("<dict")):
		return parseLaunchdPlist(text, it, budget)
	case systemdUnit(text, it.Source):
		return parseSystemdUnit(text, it, budget)
	default:
		return nil, ParseSummary{}, false
	}
}

func systemdUnit(text []byte, source string) bool {
	if !bytes.Contains(text, []byte("ExecStart=")) {
		return false
	}
	return bytes.Contains(text, []byte("[Service]")) || strings.HasSuffix(strings.ToLower(source), ".service")
}

func parseScheduledTask(text []byte, it Item, budget int) ([]Event, ParseSummary, bool) {
	summary := ParseSummary{Evidence: it.ID, Format: "WindowsScheduledTask"}
	dec := xml.NewDecoder(bytes.NewReader(text))
	dec.CharsetReader = func(_ string, input io.Reader) (io.Reader, error) {
		return input, nil
	}
	var stack []xml.Name
	var user, command, args string
	var events []Event
	tokens := 0
	for {
		tok, e := dec.Token()
		if e == io.EOF {
			break
		}
		tokens++
		if tokens > 100000 {
			summary.Limited = true
			break
		}
		if e != nil {
			summary.Error = e.Error()
			break
		}
		switch el := tok.(type) {
		case xml.StartElement:
			if len(stack) == 0 && (el.Name.Local != "Task" || el.Name.Space != taskNamespace) {
				summary.Error = "expected Task root in the Windows Task Scheduler namespace"
				return nil, summary, true
			}
			stack = append(stack, el.Name)
			if len(stack) > 32 {
				summary.Limited = true
				return events, summary, true
			}
			if taskPath(stack, "Task", "Principals", "Principal", "UserId") {
				user = ""
			}
			if taskPath(stack, "Task", "Actions", "Exec") {
				command, args = "", ""
			}
		case xml.EndElement:
			if taskPath(stack, "Task", "Actions", "Exec") && strings.TrimSpace(command) != "" {
				summary.Rows++
				if len(events) < budget {
					detail := strings.TrimSpace(strings.TrimSpace(command) + " " + strings.TrimSpace(args))
					events = append(events, Event{Time: evidenceTime(it), Type: eventScheduledTask, Evidence: it.ID, Source: it.Source, User: strings.TrimSpace(user), Detail: detail})
					summary.Parsed++
				} else {
					summary.Limited = true
				}
			}
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		case xml.CharData:
			// XML entities and CDATA may split one value into multiple tokens.
			switch {
			case taskPath(stack, "Task", "Actions", "Exec", "Command"):
				command += string(el)
			case taskPath(stack, "Task", "Actions", "Exec", "Arguments"):
				args += string(el)
			case taskPath(stack, "Task", "Principals", "Principal", "UserId"):
				user += string(el)
			}
		}
	}
	return events, summary, true
}

// A matching local name in a different XML namespace is a different element.
func taskPath(stack []xml.Name, path ...string) bool {
	if len(stack) != len(path) {
		return false
	}
	for i, name := range stack {
		if name.Space != taskNamespace || name.Local != path[i] {
			return false
		}
	}
	return true
}

func parseLaunchdPlist(text []byte, it Item, budget int) ([]Event, ParseSummary, bool) {
	summary := ParseSummary{Evidence: it.ID, Format: "LaunchdPlist"}
	if !bytes.Contains(text, []byte("<key>Label</key>")) && !bytes.Contains(text, []byte("<key>ProgramArguments</key>")) && !bytes.Contains(text, []byte("<key>Program</key>")) {
		return nil, ParseSummary{}, false
	}
	dec := xml.NewDecoder(bytes.NewReader(text))
	var stack []string
	var key, scalar string
	var label, program, user string
	var args []string
	inArgs := false
	tokens := 0
	for {
		tok, e := dec.Token()
		if e == io.EOF {
			break
		}
		tokens++
		if tokens > 100000 {
			summary.Limited = true
			break
		}
		if e != nil {
			summary.Error = e.Error()
			break
		}
		switch el := tok.(type) {
		case xml.StartElement:
			stack = append(stack, el.Name.Local)
			if len(stack) > 32 {
				summary.Limited = true
				return nil, summary, true
			}
			if el.Name.Local == "key" || el.Name.Local == "string" {
				scalar = ""
			}
			if el.Name.Local == "array" && key == "ProgramArguments" {
				inArgs = true
				args = nil
			}
		case xml.EndElement:
			value := strings.TrimSpace(scalar)
			if len(stack) == 3 && stack[0] == "plist" && stack[1] == "dict" {
				if el.Name.Local == "key" {
					key = value
				}
				if el.Name.Local == "string" {
					switch key {
					case "Label":
						label = value
					case "Program":
						program = value
					case "UserName":
						user = value
					}
				}
			}
			if inArgs && len(stack) == 4 && el.Name.Local == "string" {
				args = append(args, value)
			}
			if el.Name.Local == "array" {
				inArgs = false
			}
			if el.Name.Local != "key" {
				key = ""
			}
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		case xml.CharData:
			if len(stack) > 0 && (stack[len(stack)-1] == "key" || stack[len(stack)-1] == "string") {
				scalar += string(el)
			}
		}
	}
	detail := program
	if len(args) > 0 {
		detail = strings.Join(args, " ")
	}
	if label != "" && detail != "" {
		detail = label + ": " + detail
	} else if detail == "" {
		detail = label
	}
	if detail == "" || budget <= 0 {
		if budget <= 0 {
			summary.Limited = true
		}
		summary.Rows = 1
		return nil, summary, true
	}
	summary.Rows = 1
	summary.Parsed = 1
	return []Event{{Time: evidenceTime(it), Type: eventLaunchAgent, Evidence: it.ID, Source: it.Source, User: user, Detail: detail}}, summary, true
}

func parseSystemdUnit(text []byte, it Item, budget int) ([]Event, ParseSummary, bool) {
	summary := ParseSummary{Evidence: it.ID, Format: "SystemdUnit"}
	type directive struct {
		key, value string
		line       int
	}
	var directives []directive
	section := ""
	lines := strings.Split(string(text), "\n")
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		start := i + 1
		for strings.HasSuffix(line, `\`) && i+1 < len(lines) {
			line = strings.TrimSuffix(line, `\`) + " " + strings.TrimSpace(lines[i+1])
			i++
		}
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}
		if section != "Service" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if ok {
			directives = append(directives, directive{strings.TrimSpace(key), strings.TrimSpace(value), start})
		}
	}
	// Unit directives are declarative: User applies regardless of line order.
	// An empty ExecStart assignment resets previous commands of the same kind.
	var user string
	commands := map[string][]directive{}
	for _, d := range directives {
		switch d.key {
		case "User":
			user = d.value
		case "ExecStart", "ExecStartPre", "ExecStartPost":
			if d.value == "" {
				commands[d.key] = nil
			} else {
				commands[d.key] = append(commands[d.key], d)
			}
		}
	}
	var active []directive
	for _, rows := range commands {
		active = append(active, rows...)
	}
	sort.Slice(active, func(i, j int) bool { return active[i].line < active[j].line })
	var events []Event
	for _, d := range active {
		summary.Rows++
		if len(events) >= budget {
			summary.Limited = true
			continue
		}
		events = append(events, Event{Time: evidenceTime(it), Type: eventSystemdExec, Evidence: it.ID, Source: it.Source, User: user, Detail: d.value, Line: d.line})
		summary.Parsed++
	}
	return events, summary, true
}

func evidenceTime(it Item) time.Time {
	if !it.Modified.IsZero() {
		return it.Modified.UTC()
	}
	return it.Collected.UTC()
}

func decodeBOM(b []byte) []byte {
	switch {
	case bytes.HasPrefix(b, []byte{0xff, 0xfe}):
		return utf16Bytes(b[2:], binary.LittleEndian)
	case bytes.HasPrefix(b, []byte{0xfe, 0xff}):
		return utf16Bytes(b[2:], binary.BigEndian)
	case bytes.HasPrefix(b, []byte{0xef, 0xbb, 0xbf}):
		return b[3:]
	default:
		return b
	}
}

func utf16Bytes(b []byte, order binary.ByteOrder) []byte {
	if len(b) < 2 {
		return nil
	}
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	raw := make([]uint16, len(b)/2)
	for i := range raw {
		raw[i] = order.Uint16(b[i*2:])
	}
	return []byte(string(utf16.Decode(raw)))
}

func utf16LEString(b []byte, maxUnits int) string {
	if len(b) < 2 {
		return ""
	}
	units := len(b) / 2
	if units > maxUnits {
		units = maxUnits
	}
	raw := make([]uint16, 0, units)
	for i := 0; i < units; i++ {
		v := binary.LittleEndian.Uint16(b[i*2:])
		if v == 0 {
			break
		}
		raw = append(raw, v)
	}
	return string(utf16.Decode(raw))
}

func persistenceEvent(ev Event) bool {
	switch ev.Type {
	case eventScheduledTask, eventLaunchAgent, eventSystemdExec, eventPrefetch:
		return true
	default:
		return false
	}
}

func writePersistence(a Analysis, path string) error {
	var b bytes.Buffer
	w := csv.NewWriter(&b)
	_ = w.Write([]string{"time_utc", "event_type", "evidence_id", "source", "user", "detail"})
	for _, ev := range a.Timeline {
		if !persistenceEvent(ev) {
			continue
		}
		_ = w.Write([]string{ev.Time.UTC().Format(time.RFC3339Nano), ev.Type, ev.Evidence, csvSafe(ev.Source), csvSafe(ev.User), csvSafe(ev.Detail)})
	}
	w.Flush()
	if e := w.Error(); e != nil {
		return e
	}
	return WriteNew(path, b.Bytes())
}
