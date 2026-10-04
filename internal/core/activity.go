package core

import (
	"bytes"
	"encoding/csv"
	"net/netip"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const activityLimit = 10000

// Activity is one interpreted action from collected host evidence.
// It is a triage reading of a log line, event field or command text.
type Activity struct {
	Time         time.Time `json:"time,omitempty"`
	OriginalTime string    `json:"original_time,omitempty"`
	Platform     string    `json:"platform"`
	Category     string    `json:"category"`
	Action       string    `json:"action"`
	User         string    `json:"user,omitempty"`
	SourceIP     string    `json:"source_ip,omitempty"`
	Target       string    `json:"target,omitempty"`
	Detail       string    `json:"detail,omitempty"`
	Evidence     string    `json:"evidence"`
	Source       string    `json:"source"`
	Line         int       `json:"line,omitempty"`
}

// ActivityCount is how many interpreted rows share one platform and action.
type ActivityCount struct {
	Platform string `json:"platform"`
	Action   string `json:"action"`
	Count    int    `json:"count"`
}

var (
	reSSHFail  = regexp.MustCompile(`Failed password for (?:invalid user )?(\S+) from (\S+)`)
	reSSHOK    = regexp.MustCompile(`Accepted (password|publickey|keyboard-interactive) for (\S+) from (\S+)`)
	reSudo     = regexp.MustCompile(`sudo:\s+(\S+)\s*:.*COMMAND=(.+)`)
	reCron     = regexp.MustCompile(`CRON\[\d+\]:\s+\((\S+)\)\s+CMD\s+\((.*)\)`)
	reUserAdd  = regexp.MustCompile(`(?:useradd|new user:)[^\n]*\bname=(\S+)`)
	reZshHist  = regexp.MustCompile(`^: (\d+):\d+;(.*)$`)
	reBashWhen = regexp.MustCompile(`^#(\d{9,12})$`)
)

var logonTypeNames = map[string]string{
	"2":  "interactive",
	"3":  "network",
	"4":  "batch",
	"5":  "service",
	"7":  "unlock",
	"8":  "network cleartext",
	"9":  "new credentials",
	"10": "remote interactive",
	"11": "cached interactive",
}

func activitiesFromText(b []byte, it Item) []Activity {
	if !utf8.Valid(b) || bytes.IndexByte(b, 0) >= 0 {
		return nil
	}
	if isShellHistory(it.Source) {
		return shellActivities(string(b), it)
	}
	var out []Activity
	for i, line := range strings.Split(string(b), "\n") {
		if act, ok := activityFromLogLine(line, it, i+1); ok {
			out = append(out, act)
		}
	}
	return out
}

func isShellHistory(source string) bool {
	base := strings.ToLower(filepath.Base(source))
	switch base {
	case ".bash_history", ".zsh_history", ".sh_history", ".python_history", "consolehost_history.txt":
		return true
	}
	return strings.Contains(strings.ToLower(source), ".zsh_sessions")
}

func shellActivities(text string, it Item) []Activity {
	platform := "linux"
	if strings.Contains(strings.ToLower(it.Source), "consolehost_history") {
		platform = "windows"
	}
	var pending time.Time
	var pendingRaw string
	var out []Activity
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		if m := reBashWhen.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
			sec, e := strconv.ParseInt(m[1], 10, 64)
			if e == nil {
				pending = time.Unix(sec, 0).UTC()
				pendingRaw = m[1]
			}
			continue
		}
		when, raw := pending, pendingRaw
		pending, pendingRaw = time.Time{}, ""
		command := line
		if m := reZshHist.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
			if sec, e := strconv.ParseInt(m[1], 10, 64); e == nil {
				when = time.Unix(sec, 0).UTC()
				raw = m[1]
			}
			command = m[2]
		}
		command = strings.TrimSpace(command)
		if command == "" {
			continue
		}
		if len(out) >= 2000 {
			break
		}
		action, category := commandClass(command)
		out = append(out, Activity{
			Time: when, OriginalTime: raw, Platform: platform, Category: category, Action: action,
			Target: clip(command, 400), Detail: clip(command, 400), Evidence: it.ID, Source: it.Source, Line: i + 1,
		})
	}
	return out
}

func commandClass(command string) (action, category string) {
	l := strings.ToLower(command)
	switch {
	case strings.Contains(l, "/dev/tcp") || strings.Contains(l, "nc -") || strings.Contains(l, "ncat ") || strings.Contains(l, "bash -i"):
		return "remote_shell", "command"
	case strings.Contains(l, "base64") || strings.Contains(l, "-enc") || strings.Contains(l, "frombase64string"):
		return "encoded_command", "command"
	case strings.Contains(l, "curl ") || strings.HasPrefix(l, "curl ") || strings.Contains(l, "wget ") || strings.Contains(l, "invoke-webrequest") || strings.Contains(l, "iwr "):
		return "download", "command"
	case strings.Contains(l, "crontab") || strings.Contains(l, "systemctl enable") || strings.Contains(l, "schtasks") || strings.Contains(l, "launchctl load") || strings.Contains(l, "reg add"):
		return "persistence_command", "command"
	case strings.HasPrefix(l, "sudo ") || strings.Contains(l, " pkexec ") || strings.HasPrefix(l, "pkexec "):
		return "privilege_command", "command"
	default:
		return "command", "command"
	}
}

func activityFromLogLine(line string, it Item, lineNo int) (Activity, bool) {
	when, raw := lineTime(line)
	switch {
	case reSSHFail.MatchString(line):
		m := reSSHFail.FindStringSubmatch(line)
		return Activity{Time: when, OriginalTime: raw, Platform: "linux", Category: "authentication", Action: "ssh_failure", User: m[1], SourceIP: cleanIP(m[2]), Detail: clip(line, 400), Evidence: it.ID, Source: it.Source, Line: lineNo}, true
	case reSSHOK.MatchString(line):
		m := reSSHOK.FindStringSubmatch(line)
		return Activity{Time: when, OriginalTime: raw, Platform: "linux", Category: "authentication", Action: "ssh_success", User: m[2], SourceIP: cleanIP(m[3]), Target: m[1], Detail: clip(line, 400), Evidence: it.ID, Source: it.Source, Line: lineNo}, true
	case reSudo.MatchString(line):
		m := reSudo.FindStringSubmatch(line)
		return Activity{Time: when, OriginalTime: raw, Platform: hostPlatform(it.Source, "linux"), Category: "privilege", Action: "sudo", User: m[1], Target: clip(strings.TrimSpace(m[2]), 400), Detail: clip(line, 400), Evidence: it.ID, Source: it.Source, Line: lineNo}, true
	case reCron.MatchString(line):
		m := reCron.FindStringSubmatch(line)
		return Activity{Time: when, OriginalTime: raw, Platform: "linux", Category: "execution", Action: "cron", User: m[1], Target: clip(strings.TrimSpace(m[2]), 400), Detail: clip(line, 400), Evidence: it.ID, Source: it.Source, Line: lineNo}, true
	case reUserAdd.MatchString(line):
		m := reUserAdd.FindStringSubmatch(line)
		return Activity{Time: when, OriginalTime: raw, Platform: "linux", Category: "account", Action: "user_created", Target: m[1], Detail: clip(line, 400), Evidence: it.ID, Source: it.Source, Line: lineNo}, true
	default:
		return Activity{}, false
	}
}

func hostPlatform(source, fallback string) string {
	l := strings.ToLower(source)
	switch {
	case strings.Contains(l, "system.log") || strings.Contains(l, "unified-log") || strings.Contains(l, "/library/logs"):
		return "darwin"
	default:
		return fallback
	}
}

func deriveActivities(a *Analysis) {
	var extra []Activity
	for _, ev := range a.Timeline {
		switch ev.Type {
		case "windows_event":
			if act, ok := activityFromWindows(ev); ok {
				extra = append(extra, act)
			}
		case eventPrefetch:
			extra = append(extra, Activity{Time: ev.Time, Platform: "windows", Category: "execution", Action: "prefetch", Target: ev.Detail, Detail: ev.Detail, Evidence: ev.Evidence, Source: ev.Source})
		case eventScheduledTask:
			extra = append(extra, Activity{Time: ev.Time, Platform: "windows", Category: "persistence", Action: "scheduled_task", User: ev.User, Target: clip(ev.Detail, 400), Detail: clip(ev.Detail, 400), Evidence: ev.Evidence, Source: ev.Source})
		case eventLaunchAgent:
			extra = append(extra, Activity{Time: ev.Time, Platform: "darwin", Category: "persistence", Action: "launch_agent", User: ev.User, Target: clip(ev.Detail, 400), Detail: clip(ev.Detail, 400), Evidence: ev.Evidence, Source: ev.Source})
		case eventSystemdExec:
			extra = append(extra, Activity{Time: ev.Time, Platform: "linux", Category: "persistence", Action: "systemd_exec", User: ev.User, Target: clip(ev.Detail, 400), Detail: clip(ev.Detail, 400), Evidence: ev.Evidence, Source: ev.Source})
		}
	}
	appendActivities(a, extra)
	sort.SliceStable(a.Activities, func(i, j int) bool {
		if a.Activities[i].Time.Equal(a.Activities[j].Time) {
			return a.Activities[i].Action < a.Activities[j].Action
		}
		if a.Activities[i].Time.IsZero() {
			return false
		}
		if a.Activities[j].Time.IsZero() {
			return true
		}
		return a.Activities[i].Time.Before(a.Activities[j].Time)
	})
	counts := map[string]int{}
	for _, act := range a.Activities {
		counts[act.Platform+"\x00"+act.Action]++
	}
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	a.ActivityCounts = make([]ActivityCount, 0, len(keys))
	for _, key := range keys {
		platform, action, _ := strings.Cut(key, "\x00")
		a.ActivityCounts = append(a.ActivityCounts, ActivityCount{Platform: platform, Action: action, Count: counts[key]})
	}
}

func activityFromWindows(ev Event) (Activity, bool) {
	if ev.Windows == nil {
		return Activity{}, false
	}
	id := ev.Windows.EventID
	user := firstData(ev, "TargetUserName", "SubjectUserName")
	ip := cleanIP(firstData(ev, "IpAddress", "SourceAddress"))
	act := Activity{Time: ev.Time, OriginalTime: ev.OriginalTime, Platform: "windows", User: user, SourceIP: ip, Evidence: ev.Evidence, Source: ev.Source, Line: ev.Line}
	switch id {
	case 4624:
		kind := logonTypeNames[firstData(ev, "LogonType")]
		act.Category, act.Action, act.Detail = "authentication", "logon_success", joinDetail("logon", kind, firstData(ev, "WorkstationName"))
	case 4625:
		kind := logonTypeNames[firstData(ev, "LogonType")]
		act.Category, act.Action, act.Detail = "authentication", "logon_failure", joinDetail("failed logon", kind, firstData(ev, "Status"))
	case 4648:
		act.Category, act.Action, act.Target = "authentication", "explicit_credentials", firstData(ev, "TargetServerName")
		act.Detail = "explicit credentials"
	case 4672:
		act.Category, act.Action, act.Detail = "privilege", "special_privileges", clip(firstData(ev, "PrivilegeList"), 400)
	case 4688:
		act.Category, act.Action = "process", "process_start"
		act.Target = firstData(ev, "NewProcessName")
		act.Detail = clip(firstData(ev, "CommandLine"), 400)
		if act.Detail == "" {
			act.Detail = act.Target
		}
	case 4689:
		act.Category, act.Action, act.Target = "process", "process_exit", firstData(ev, "ProcessName")
	case 4697, 7045:
		act.Category, act.Action = "persistence", "service_installed"
		act.Target = firstData(ev, "ServiceName", "ServiceFileName")
		act.Detail = clip(firstData(ev, "ImagePath", "ServiceFileName"), 400)
	case 4698:
		act.Category, act.Action, act.Target = "persistence", "task_created", firstData(ev, "TaskName")
	case 4699:
		act.Category, act.Action, act.Target = "persistence", "task_deleted", firstData(ev, "TaskName")
	case 4702:
		act.Category, act.Action, act.Target = "persistence", "task_updated", firstData(ev, "TaskName")
	case 4720:
		act.Category, act.Action, act.Target = "account", "user_created", firstData(ev, "TargetUserName")
	case 4726:
		act.Category, act.Action, act.Target = "account", "user_deleted", firstData(ev, "TargetUserName")
	case 4732:
		act.Category, act.Action = "account", "group_member_added"
		act.Target = firstData(ev, "TargetUserName")
		act.Detail = firstData(ev, "GroupName")
	case 4733:
		act.Category, act.Action = "account", "group_member_removed"
		act.Target = firstData(ev, "TargetUserName")
		act.Detail = firstData(ev, "GroupName")
	case 1102:
		act.Category, act.Action, act.Detail = "defense", "audit_log_cleared", "audit log cleared"
	case 4104:
		act.Category, act.Action, act.Detail = "command", "powershell_script", clip(firstData(ev, "ScriptBlockText"), 400)
	case 1149:
		act.Category, act.Action, act.User = "authentication", "rdp_authentication", firstData(ev, "Param1", "TargetUserName")
		act.SourceIP = cleanIP(firstData(ev, "Param3", "IpAddress"))
	default:
		return Activity{}, false
	}
	if act.Detail == "" {
		act.Detail = act.Target
	}
	return act, true
}

func firstData(ev Event, names ...string) string {
	if ev.Windows == nil {
		return ""
	}
	for _, name := range names {
		for _, field := range ev.Windows.Data {
			if strings.EqualFold(field.Name, name) {
				return strings.TrimSpace(field.Value)
			}
		}
	}
	return ""
}

func appendActivities(a *Analysis, items []Activity) {
	for _, item := range items {
		if len(a.Activities) >= activityLimit {
			note := "Activity limit reached: remaining authentication, process and command rows were not recorded"
			if len(a.Notes) == 0 || a.Notes[len(a.Notes)-1] != note {
				found := false
				for _, existing := range a.Notes {
					if existing == note {
						found = true
						break
					}
				}
				if !found {
					a.Notes = append(a.Notes, note)
				}
			}
			return
		}
		a.Activities = append(a.Activities, item)
	}
}

func lineTime(line string) (time.Time, string) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return time.Time{}, ""
	}
	layouts := []string{
		time.RFC3339Nano,
		"2006-01-02T15:04:05.999999999-0700",
		"2006-01-02T15:04:05-0700",
		"2006-01-02 15:04:05.999999999-0700",
		"2006-01-02 15:04:05-0700",
	}
	candidates := []string{fields[0]}
	if len(fields) > 1 {
		candidates = append(candidates, fields[0]+" "+fields[1])
	}
	for _, candidate := range candidates {
		for _, layout := range layouts {
			if when, e := time.Parse(layout, candidate); e == nil {
				return when.UTC(), candidate
			}
		}
	}
	return time.Time{}, ""
}

func cleanIP(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || value == "-" {
		return ""
	}
	addr, e := netip.ParseAddr(value)
	if e != nil {
		return ""
	}
	return addr.Unmap().String()
}

func joinDetail(parts ...string) string {
	var kept []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			kept = append(kept, part)
		}
	}
	return strings.Join(kept, " ")
}

func clip(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) > n {
		r = r[:n]
	}
	return string(r)
}

func writeActivities(a Analysis, path string) error {
	var b bytes.Buffer
	w := csv.NewWriter(&b)
	_ = w.Write([]string{"time_utc", "original_time", "platform", "category", "action", "user", "source_ip", "target", "detail", "evidence_id", "source", "line"})
	for _, act := range a.Activities {
		stamp := ""
		if !act.Time.IsZero() {
			stamp = act.Time.UTC().Format(time.RFC3339Nano)
		}
		_ = w.Write([]string{stamp, csvSafe(act.OriginalTime), act.Platform, act.Category, act.Action, csvSafe(act.User), act.SourceIP, csvSafe(act.Target), csvSafe(act.Detail), act.Evidence, csvSafe(act.Source), strconv.Itoa(act.Line)})
	}
	w.Flush()
	if e := w.Error(); e != nil {
		return e
	}
	return WriteNew(path, b.Bytes())
}
