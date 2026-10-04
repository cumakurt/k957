package core

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"
	"unicode/utf16"
)

func TestPersistenceParsers(t *testing.T) {
	when := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	it := Item{ID: "E1", Source: "task.xml", Modified: when}
	task := `<?xml version="1.0"?><Task xmlns="` + taskNamespace + `"><Principals><Principal><UserId>SYSTEM</UserId></Principal></Principals><Actions><Exec><Command>C:\Windows\System32\cmd.exe</Command><Arguments>/c whoami</Arguments></Exec></Actions></Task>`
	encoded := utf16.Encode([]rune(task))
	buf := []byte{0xff, 0xfe}
	for _, u := range encoded {
		var pair [2]byte
		binary.LittleEndian.PutUint16(pair[:], u)
		buf = append(buf, pair[:]...)
	}
	events, summary, ok := parsePersistence(buf, it, 10)
	if !ok || summary.Format != "WindowsScheduledTask" || len(events) != 1 || events[0].User != "SYSTEM" || events[0].Detail != `C:\Windows\System32\cmd.exe /c whoami` {
		t.Fatalf("task ok %v summary %+v events %#v", ok, summary, events)
	}
	plist := `<?xml version="1.0"?><plist version="1.0"><dict><key>Label</key><string>com.example.agent</string><key>ProgramArguments</key><array><string>/bin/sh</string><string>-c</string><string>id</string></array></dict></plist>`
	it.Source = "com.example.agent.plist"
	events, summary, ok = parsePersistence([]byte(plist), it, 10)
	if !ok || summary.Format != "LaunchdPlist" || len(events) != 1 || events[0].Detail != "com.example.agent: /bin/sh -c id" {
		t.Fatalf("plist ok %v %+v %#v", ok, summary, events)
	}
	unit := "[Unit]\nDescription=demo\n[Service]\nUser=ada\nExecStart=/usr/bin/python3 /opt/app.py\n"
	it.Source = "/etc/systemd/system/demo.service"
	events, summary, ok = parsePersistence([]byte(unit), it, 10)
	if !ok || summary.Format != "SystemdUnit" || len(events) != 1 || events[0].User != "ada" || events[0].Detail != "/usr/bin/python3 /opt/app.py" {
		t.Fatalf("unit ok %v %+v %#v", ok, summary, events)
	}
	if _, _, ok = parsePersistence([]byte("plain log\n"), it, 10); ok {
		t.Fatal("plain text was treated as persistence")
	}
	prefetch := make([]byte, 96)
	binary.LittleEndian.PutUint32(prefetch[0:], 30)
	copy(prefetch[4:], "SCCA")
	for i, u := range utf16.Encode([]rune("NOTEPAD.EXE")) {
		binary.LittleEndian.PutUint16(prefetch[16+i*2:], u)
	}
	ev, ok := prefetchEvent(prefetch, Item{ID: "E2", Source: "NOTEPAD.EXE-ABC123.pf", Modified: when})
	if !ok || ev.Type != eventPrefetch || ev.Detail != "NOTEPAD.EXE" {
		t.Fatalf("%v %#v", ok, ev)
	}
	if _, ok = prefetchEvent([]byte("not prefetch"), it); ok {
		t.Fatal("accepted a non-prefetch")
	}
}

func TestAnalyzePersistencePackage(t *testing.T) {
	d := t.TempDir()
	root := filepath.Join(d, "src")
	if e := os.Mkdir(root, 0700); e != nil {
		t.Fatal(e)
	}
	unit := "[Service]\nExecStart=/bin/true\n"
	if e := os.WriteFile(filepath.Join(root, "demo.service"), []byte(unit), 0600); e != nil {
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
	found := false
	for _, ev := range a.Timeline {
		if ev.Type == eventSystemdExec && ev.Detail == "/bin/true" {
			found = true
		}
	}
	if !found {
		t.Fatalf("systemd command missing: %#v", a.Timeline)
	}
	report := filepath.Join(d, "report")
	if e = Export(a, report); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Join(report, "persistence.csv")); e != nil {
		t.Fatal(e)
	}
}
