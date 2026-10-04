package core

import "testing"

func TestNormalizeSnapshotTextKeepsUTF8(t *testing.T) {
	raw := []byte("2026-10-02T14:00:00Z Unicode \u00fc\u00e7 already utf-8\n")
	out, note := normalizeSnapshotText("systeminfo.exe", raw)
	if note != "" || string(out) != string(raw) {
		t.Fatalf("note %q out %q", note, out)
	}
	if base := snapshotUsesANSICodePage("C:\\Windows\\System32\\wevtutil.exe"); !base {
		t.Fatal("wevtutil should use the ANSI code page")
	}
	if snapshotUsesANSICodePage("systeminfo.exe") {
		t.Fatal("systeminfo should use the OEM code page")
	}
}
