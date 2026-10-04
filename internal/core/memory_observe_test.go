package core

import (
	"bytes"
	"encoding/binary"
	"strconv"
	"strings"
	"testing"
)

func TestMemoryObservationsAreSymbolFreeReadings(t *testing.T) {
	var b bytes.Buffer
	b.Write(elf64())
	b.Write(pe64())
	b.Write(macho64())
	b.WriteString("\nalice:x:1000:1000:Alice:/home/alice:/bin/bash\n")
	b.WriteString("bob:$6$salt$hash:1001:1001:Bob:/home/bob:/bin/sh\n")
	b.WriteString(" 0: 0100007F:0277 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1 1 0000000000000000 100 0 0 10 0\n")
	b.WriteString(" 1: 00000000000000000000000001000000:0050 00000000000000000000000000000000:0000 01\n")
	b.WriteString("vermagic=6.1.0-k957 SMP preempt mod_unload\n")
	b.Write([]byte{0})
	b.WriteString("/usr/bin/python3")
	b.WriteByte(0)
	b.WriteString("/opt/raas/raas.py")
	b.WriteByte(0)
	b.WriteString("--config")
	b.WriteByte(0)
	b.WriteByte(0)
	b.WriteString("USER=cuma")
	b.WriteByte(0)
	b.WriteString("PASSWORD=supersecret")
	b.WriteByte(0)
	b.WriteString("-----BEGIN PRIVATE KEY-----\nsecret-body\n")
	b.WriteString("MZ-not-a-pe")
	got, e := scanRaw(bytes.NewReader(b.Bytes()), nil)
	if e != nil {
		t.Fatal(e)
	}
	seen := map[string]string{}
	for _, row := range got.Observations {
		seen[row.Kind] = row.Detail
		if strings.Contains(row.Detail, "supersecret") || strings.Contains(row.Detail, "$6$") || strings.Contains(row.Detail, "secret-body") {
			t.Fatalf("secret copied into %s %q", row.Kind, row.Detail)
		}
	}
	wants := map[string]string{
		"elf":      "ELF64 LE ET_DYN machine=0x3e entry=0x400000",
		"pe":       "PE32+ machine=0x8664",
		"macho":    "Mach-O 64 LE MH_EXECUTE cpu=0x1000007 ncmds=1",
		"account":  "alice uid=1000 gid=1000 home=/home/alice shell=/bin/bash gecos=Alice",
		"tcp":      "127.0.0.1:631 -> 0.0.0.0:0 LISTEN",
		"module":   "vermagic=6.1.0-k957 SMP preempt mod_unload",
		"command":  "/usr/bin/python3 /opt/raas/raas.py --config",
		"identity": "USER=cuma",
		"pem":      "PEM private key header, body omitted",
	}
	for kind, detail := range wants {
		if seen[kind] != detail && !strings.Contains(joinedDetails(got.Observations, kind), detail) {
			t.Fatalf("%s: got %#v", kind, detailsOf(got.Observations, kind))
		}
	}
	if !strings.Contains(joinedDetails(got.Observations, "account"), "bob uid=1001") || !strings.Contains(joinedDetails(got.Observations, "account"), "password=[omitted]") {
		t.Fatalf("hash account %#v", detailsOf(got.Observations, "account"))
	}
	if !strings.Contains(joinedDetails(got.Observations, "identity"), "PASSWORD= [value omitted]") {
		t.Fatalf("identity %#v", detailsOf(got.Observations, "identity"))
	}
	if !strings.Contains(joinedDetails(got.Observations, "tcp"), "::1:80") {
		t.Fatalf("tcp6 %#v", detailsOf(got.Observations, "tcp"))
	}
}

func TestMemoryObservationSurvivesChunkBoundary(t *testing.T) {
	prev := memoryWindow
	memoryWindow = 40
	t.Cleanup(func() { memoryWindow = prev })
	var b bytes.Buffer
	b.Write(bytes.Repeat([]byte{0x11}, 30))
	b.Write(elf64())
	got, e := scanRaw(&b, nil)
	if e != nil {
		t.Fatal(e)
	}
	if joinedDetails(got.Observations, "elf") == "" {
		t.Fatalf("observations %#v", got.Observations)
	}
}

func TestMemoryObservationEdgesWithoutCountCaps(t *testing.T) {
	var b bytes.Buffer
	elf32 := make([]byte, 52)
	copy(elf32, []byte{0x7f, 'E', 'L', 'F', 1, 2, 1})
	binary.BigEndian.PutUint16(elf32[16:], 2)
	binary.BigEndian.PutUint16(elf32[18:], 40)
	binary.BigEndian.PutUint32(elf32[24:], 0x8000)
	b.Write(elf32)
	b.Write([]byte{0x7f, 'E', 'L', 'F', 9, 1, 1})
	pe := make([]byte, 0x80)
	copy(pe, "MZ")
	binary.LittleEndian.PutUint32(pe[0x3c:], 0x40)
	copy(pe[0x40:], []byte{'P', 'E', 0, 0})
	binary.LittleEndian.PutUint16(pe[0x44:], 0x14c)
	binary.LittleEndian.PutUint16(pe[0x58:], 0x10b)
	b.Write(pe)
	fat := make([]byte, 16)
	copy(fat, []byte{0xca, 0xfe, 0xba, 0xbe})
	binary.BigEndian.PutUint32(fat[4:], 1)
	binary.BigEndian.PutUint32(fat[8:], 0x0100000c)
	b.Write(fat)
	b.WriteString("\x00/lib/libc.so.6\x00")
	b.WriteString("-----BEGIN CERTIFICATE-----\n")
	b.WriteString(" 2: 08080808:0035 0100007F:0000 07 ")
	for _, st := range []string{"02", "03", "04", "05", "06", "08", "09", "0B", "FF"} {
		b.WriteString(" 0: 0100007F:0001 0100007F:0002 " + st + " ")
	}
	got, e := scanRaw(&b, nil)
	if e != nil {
		t.Fatal(e)
	}
	joined := joinedDetails(got.Observations, "elf") + joinedDetails(got.Observations, "pe") + joinedDetails(got.Observations, "macho") + joinedDetails(got.Observations, "path") + joinedDetails(got.Observations, "pem") + joinedDetails(got.Observations, "socket") + joinedDetails(got.Observations, "tcp")
	for _, want := range []string{"ELF32 BE ET_EXEC", "PE32 machine=0x14c", "Mach-O fat", "/lib/libc.so.6", "PEM certificate header", "CLOSE", "SYN_SENT", "CLOSING"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %s in %s", want, joined)
		}
	}
	s := newMemScan(nil)
	for i := 0; i < memoryObsPerKind+1; i++ {
		s.addObs("path", 1, strings.Repeat("p", i+1))
	}
	if len(s.observations) != memoryObsPerKind+1 || s.obsLimited {
		t.Fatalf("kind cap %d %v", len(s.observations), s.obsLimited)
	}
	s = newMemScan(nil)
	for i := 0; i < memoryObsTotal+1; i++ {
		s.addObs("k"+strconv.Itoa(i), uint64(i), "row")
	}
	s.observe(0, nil)
	if len(s.observations) != memoryObsTotal+1 || s.obsLimited {
		t.Fatalf("total cap %d", len(s.observations))
	}
	if _, ok := procIP("zz"); ok {
		t.Fatal("bad ip")
	}
	if _, _, ok := netState("00"); ok {
		t.Fatal("bad state")
	}
}

func elf64() []byte {
	b := make([]byte, 64)
	copy(b, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(b[16:], 3)
	binary.LittleEndian.PutUint16(b[18:], 0x3e)
	binary.LittleEndian.PutUint64(b[24:], 0x400000)
	return b
}

func pe64() []byte {
	b := make([]byte, 0x100)
	copy(b, "MZ")
	binary.LittleEndian.PutUint32(b[0x3c:], 0x80)
	copy(b[0x80:], []byte{'P', 'E', 0, 0})
	binary.LittleEndian.PutUint16(b[0x84:], 0x8664)
	binary.LittleEndian.PutUint16(b[0x98:], 0x20b)
	return b
}

func macho64() []byte {
	b := make([]byte, 32)
	binary.LittleEndian.PutUint32(b[0:], 0xFEEDFACF)
	binary.LittleEndian.PutUint32(b[4:], 0x01000007)
	binary.LittleEndian.PutUint32(b[12:], 2)
	binary.LittleEndian.PutUint32(b[16:], 1)
	binary.LittleEndian.PutUint32(b[20:], 64)
	return b
}

func detailsOf(rows []MemoryObservation, kind string) []string {
	var out []string
	for _, row := range rows {
		if row.Kind == kind {
			out = append(out, row.Detail)
		}
	}
	return out
}

func joinedDetails(rows []MemoryObservation, kind string) string {
	return strings.Join(detailsOf(rows, kind), "\n")
}
