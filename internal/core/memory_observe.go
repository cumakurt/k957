package core

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
)

const (
	memoryObsTotal   = 500
	memoryObsPerKind = 80
)

// MemoryObservation is one symbol-free reading from a memory image.
// It records that the bytes were present. It does not reconstruct a kernel object.
type MemoryObservation struct {
	Kind     string `json:"kind"`
	Physical uint64 `json:"physical"`
	Detail   string `json:"detail"`
}

func (s *memScan) observe(phys uint64, data []byte) {
	s.observeImages(phys, data)
	s.observeAccounts(phys, data)
	s.observeNet(phys, data)
	s.observeModules(phys, data)
	s.observeCommands(phys, data)
	s.observeEnv(phys, data)
	s.observePEM(phys, data)
}

func (s *memScan) addObs(kind string, phys uint64, detail string) {
	if detail == "" {
		return
	}
	key := fmt.Sprintf("%s\x00%x\x00%s", kind, phys, detail)
	if _, seen := s.obsSeen[key]; seen {
		return
	}
	s.obsSeen[key] = phys
	s.obsCounts[kind]++
	if s.resultWriter != nil {
		s.emit(MemoryResult{Kind: kind, Physical: phys, Detail: detail})
		s.resultWriter.result.Observations++
	}
	if s.resultWriter == nil || len(s.observations) < memoryObsTotal {
		s.observations = append(s.observations, MemoryObservation{Kind: kind, Physical: phys, Detail: detail})
	}
}

func (s *memScan) observeImages(phys uint64, data []byte) {
	for _, hit := range indexAll(data, []byte{0x7f, 'E', 'L', 'F'}) {
		if detail, ok := elfDetail(data[hit:]); ok {
			s.addObs("elf", phys+uint64(hit), detail)
		}
	}
	for _, hit := range indexAll(data, []byte{'M', 'Z'}) {
		if detail, ok := peDetail(data[hit:]); ok {
			s.addObs("pe", phys+uint64(hit), detail)
		}
	}
	for _, magic := range [][]byte{
		{0xcf, 0xfa, 0xed, 0xfe},
		{0xfe, 0xed, 0xfa, 0xcf},
		{0xce, 0xfa, 0xed, 0xfe},
		{0xfe, 0xed, 0xfa, 0xce},
		{0xca, 0xfe, 0xba, 0xbe},
	} {
		for _, hit := range indexAll(data, magic) {
			if detail, ok := machoDetail(data[hit:]); ok {
				s.addObs("macho", phys+uint64(hit), detail)
			}
		}
	}
}

func indexAll(data, needle []byte) []int {
	var out []int
	from := 0
	for from < len(data) {
		rel := bytes.Index(data[from:], needle)
		if rel < 0 {
			break
		}
		out = append(out, from+rel)
		from += rel + 1
	}
	return out
}

func elfDetail(b []byte) (string, bool) {
	if len(b) < 52 || b[6] != 1 {
		return "", false
	}
	class, endian := b[4], b[5]
	if (class != 1 && class != 2) || (endian != 1 && endian != 2) {
		return "", false
	}
	need := 52
	if class == 2 {
		need = 64
	}
	if len(b) < need {
		return "", false
	}
	order := binary.ByteOrder(binary.LittleEndian)
	end := "LE"
	if endian == 2 {
		order = binary.BigEndian
		end = "BE"
	}
	typ := order.Uint16(b[16:])
	mach := order.Uint16(b[18:])
	names := map[uint16]string{1: "ET_REL", 2: "ET_EXEC", 3: "ET_DYN", 4: "ET_CORE"}
	name, ok := names[typ]
	if !ok || mach == 0 {
		return "", false
	}
	var entry uint64
	if class == 2 {
		entry = order.Uint64(b[24:])
	} else {
		entry = uint64(order.Uint32(b[24:]))
	}
	width := "ELF32"
	if class == 2 {
		width = "ELF64"
	}
	return fmt.Sprintf("%s %s %s machine=%#x entry=%#x", width, end, name, mach, entry), true
}

func peDetail(b []byte) (string, bool) {
	if len(b) < 0x40 || b[0] != 'M' || b[1] != 'Z' {
		return "", false
	}
	lfanew := binary.LittleEndian.Uint32(b[0x3c:])
	if lfanew < 0x40 || lfanew > 0x400 {
		return "", false
	}
	pe := int(lfanew)
	if pe+26 > len(b) || b[pe] != 'P' || b[pe+1] != 'E' || b[pe+2] != 0 || b[pe+3] != 0 {
		return "", false
	}
	machine := binary.LittleEndian.Uint16(b[pe+4:])
	magic := binary.LittleEndian.Uint16(b[pe+24:])
	kind := ""
	switch magic {
	case 0x10b:
		kind = "PE32"
	case 0x20b:
		kind = "PE32+"
	default:
		return "", false
	}
	return fmt.Sprintf("%s machine=%#x", kind, machine), true
}

func machoDetail(b []byte) (string, bool) {
	if len(b) < 8 {
		return "", false
	}
	if bytes.Equal(b[:4], []byte{0xca, 0xfe, 0xba, 0xbe}) {
		return machoFat(b)
	}
	order := binary.ByteOrder(binary.LittleEndian)
	end := "LE"
	width := "32"
	switch {
	case bytes.Equal(b[:4], []byte{0xcf, 0xfa, 0xed, 0xfe}):
		width = "64"
	case bytes.Equal(b[:4], []byte{0xfe, 0xed, 0xfa, 0xcf}):
		order = binary.BigEndian
		end = "BE"
		width = "64"
	case bytes.Equal(b[:4], []byte{0xce, 0xfa, 0xed, 0xfe}):
	case bytes.Equal(b[:4], []byte{0xfe, 0xed, 0xfa, 0xce}):
		order = binary.BigEndian
		end = "BE"
	default:
		return "", false
	}
	need := 28
	if width == "64" {
		need = 32
	}
	if len(b) < need {
		return "", false
	}
	cpu := order.Uint32(b[4:])
	filetype := order.Uint32(b[12:])
	ncmds := order.Uint32(b[16:])
	if !knownMachCPU(cpu) || filetype == 0 || filetype > 11 || ncmds == 0 || ncmds > 256 {
		return "", false
	}
	files := map[uint32]string{1: "MH_OBJECT", 2: "MH_EXECUTE", 6: "MH_DYLIB", 7: "MH_DYLINKER", 8: "MH_BUNDLE"}
	name := files[filetype]
	if name == "" {
		name = fmt.Sprintf("filetype=%d", filetype)
	}
	return fmt.Sprintf("Mach-O %s %s %s cpu=%#x ncmds=%d", width, end, name, cpu, ncmds), true
}

func machoFat(b []byte) (string, bool) {
	if len(b) < 16 {
		return "", false
	}
	n := binary.BigEndian.Uint32(b[4:])
	if n == 0 || n > 8 {
		return "", false
	}
	cpu := binary.BigEndian.Uint32(b[8:])
	if !knownMachCPU(cpu) {
		return "", false
	}
	return fmt.Sprintf("Mach-O fat arches=%d cpu=%#x", n, cpu), true
}

func knownMachCPU(cpu uint32) bool {
	switch cpu {
	case 7, 12, 18, 0x01000007, 0x0100000c, 0x01000012:
		return true
	default:
		return false
	}
}

func (s *memScan) observeAccounts(phys uint64, data []byte) {
	for i := 0; i < len(data); i++ {
		if i > 0 && data[i-1] != '\n' && data[i-1] != 0 {
			continue
		}
		detail, next, ok := accountAt(data[i:])
		if !ok {
			continue
		}
		s.addObs("account", phys+uint64(i), detail)
		if next > 1 {
			i += next - 1
		}
	}
}

func accountAt(b []byte) (string, int, bool) {
	if len(b) == 0 || !((b[0] >= 'a' && b[0] <= 'z') || (b[0] >= 'A' && b[0] <= 'Z') || b[0] == '_') {
		return "", 0, false
	}
	name, n := token(b, 32, nameChar)
	if n < 1 || n >= len(b) || b[n] != ':' {
		return "", 0, false
	}
	pass, pn := token(b[n+1:], 128, fieldChar)
	if pn >= len(b[n+1:]) || b[n+1+pn] != ':' {
		return "", 0, false
	}
	at := n + 1 + pn + 1
	uid, un := digits(b[at:], 10)
	if un < 1 || at+un >= len(b) || b[at+un] != ':' {
		return "", 0, false
	}
	at += un + 1
	gid, gn := digits(b[at:], 10)
	if gn < 1 || at+gn >= len(b) || b[at+gn] != ':' {
		return "", 0, false
	}
	at += gn + 1
	gecos, gecn := token(b[at:], 64, fieldChar)
	if at+gecn >= len(b) || b[at+gecn] != ':' {
		return "", 0, false
	}
	at += gecn + 1
	home, hn := token(b[at:], 128, fieldChar)
	if hn < 2 || home[0] != '/' || at+hn >= len(b) || b[at+hn] != ':' {
		return "", 0, false
	}
	at += hn + 1
	shell, sn := token(b[at:], 64, fieldChar)
	if sn < 2 || shell[0] != '/' {
		return "", 0, false
	}
	detail := fmt.Sprintf("%s uid=%s gid=%s home=%s shell=%s", name, uid, gid, home, shell)
	if gecos != "" {
		detail += " gecos=" + gecos
	}
	if pass != "" && pass != "x" && pass != "*" && pass != "!" {
		detail += " password=[omitted]"
	}
	return detail, at + sn, true
}

func (s *memScan) observeNet(phys uint64, data []byte) {
	for i := 0; i < len(data); i++ {
		if data[i] != ':' {
			continue
		}
		if detail, kind, ok := procNet(data, i, 8); ok {
			s.addObs(kind, phys+uint64(i-8), detail)
			continue
		}
		if detail, kind, ok := procNet(data, i, 32); ok {
			s.addObs(kind, phys+uint64(i-32), detail)
		}
	}
}

func procNet(data []byte, colon, width int) (string, string, bool) {
	if colon < width+1 || data[colon-width-1] != ' ' {
		return "", "", false
	}
	localHex := data[colon-width : colon]
	if !isHex(localHex) || colon+1+4 > len(data) {
		return "", "", false
	}
	localPort := data[colon+1 : colon+5]
	if !isHex(localPort) || colon+5 >= len(data) || data[colon+5] != ' ' {
		return "", "", false
	}
	remAt := colon + 6
	if remAt+width+1+4+1+2 > len(data) {
		return "", "", false
	}
	remHex := data[remAt : remAt+width]
	if !isHex(remHex) || data[remAt+width] != ':' {
		return "", "", false
	}
	remPort := data[remAt+width+1 : remAt+width+5]
	if !isHex(remPort) || data[remAt+width+5] != ' ' {
		return "", "", false
	}
	stateHex := data[remAt+width+6 : remAt+width+8]
	if !isHex(stateHex) {
		return "", "", false
	}
	state, kind, ok := netState(string(stateHex))
	if !ok {
		return "", "", false
	}
	local, ok := procIP(string(localHex))
	if !ok {
		return "", "", false
	}
	remote, ok := procIP(string(remHex))
	if !ok {
		return "", "", false
	}
	lp, _ := strconv.ParseUint(string(localPort), 16, 16)
	rp, _ := strconv.ParseUint(string(remPort), 16, 16)
	return fmt.Sprintf("%s:%d -> %s:%d %s", local, lp, remote, rp, state), kind, true
}

func netState(hexState string) (string, string, bool) {
	switch strings.ToUpper(hexState) {
	case "01":
		return "ESTABLISHED", "tcp", true
	case "02":
		return "SYN_SENT", "tcp", true
	case "03":
		return "SYN_RECV", "tcp", true
	case "04":
		return "FIN_WAIT1", "tcp", true
	case "05":
		return "FIN_WAIT2", "tcp", true
	case "06":
		return "TIME_WAIT", "tcp", true
	case "07":
		return "CLOSE", "socket", true
	case "08":
		return "CLOSE_WAIT", "tcp", true
	case "09":
		return "LAST_ACK", "tcp", true
	case "0A":
		return "LISTEN", "tcp", true
	case "0B":
		return "CLOSING", "tcp", true
	default:
		return "", "", false
	}
}

func procIP(h string) (string, bool) {
	raw, e := hex.DecodeString(h)
	if e != nil {
		return "", false
	}
	switch len(raw) {
	case 4:
		v := binary.LittleEndian.Uint32(raw)
		return net.IP{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}.String(), true
	case 16:
		var ip [16]byte
		for w := 0; w < 4; w++ {
			v := binary.LittleEndian.Uint32(raw[w*4:])
			binary.BigEndian.PutUint32(ip[w*4:], v)
		}
		return net.IP(ip[:]).String(), true
	default:
		return "", false
	}
}

func (s *memScan) observeModules(phys uint64, data []byte) {
	needle := []byte("vermagic=")
	for _, hit := range indexAll(data, needle) {
		text, _, ok := cstring(data[hit:], 180)
		if !ok || len(text) < len(needle)+3 {
			continue
		}
		s.addObs("module", phys+uint64(hit), text)
	}
}

func (s *memScan) observeCommands(phys uint64, data []byte) {
	for i := 0; i < len(data); i++ {
		if data[i] != '/' || (i > 0 && data[i-1] != 0 && data[i-1] != '\n') {
			continue
		}
		argv0, next, ok := cstring(data[i:], 200)
		if !ok || !pathLike(argv0) || next >= len(data[i:]) || data[i+next] != 0 {
			continue
		}
		args := []string{argv0}
		j := i + next + 1
		for len(args) < 8 && j < len(data) && data[j] != 0 {
			tok, n, ok := cstring(data[j:], 120)
			if !ok {
				break
			}
			// Another argument is accepted only when it is NUL-terminated,
			// which is how a process argument vector is stored.
			if j+n >= len(data) || data[j+n] != 0 {
				break
			}
			args = append(args, tok)
			j += n + 1
		}
		kind := "command"
		if len(args) == 1 {
			kind = "path"
		}
		s.addObs(kind, phys+uint64(i), strings.Join(args, " "))
		if j > i {
			i = j - 1
		}
	}
}

func pathLike(p string) bool {
	if len(p) < 4 || strings.ContainsAny(p, " \t") || !strings.Contains(p, "/") {
		return false
	}
	for _, prefix := range []string{"/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/opt/", "/home/", "/tmp/", "/etc/", "/var/", "/proc/"} {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return strings.Contains(p, ".so")
}

func (s *memScan) observeEnv(phys uint64, data []byte) {
	keys := []string{"USER=", "HOME=", "LOGNAME=", "SHELL=", "SSH_CLIENT=", "SSH_CONNECTION=", "SUDO_USER=", "SUDO_COMMAND=", "PWD="}
	secrets := []string{"PASSWORD=", "PASSWD=", "SECRET=", "TOKEN=", "API_KEY=", "PRIVATE_KEY="}
	for _, key := range keys {
		s.observeEnvKey(phys, data, key, false)
	}
	for _, key := range secrets {
		s.observeEnvKey(phys, data, key, true)
	}
}

func (s *memScan) observeEnvKey(phys uint64, data []byte, key string, secret bool) {
	needle := []byte(key)
	for _, hit := range indexAll(data, needle) {
		if hit > 0 && data[hit-1] != 0 && data[hit-1] != '\n' {
			continue
		}
		if secret {
			s.addObs("identity", phys+uint64(hit), strings.TrimSuffix(key, "=")+"= [value omitted]")
			continue
		}
		val, _, ok := cstring(data[hit+len(needle):], 160)
		if !ok {
			continue
		}
		s.addObs("identity", phys+uint64(hit), key+val)
	}
}

func (s *memScan) observePEM(phys uint64, data []byte) {
	markers := []struct{ needle, detail string }{
		{"-----BEGIN PRIVATE KEY-----", "PEM private key header, body omitted"},
		{"-----BEGIN OPENSSH PRIVATE KEY-----", "PEM OpenSSH private key header, body omitted"},
		{"-----BEGIN RSA PRIVATE KEY-----", "PEM RSA private key header, body omitted"},
		{"-----BEGIN CERTIFICATE-----", "PEM certificate header"},
	}
	for _, m := range markers {
		for _, hit := range indexAll(data, []byte(m.needle)) {
			s.addObs("pem", phys+uint64(hit), m.detail)
		}
	}
}

func cstring(b []byte, max int) (string, int, bool) {
	n := 0
	for n < len(b) && n < max && b[n] != 0 && b[n] != '\n' && b[n] >= 32 && b[n] < 127 {
		n++
	}
	if n == 0 {
		return "", n, false
	}
	return string(b[:n]), n, true
}

func token(b []byte, max int, ok func(byte) bool) (string, int) {
	n := 0
	for n < len(b) && n < max && ok(b[n]) {
		n++
	}
	return string(b[:n]), n
}

func nameChar(b byte) bool {
	return b == '_' || b == '.' || b == '-' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

func fieldChar(b byte) bool {
	return b >= 32 && b < 127 && b != ':'
}

func digits(b []byte, max int) (string, int) {
	n := 0
	for n < len(b) && n < max && b[n] >= '0' && b[n] <= '9' {
		n++
	}
	return string(b[:n]), n
}

func isHex(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
