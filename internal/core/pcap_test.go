package core

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func packet4(tcp bool) []byte {
	n := 8
	if tcp {
		n = 20
	}
	b := make([]byte, 20+n+4)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	b[8] = 64
	b[9] = 17
	if tcp {
		b[9] = 6
	}
	copy(b[12:16], []byte{192, 0, 2, 10})
	copy(b[16:20], []byte{198, 51, 100, 20})
	binary.BigEndian.PutUint16(b[20:22], 12345)
	binary.BigEndian.PutUint16(b[22:24], 443)
	if tcp {
		b[32] = 0x50
		b[33] = 0x12
	} else {
		binary.BigEndian.PutUint16(b[24:26], uint16(n+4))
	}
	copy(b[len(b)-4:], []byte("TEST"))
	return b
}
func packet6(ext byte) []byte {
	b := make([]byte, 40+8+4)
	b[0] = 0x60
	b[6] = 17
	b[7] = 64
	copy(b[8:24], []byte{0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	copy(b[24:40], []byte{0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})
	binary.BigEndian.PutUint16(b[40:42], 53)
	binary.BigEndian.PutUint16(b[42:44], 50000)
	binary.BigEndian.PutUint16(b[44:46], 12)
	copy(b[48:], "DATA")
	if ext != 255 {
		header := []byte{17, 0, 0, 0, 0, 0, 0, 0}
		if ext == 51 {
			header = []byte{17, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
		}
		b = append(append(append([]byte{}, b[:40]...), header...), b[40:]...)
		b[6] = ext
	}
	binary.BigEndian.PutUint16(b[4:6], uint16(len(b)-40))
	return b
}
func ethernet(ip []byte, tags int) []byte {
	b := make([]byte, 14+tags*4)
	typ := uint16(0x0800)
	if ip[0]>>4 == 6 {
		typ = 0x86dd
	}
	if tags == 0 {
		binary.BigEndian.PutUint16(b[12:14], typ)
	} else {
		binary.BigEndian.PutUint16(b[12:14], 0x88a8)
		for i := 0; i < tags; i++ {
			next := uint16(0x8100)
			if i == tags-1 {
				next = typ
			}
			binary.BigEndian.PutUint16(b[16+i*4:18+i*4], next)
		}
	}
	return append(b, ip...)
}
func pcapBytes(order binary.ByteOrder, nano bool, link uint32, frames ...[]byte) []byte {
	b := make([]byte, 24)
	magic := uint32(0xa1b2c3d4)
	if nano {
		magic = 0xa1b23c4d
	}
	order.PutUint32(b[:4], magic)
	order.PutUint16(b[4:6], 2)
	order.PutUint16(b[6:8], 4)
	order.PutUint32(b[16:20], 65535)
	order.PutUint32(b[20:24], link)
	for i, f := range frames {
		h := make([]byte, 16)
		order.PutUint32(h[:4], uint32(1600000000+i))
		order.PutUint32(h[4:8], 123456)
		order.PutUint32(h[8:12], uint32(len(f)))
		order.PutUint32(h[12:16], uint32(len(f)))
		b = append(b, h...)
		b = append(b, f...)
	}
	return b
}
func TestPCAPEndianResolutionOffsetsAndFlows(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		for _, nano := range []bool{false, true} {
			frame := ethernet(packet4(true), 0)
			data := pcapBytes(order, nano, 1, frame, frame)
			ev, flows, s := parsePCAP(data, Item{ID: "E", Source: "test.pcap"}, 100, 10)
			if s.Error != "" || s.Records != 2 || s.Parsed != 2 || s.Skipped != 0 || len(flows) != 1 || flows[0].Packets != 2 {
				t.Fatalf("%+v %+v", s, flows)
			}
			ns := int64(123456000)
			if nano {
				ns = 123456
			}
			if ev[0].Time.Nanosecond() != int(ns) || !ev[0].Time.Equal(time.Unix(1600000000, ns)) || ev[0].ByteOffset != 24 || ev[1].ByteOffset != int64(40+len(frame)) || ev[1].Packet != 2 {
				t.Fatal(ev)
			}
			if ev[0].SourceIP != "192.0.2.10" || ev[0].DestinationPort != 443 || ev[0].TCPFlags != 0x12 || ev[0].Protocol != "TCP" {
				t.Fatal(ev[0])
			}
			if flows[0].CapturedBytes != int64(2*len(frame)) || flows[0].References[1].Packet != 2 {
				t.Fatal(flows)
			}
		}
	}
}
func TestPCAPRawIPv6VLANAndExtensions(t *testing.T) {
	for _, ext := range []byte{255, 0, 43, 60, 51} {
		ev, flows, s := parsePCAP(pcapBytes(binary.BigEndian, true, 101, packet6(ext)), Item{}, 10, 10)
		if s.Parsed != 1 || len(flows) != 1 || ev[0].SourceIP != "2001:db8::1" || ev[0].SourcePort != 53 || ev[0].Protocol != "UDP" {
			t.Fatalf("ext %d: %+v", ext, s)
		}
	}
	for tags := 0; tags <= 2; tags++ {
		_, _, s := parsePCAP(pcapBytes(binary.LittleEndian, false, 1, ethernet(packet4(false), tags)), Item{}, 10, 10)
		if s.Parsed != 1 {
			t.Fatal(s)
		}
	}
	_, _, s := parsePCAP(pcapBytes(binary.LittleEndian, false, 1, ethernet(packet4(false), 3)), Item{}, 10, 10)
	if s.SkipReasons["vlan_depth_limit"] != 1 {
		t.Fatal(s)
	}
}
func TestPCAPMalformedFragmentAndUnsupported(t *testing.T) {
	tests := map[string][]byte{}
	f := packet4(false)
	binary.BigEndian.PutUint16(f[6:8], 0x2000)
	tests["fragment"] = f
	f = packet4(false)
	f[0] = 0x4f
	tests["invalid_ip_length"] = f
	f = packet4(true)
	f[32] = 0xf0
	tests["invalid_transport_length"] = f
	f = packet4(false)
	f[9] = 1
	tests["unsupported_ip_protocol"] = f
	f = packet6(44)
	tests["fragment-v6"] = f
	f = packet6(0)
	f[41] = 255
	tests["invalid_extension_length"] = f
	for expected, frame := range tests {
		_, _, s := parsePCAP(pcapBytes(binary.LittleEndian, false, 101, frame), Item{}, 10, 10)
		if expected == "fragment-v6" {
			expected = "fragment"
		}
		if s.Skipped != 1 || s.SkipReasons[expected] != 1 {
			t.Fatalf("%s: %+v", expected, s)
		}
	}
	for _, kind := range []string{"magic", "version", "snaplen", "link", "link-flags", "cap>orig", "cap>snap", "short-body", "short-header", "pcapng"} {
		data := pcapBytes(binary.LittleEndian, false, 101, packet4(false))
		switch kind {
		case "magic":
			data[0] = 0
		case "version":
			data[4] = 3
		case "snaplen":
			binary.LittleEndian.PutUint32(data[16:20], 0)
		case "link":
			binary.LittleEndian.PutUint32(data[20:24], 999)
		case "link-flags":
			binary.LittleEndian.PutUint32(data[20:24], 0x24000001)
		case "cap>orig":
			binary.LittleEndian.PutUint32(data[36:40], 1)
		case "cap>snap":
			binary.LittleEndian.PutUint32(data[16:20], 1)
		case "short-body":
			data = data[:len(data)-1]
		case "short-header":
			data = data[:30]
		case "pcapng":
			data = []byte{10, 13, 13, 10}
		}
		_, _, s := parsePCAP(data, Item{}, 10, 10)
		if s.Error == "" {
			t.Fatal("accepted", kind)
		}
	}
	data := pcapBytes(binary.LittleEndian, false, 101, packet4(false))
	binary.LittleEndian.PutUint32(data[28:32], 1000000)
	_, _, s := parsePCAP(data, Item{}, 10, 10)
	if s.SkipReasons["invalid_timestamp"] != 1 {
		t.Fatal(s)
	}
}
func TestPCAPTruncationBudgetsAndDirection(t *testing.T) {
	frame := packet4(true)
	data := pcapBytes(binary.LittleEndian, false, 101, frame)
	data = data[:len(data)-4]
	binary.LittleEndian.PutUint32(data[32:36], uint32(len(frame)-4))
	ev, _, s := parsePCAP(data, Item{}, 10, 10)
	if s.Parsed != 1 || s.TruncatedPackets != 1 || len(ev) != 1 {
		t.Fatal(s)
	}
	data = data[:len(data)-1]
	binary.LittleEndian.PutUint32(data[32:36], uint32(len(frame)-5))
	_, _, s = parsePCAP(data, Item{}, 10, 10)
	if s.SkipReasons["short_transport_header"] != 1 {
		t.Fatal(s)
	}
	frame = packet4(false)
	reverse := append([]byte{}, frame...)
	copy(reverse[12:16], frame[16:20])
	copy(reverse[16:20], frame[12:16])
	copy(reverse[20:22], frame[22:24])
	copy(reverse[22:24], frame[20:22])
	data = pcapBytes(binary.LittleEndian, false, 101, frame, reverse, frame)
	ev, flows, s := parsePCAP(data, Item{}, 3, 1)
	if s.Parsed != 3 || s.FlowOmittedPackets != 1 || len(flows) != 1 || flows[0].Packets != 2 || len(ev) != 3 {
		t.Fatalf("%+v %+v", s, flows)
	}
	_, _, s = parsePCAP(data, Item{}, 1, 10)
	if !s.Limited || s.Records != 1 {
		t.Fatal(s)
	}
	_, _, s = parsePCAP(data, Item{}, 0, 0)
	if !s.Limited || s.Records != 0 {
		t.Fatal(s)
	}
	frames := make([][]byte, 23)
	for i := range frames {
		frames[i] = frame
	}
	data = pcapBytes(binary.LittleEndian, false, 101, frames...)
	// Timestamps may be out of order; flow range must be actual min/max.
	binary.LittleEndian.PutUint32(data[24:28], 1700000000)
	_, flows, s = parsePCAP(data, Item{}, 30, 1)
	if s.Parsed != 23 || len(flows[0].References) != 20 || !flows[0].ReferencesTruncated || flows[0].Last.Unix() != 1700000000 || flows[0].First.Unix() != 1600000001 {
		t.Fatal(flows, s)
	}
}
func TestPCAPAnalysisCorrelationAndShare(t *testing.T) {
	d, o := fixture(t, false)
	capture := pcapBytes(binary.LittleEndian, false, 1, ethernet(packet4(false), 0))
	os.WriteFile(filepath.Join(o.Root, "capture.bin"), capture, 0600)
	os.WriteFile(filepath.Join(o.Root, "peer.jsonl"), []byte(`{"timestamp":"2020-09-13T12:26:40Z","src_ip":"192.0.2.10","message":"event"}`), 0600)
	os.WriteFile(filepath.Join(o.Root, "unsupported.pcapng"), []byte{10, 13, 13, 10}, 0600)
	if _, e := Collect(context.Background(), o); e != nil {
		t.Fatal(e)
	}
	p, e := Open(o.Out, "")
	if e != nil {
		t.Fatal(e)
	}
	defer p.Zip.Close()
	a := Analyze(p, nil)
	if len(a.NetworkFlows) != 1 || len(a.CaptureSummaries) != 2 || len(a.Correlations) != 1 {
		t.Fatalf("%+v %+v", a.CaptureSummaries, a.Correlations)
	}
	found := false
	for _, r := range a.Correlations[0].References {
		if r.Packet == 1 && r.Offset == 24 {
			found = true
		}
	}
	if !found {
		t.Fatal("packet provenance absent")
	}
	out := filepath.Join(d, "report")
	if e = Export(a, out); e != nil {
		t.Fatal(e)
	}
	if _, e = LoadAnalysis(filepath.Join(out, "analysis.json")); e != nil {
		t.Fatal(e)
	}
	before := JSON(a)
	s, e := BuildSharedReport(a, SharePolicy{Schema: sharePolicySchema})
	if e != nil {
		t.Fatal(e)
	}
	if len(s.NetworkFlows) != 1 || s.NetworkFlows[0].First != nil || s.NetworkFlows[0].SourceIP == "192.0.2.10" {
		t.Fatal(s.NetworkFlows)
	}
	shared := filepath.Join(d, "shared")
	if e = ExportShared(s, shared); e != nil {
		t.Fatal(e)
	}
	files, _ := os.ReadDir(shared)
	for _, f := range files {
		b, _ := os.ReadFile(filepath.Join(shared, f.Name()))
		for _, secret := range []string{"192.0.2.10", "198.51.100.20", "capture.bin", "unsupported.pcapng"} {
			if bytes.Contains(b, []byte(secret)) {
				t.Fatalf("share leak %s in %s", secret, f.Name())
			}
		}
	}
	if !bytes.Equal(before, JSON(a)) {
		t.Fatal("mutated analysis")
	}
	csv, _ := os.ReadFile(filepath.Join(out, "network.csv"))
	if !bytes.Contains(csv, []byte("192.0.2.10")) {
		t.Fatal("missing network export")
	}
	html, _ := os.ReadFile(filepath.Join(out, "report.html"))
	if !strings.Contains(string(html), "Yönlü ağ akışları") {
		t.Fatal("missing network section")
	}
}
func FuzzPCAP(f *testing.F) {
	f.Add(pcapBytes(binary.LittleEndian, false, 1, ethernet(packet4(true), 0)))
	f.Add(pcapBytes(binary.BigEndian, true, 101, packet6(0)))
	f.Add([]byte{10, 13, 13, 10})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		events, flows, s := parsePCAP(data, Item{}, 100, 10)
		if s.Records != s.Parsed+s.Skipped || len(events) != s.Parsed || s.Records > 100 || len(flows) > 10 {
			t.Fatal("bounds/count invariant")
		}
		sum := s.FlowOmittedPackets
		for _, v := range flows {
			sum += v.Packets
			if len(v.References) > 20 {
				t.Fatal("reference bound")
			}
		}
		if sum != s.Parsed {
			t.Fatal("flow accounting")
		}
		if len(data) < 4096 {
			decodeCapturePacket(data, 1, int64(len(data)+64))
			decodeCapturePacket(data, 101, int64(len(data)+64))
		}
	})
}

func TestNetworkEndpointIPv6(t *testing.T) {
	if networkEndpoint("2001:db8::1", 443) != "[2001:db8::1]:443" {
		t.Fatal("ambiguous IPv6 endpoint")
	}
	if networkEndpoint("192.0.2.1", 53) != "192.0.2.1:53" {
		t.Fatal("IPv4 endpoint")
	}
}
