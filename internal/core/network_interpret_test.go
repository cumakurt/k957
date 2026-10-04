package core

import (
	"encoding/binary"
	"testing"
)

func tcpReferencePacket(sequence uint32, flags byte, payload string) []byte {
	b := append(packet4(true)[:40], []byte(payload)...)
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	binary.BigEndian.PutUint16(b[22:24], 80)
	binary.BigEndian.PutUint32(b[24:28], sequence)
	b[33] = flags
	binary.BigEndian.PutUint16(b[10:12], internetChecksum(b[:20]))
	return b
}

func TestTCPReassemblyOrderReuseOverlapAndLimits(t *testing.T) {
	first, second := "GET /reference HTTP/1.1\r\n", "Host: example.test\r\n\r\n"
	frames := [][]byte{tcpReferencePacket(100, 2, ""), tcpReferencePacket(101+uint32(len(first)), 0x18, second), tcpReferencePacket(101, 0x18, first), tcpReferencePacket(101, 0x18, first), tcpReferencePacket(200, 4, ""), tcpReferencePacket(500, 2, ""), tcpReferencePacket(501, 0x18, first+second)}
	data := pcapBytes(binary.LittleEndian, false, 101, frames...)
	events, _, summary, result := parseCaptureAdvanced(data, Item{ID: "E1", Source: "capture"}, 100, 100, 100, 100, 4<<20)
	if summary.Error != "" || len(result.Sessions) != 2 || len(result.Observations) != 2 {
		t.Fatalf("%+v %+v", summary, result)
	}
	if result.Sessions[0].Retransmissions != 1 || result.Sessions[0].Gaps || result.Sessions[0].Conflict {
		t.Fatal(result.Sessions)
	}
	if result.Observations[0].HTTP.Host != "example.test" || result.Observations[0].HTTP.Target != "/reference" || result.Observations[0].PartialStream {
		t.Fatal(result.Observations)
	}
	if result.Observations[0].References[0].Packet != 3 || len(events[2].Network) != 1 {
		t.Fatal("out-of-order provenance lost", result.Observations)
	}
	conflict := pcapBytes(binary.LittleEndian, false, 101, tcpReferencePacket(100, 2, ""), tcpReferencePacket(101, 0x18, first+second), tcpReferencePacket(101, 0x18, "BAD"))
	_, _, _, result = parseCaptureAdvanced(conflict, Item{ID: "E1"}, 100, 100, 100, 100, 4<<20)
	if !result.Sessions[0].Conflict || len(result.Observations) != 0 {
		t.Fatal("conflicting bytes were interpreted", result)
	}
	gap := pcapBytes(binary.LittleEndian, false, 101, tcpReferencePacket(100, 2, ""), tcpReferencePacket(200, 0x18, first+second))
	_, _, _, result = parseCaptureAdvanced(gap, Item{ID: "E1"}, 100, 100, 100, 100, 4<<20)
	if !result.Sessions[0].Gaps || len(result.Observations) != 0 {
		t.Fatal("gap was filled with invented bytes")
	}
	_, _, _, result = parseCaptureAdvanced(data, Item{ID: "E1"}, 100, 100, 1, 0, 0)
	if !result.Limited || len(result.Observations) != 0 || result.Omissions["session_limit"] == 0 || result.Omissions["protocol_metadata_limit"] == 0 {
		t.Fatal("limits concealed", result)
	}
}

func TestDNSCompressionChecksumAndMalformedPointers(t *testing.T) {
	payload := []byte{0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 4, 't', 'e', 's', 't', 0, 0, 1, 0, 1, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1}
	dns, e := parseDNS(payload)
	if e != nil || dns.Questions[0].Name != "example.test" || dns.Answers[0].Value != "192.0.2.1" {
		t.Fatalf("%+v %v", dns, e)
	}
	bad := append([]byte(nil), payload...)
	bad[12] = 0xc0
	bad[13] = 12
	if _, e = parseDNS(bad); e == nil {
		t.Fatal("cyclic compression accepted")
	}
	packet := append(packet4(false)[:28], payload...)
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	binary.BigEndian.PutUint16(packet[22:24], 53)
	binary.BigEndian.PutUint16(packet[24:26], uint16(len(packet)-20))
	binary.BigEndian.PutUint16(packet[10:12], internetChecksum(packet[:20]))
	pseudo := []byte{192, 0, 2, 10, 198, 51, 100, 20, 0, 17, 0, byte(len(packet) - 20)}
	binary.BigEndian.PutUint16(packet[26:28], internetChecksum(append(pseudo, packet[20:]...)))
	events, _, _, result := parseCaptureAdvanced(pcapBytes(binary.LittleEndian, false, 101, packet), Item{ID: "E1"}, 100, 100, 100, 100, 4<<20)
	if result.Checksums["transport_valid"] != 1 || result.Checksums["ip_valid"] != 1 || len(result.Observations) != 1 || len(events[0].Network) != 1 {
		t.Fatal(result)
	}
}

func TestTLSClientHelloMetadataAndHTTPAmbiguity(t *testing.T) {
	name := "example.test"
	serverName := []byte{0, 0, 0, 0, byte(len(name))}
	serverName = append(serverName, []byte(name)...)
	binary.BigEndian.PutUint16(serverName[:2], uint16(len(serverName)-2))
	extensions := binary.BigEndian.AppendUint16(nil, 0)
	extensions = binary.BigEndian.AppendUint16(extensions, uint16(len(serverName)))
	extensions = append(extensions, serverName...)
	body := make([]byte, 34)
	body[0], body[1] = 3, 3
	body = append(body, 0, 0, 2, 0x13, 1, 1, 0)
	body = binary.BigEndian.AppendUint16(body, uint16(len(extensions)))
	body = append(body, extensions...)
	handshake := []byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	handshake = append(handshake, body...)
	record := []byte{22, 3, 3, byte(len(handshake) >> 8), byte(len(handshake))}
	record = append(record, handshake...)
	tls, e := parseTLSClientHello(record)
	if e != nil || tls.ServerName != name || tls.LegacyVersion != 0x0303 {
		t.Fatalf("%+v %v", tls, e)
	}
	if _, e = parseTLSClientHello(record[:len(record)-1]); e == nil {
		t.Fatal("truncated TLS record accepted")
	}
	if _, e = parseHTTPMetadata([]byte("GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n")); e == nil {
		t.Fatal("ambiguous HTTP Host accepted")
	}
}
