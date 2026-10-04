package core

import (
	"archive/zip"
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
	"path/filepath"
	"strings"
	"time"
)

const pcapFileLimit int64 = 64 << 20
const pcapTotalLimit int64 = 256 << 20
const pcapRecordLimit = 20000
const pcapFlowLimit = 10000
const pcapReferenceLimit = 20

// CaptureContext identifies a PCAPNG interface within its section. Section zero
// denotes classic PCAP or a non-capture event; PCAPNG sections start at one.
type CaptureContext struct {
	Section     int    `json:"section,omitempty"`
	InterfaceID uint32 `json:"interface_id,omitempty"`
}

type PacketReference struct {
	CaptureContext
	Packet         int       `json:"packet"`
	ByteOffset     int64     `json:"byte_offset"`
	Time           time.Time `json:"time"`
	CapturedLength int64     `json:"captured_length"`
	OriginalLength int64     `json:"original_length"`
}
type NetworkFlow struct {
	CaptureContext
	Evidence            string            `json:"evidence"`
	Source              string            `json:"source"`
	Protocol            string            `json:"protocol"`
	SourceIP            string            `json:"source_ip"`
	DestinationIP       string            `json:"destination_ip"`
	SourcePort          uint16            `json:"source_port"`
	DestinationPort     uint16            `json:"destination_port"`
	Packets             int               `json:"packets"`
	CapturedBytes       int64             `json:"captured_bytes"`
	OriginalBytes       int64             `json:"original_bytes"`
	First               time.Time         `json:"first"`
	Last                time.Time         `json:"last"`
	References          []PacketReference `json:"references"`
	ReferencesTruncated bool              `json:"references_truncated"`
}
type CaptureSummary struct {
	Sections           int                `json:"sections,omitempty"`
	Blocks             int                `json:"blocks,omitempty"`
	IgnoredBlocks      int                `json:"ignored_blocks,omitempty"`
	Interfaces         []CaptureInterface `json:"interfaces,omitempty"`
	Evidence           string             `json:"evidence"`
	Source             string             `json:"source"`
	Format             string             `json:"format"`
	ByteOrder          string             `json:"byte_order,omitempty"`
	Resolution         string             `json:"timestamp_resolution,omitempty"`
	LinkType           uint32             `json:"link_type"`
	Records            int                `json:"records"`
	Parsed             int                `json:"parsed"`
	Skipped            int                `json:"skipped"`
	TruncatedPackets   int                `json:"truncated_packets"`
	SkipReasons        map[string]int     `json:"skip_reasons"`
	FlowOmittedPackets int                `json:"flow_omitted_packets"`
	Limited            bool               `json:"limited"`
	Error              string             `json:"error,omitempty"`
}
type packetHeader struct {
	protocol, src, dst            string
	sport, dport                  uint16
	tcpFlags                      uint8
	sequence                      uint32
	payload                       []byte
	complete                      bool
	ipChecksum, transportChecksum string
}

func captureMagic(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	switch string(b[:4]) {
	case "\xd4\xc3\xb2\xa1", "\xa1\xb2\xc3\xd4", "\x4d\x3c\xb2\xa1", "\xa1\xb2\x3c\x4d", "\x0a\x0d\x0d\x0a":
		return true
	}
	return false
}
func captureCandidate(f *zip.File, source string) bool {
	switch strings.ToLower(filepath.Ext(source)) {
	case ".pcap", ".cap", ".pcapng":
		return true
	}
	if f == nil {
		return false
	}
	r, e := f.Open()
	if e != nil {
		return false
	}
	defer r.Close()
	var b [4]byte
	n, _ := io.ReadFull(r, b[:])
	return captureMagic(b[:n])
}
func newCaptureSummary(it Item) CaptureSummary {
	return CaptureSummary{Evidence: it.ID, Source: it.Source, Format: "PCAP", SkipReasons: map[string]int{}}
}

// parsePCAP dispatches PCAPNG and reads classic pcap v2.4. Record lengths are
// checked before slicing. Captured payload is never exported or reassembled.
func parsePCAP(data []byte, it Item, recordBudget, flowBudget int) (events []Event, flows []NetworkFlow, s CaptureSummary) {
	return parsePCAPWithInterpreter(data, it, recordBudget, flowBudget, nil)
}

func parsePCAPWithInterpreter(data []byte, it Item, recordBudget, flowBudget int, interpreter *captureInterpreter) (events []Event, flows []NetworkFlow, s CaptureSummary) {
	events = []Event{}
	flows = []NetworkFlow{}
	s = newCaptureSummary(it)
	fail := func(message string) { s.Error = message }
	if len(data) >= 4 && string(data[:4]) == "\x0a\x0d\x0d\x0a" {
		return parsePCAPNGWithInterpreter(data, it, recordBudget, flowBudget, interpreter)
	}
	if len(data) < 24 {
		fail("truncated pcap file header")
		return
	}
	var order binary.ByteOrder
	nanosecond := false
	switch string(data[:4]) {
	case "\xd4\xc3\xb2\xa1":
		order = binary.LittleEndian
		s.ByteOrder = "little"
	case "\xa1\xb2\xc3\xd4":
		order = binary.BigEndian
		s.ByteOrder = "big"
	case "\x4d\x3c\xb2\xa1":
		order = binary.LittleEndian
		s.ByteOrder = "little"
		nanosecond = true
	case "\xa1\xb2\x3c\x4d":
		order = binary.BigEndian
		s.ByteOrder = "big"
		nanosecond = true
	default:
		fail("unsupported pcap magic")
		return
	}
	s.Resolution = "microseconds"
	if nanosecond {
		s.Resolution = "nanoseconds"
	}
	if order.Uint16(data[4:6]) != 2 || order.Uint16(data[6:8]) != 4 {
		fail("only pcap version 2.4 is supported")
		return
	}
	snap := order.Uint32(data[16:20])
	linkWord := order.Uint32(data[20:24])
	s.LinkType = linkWord & 0xffff
	if snap == 0 {
		fail("zero snaplen")
		return
	}
	// Additional FCS/link metadata is not silently interpreted as a plain link.
	if linkWord != s.LinkType || !supportedCaptureLink(s.LinkType) {
		fail("unsupported link type or additional link metadata")
		return
	}
	if recordBudget < 0 {
		recordBudget = 0
	}
	recordBudget = min(recordBudget, pcapRecordLimit)
	if flowBudget < 0 {
		flowBudget = 0
	}
	flowBudget = min(flowBudget, pcapFlowLimit)
	index := map[captureFlowKey]int{}
	for pos := 24; pos < len(data); {
		if s.Records >= recordBudget {
			s.Limited = true
			break
		}
		if len(data)-pos < 16 {
			fail(fmt.Sprintf("truncated record header at byte %d", pos))
			break
		}
		offset := pos
		sec := order.Uint32(data[pos : pos+4])
		fraction := order.Uint32(data[pos+4 : pos+8])
		captured := order.Uint32(data[pos+8 : pos+12])
		original := order.Uint32(data[pos+12 : pos+16])
		pos += 16
		if captured > snap || captured > original || captured > 1<<20 {
			fail(fmt.Sprintf("invalid or over-limit record lengths at byte %d", offset))
			break
		}
		if uint64(captured) > uint64(len(data)-pos) {
			fail(fmt.Sprintf("truncated record body at byte %d", offset))
			break
		}
		packet := data[pos : pos+int(captured)]
		pos += int(captured)
		s.Records++
		if captured < original {
			s.TruncatedPackets++
		}
		skip := func(reason string) { s.Skipped++; s.SkipReasons[reason]++ }
		scale := uint32(1000000)
		if nanosecond {
			scale = 1000000000
		}
		if fraction >= scale {
			skip("invalid_timestamp")
			continue
		}
		ns := int64(fraction)
		if !nanosecond {
			ns *= 1000
		}
		stamp := time.Unix(int64(sec), ns).UTC()
		h, reason := decodeCapturePacket(packet, s.LinkType, int64(original))
		if reason != "" {
			skip(reason)
			continue
		}
		s.Parsed++
		ev := Event{Time: stamp, Type: "pcap_packet", Evidence: it.ID, Source: it.Source, SourceIP: h.src, DestinationIP: h.dst, ByteOffset: int64(offset), Packet: s.Records, Protocol: h.protocol, SourcePort: h.sport, DestinationPort: h.dport, CapturedLength: int64(captured), OriginalLength: int64(original), TCPFlags: h.tcpFlags}
		events = append(events, ev)
		if interpreter != nil {
			interpreter.observe(h, ev, len(events)-1)
		}
		flows = appendCaptureFlow(flows, index, flowBudget, ev, &s)
	}
	return
}

type captureFlowKey struct {
	CaptureContext
	protocol, src, dst string
	sport, dport       uint16
}

func supportedCaptureLink(link uint32) bool {
	return link == 1 || link == 101 || link == 113 || link == 276
}

func appendCaptureFlow(flows []NetworkFlow, index map[captureFlowKey]int, budget int, ev Event, s *CaptureSummary) []NetworkFlow {
	key := captureFlowKey{ev.CaptureContext, ev.Protocol, ev.SourceIP, ev.DestinationIP, ev.SourcePort, ev.DestinationPort}
	n, ok := index[key]
	if !ok {
		if len(flows) >= budget {
			s.FlowOmittedPackets++
			return flows
		}
		n = len(flows)
		index[key] = n
		flows = append(flows, NetworkFlow{CaptureContext: ev.CaptureContext, Evidence: ev.Evidence, Source: ev.Source, Protocol: ev.Protocol, SourceIP: ev.SourceIP, DestinationIP: ev.DestinationIP, SourcePort: ev.SourcePort, DestinationPort: ev.DestinationPort, First: ev.Time, Last: ev.Time, References: []PacketReference{}})
	}
	f := &flows[n]
	f.Packets++
	f.CapturedBytes += ev.CapturedLength
	f.OriginalBytes += ev.OriginalLength
	if ev.Time.Before(f.First) {
		f.First = ev.Time
	}
	if ev.Time.After(f.Last) {
		f.Last = ev.Time
	}
	if len(f.References) < pcapReferenceLimit {
		f.References = append(f.References, PacketReference{CaptureContext: ev.CaptureContext, Packet: ev.Packet, ByteOffset: ev.ByteOffset, Time: ev.Time, CapturedLength: ev.CapturedLength, OriginalLength: ev.OriginalLength})
	} else {
		f.ReferencesTruncated = true
	}
	return flows
}

func decodeCapturePacket(b []byte, link uint32, original int64) (h packetHeader, reason string) {
	offset := 0
	version := byte(0)
	if link == 1 || link == 113 || link == 276 {
		offset = 14
		if link == 113 {
			offset = 16
		}
		if link == 276 {
			offset = 20
		}
		if len(b) < offset {
			return h, "short_link_header"
		}
		typ := binary.BigEndian.Uint16(b[12:14])
		if link == 113 || link == 276 {
			hardware := binary.BigEndian.Uint16(b[2:4])
			typ = binary.BigEndian.Uint16(b[14:16])
			if link == 276 {
				if binary.BigEndian.Uint16(b[2:4]) != 0 {
					return h, "invalid_link_header"
				}
				hardware = binary.BigEndian.Uint16(b[8:10])
				typ = binary.BigEndian.Uint16(b[:2])
			}
			// These hardware types do not use an EtherType for the payload.
			if hardware == 824 || hardware == 803 || hardware == 770 {
				return h, "unsupported_link_protocol"
			}
		}
		tags := 0
		for typ == 0x8100 || typ == 0x88a8 {
			if tags >= 2 {
				return h, "vlan_depth_limit"
			}
			if len(b)-offset < 4 {
				return h, "short_link_header"
			}
			typ = binary.BigEndian.Uint16(b[offset+2 : offset+4])
			offset += 4
			tags++
		}
		switch typ {
		case 0x0800:
			version = 4
		case 0x86dd:
			version = 6
		default:
			return h, "unsupported_link_protocol"
		}
	} else if link == 101 {
		if len(b) == 0 {
			return h, "short_ip_header"
		}
		version = b[0] >> 4
	} else {
		return h, "unsupported_link_type"
	}
	b = b[offset:]
	if len(b) == 0 {
		return h, "short_ip_header"
	}
	if b[0]>>4 != version {
		return h, "ip_version_mismatch"
	}
	var next byte
	start, total := 0, 0
	switch version {
	case 4:
		if len(b) < 20 {
			return h, "short_ip_header"
		}
		start = int(b[0]&15) * 4
		total = int(binary.BigEndian.Uint16(b[2:4]))
		if start < 20 || total < start || int64(offset+total) > original {
			return h, "invalid_ip_length"
		}
		if len(b) < start {
			return h, "short_ip_header"
		}
		h.ipChecksum = checksumStatus(b[:start])
		if binary.BigEndian.Uint16(b[6:8])&0x3fff != 0 {
			return h, "fragment"
		}
		next = b[9]
		h.src = netip.AddrFrom4([4]byte(b[12:16])).String()
		h.dst = netip.AddrFrom4([4]byte(b[16:20])).String()
	case 6:
		if len(b) < 40 {
			return h, "short_ip_header"
		}
		payload := int(binary.BigEndian.Uint16(b[4:6]))
		if payload == 0 {
			return h, "zero_ipv6_payload_unsupported"
		}
		total = 40 + payload
		start = 40
		if int64(offset+total) > original {
			return h, "invalid_ip_length"
		}
		next = b[6]
		h.src = netip.AddrFrom16([16]byte(b[8:24])).String()
		h.dst = netip.AddrFrom16([16]byte(b[24:40])).String()
	default:
		return h, "unsupported_ip_version"
	}
	b = b[:min(len(b), total)]
	if version == 6 {
		for extensions := 0; next == 0 || next == 43 || next == 60 || next == 51 || next == 44; extensions++ {
			if extensions >= 8 {
				return h, "extension_depth_limit"
			}
			if len(b)-start < 2 {
				return h, "short_extension_header"
			}
			if next == 44 {
				if len(b)-start < 8 {
					return h, "short_extension_header"
				}
				return h, "fragment"
			}
			size := (int(b[start+1]) + 1) * 8
			if next == 51 {
				size = (int(b[start+1]) + 2) * 4
				if size < 12 {
					return h, "invalid_extension_length"
				}
			}
			if size > total-start {
				return h, "invalid_extension_length"
			}
			if size > len(b)-start {
				return h, "short_extension_header"
			}
			next = b[start]
			start += size
		}
	}
	if start > len(b) {
		return h, "short_transport_header"
	}
	transport := b[start:]
	remaining := total - start
	headerSize, transportSize := 0, remaining
	switch next {
	case 6:
		if remaining < 20 {
			return h, "invalid_transport_length"
		}
		if len(transport) < 20 {
			return h, "short_transport_header"
		}
		size := int(transport[12]>>4) * 4
		if size < 20 || size > remaining {
			return h, "invalid_transport_length"
		}
		if size > len(transport) {
			return h, "short_transport_header"
		}
		h.protocol = "TCP"
		h.tcpFlags = transport[13]
		h.sequence = binary.BigEndian.Uint32(transport[4:8])
		headerSize = size
	case 17:
		if remaining < 8 {
			return h, "invalid_transport_length"
		}
		if len(transport) < 8 {
			return h, "short_transport_header"
		}
		size := int(binary.BigEndian.Uint16(transport[4:6]))
		if size < 8 || size > remaining {
			return h, "invalid_transport_length"
		}
		h.protocol = "UDP"
		headerSize = 8
		transportSize = size
	default:
		return h, "unsupported_ip_protocol"
	}
	h.sport = binary.BigEndian.Uint16(transport[:2])
	h.dport = binary.BigEndian.Uint16(transport[2:4])
	h.complete = len(transport) >= transportSize
	h.payload = transport[headerSize:min(len(transport), transportSize)]
	h.transportChecksum = "unknown_truncated"
	if h.complete {
		if next == 17 && binary.BigEndian.Uint16(transport[6:8]) == 0 && version == 4 {
			h.transportChecksum = "absent"
		} else {
			h.transportChecksum = transportChecksumStatus(version, h.src, h.dst, next, transport[:transportSize])
		}
	}
	return h, ""
}
