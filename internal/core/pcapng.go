package core

import (
	"encoding/binary"
	"fmt"
	"math"
	"math/bits"
	"time"
)

const pcapngBlockLimit = 100000
const pcapngInterfaceLimit = 1024
const pcapngSectionLimit = 256
const pcapngSectionBlock = 0x0a0d0d0a

type CaptureInterface struct {
	CaptureContext
	LinkType          uint32 `json:"link_type"`
	Snaplen           uint32 `json:"snaplen"`
	Resolution        uint8  `json:"timestamp_resolution_raw"`
	TimeOffset        int64  `json:"timestamp_offset_seconds"`
	UnsupportedReason string `json:"unsupported_reason,omitempty"`
}

// walkPCAPNGOptions validates framing without retaining comments, names,
// addresses or other arbitrary metadata. Missing end markers are permitted by
// the format; bytes after an explicit end marker are rejected as ambiguous.
func walkPCAPNGOptions(b []byte, order binary.ByteOrder, visit func(uint16, []byte) error) error {
	for len(b) > 0 {
		if len(b) < 4 {
			return fmt.Errorf("truncated option header")
		}
		code, size := order.Uint16(b[:2]), int(order.Uint16(b[2:4]))
		b = b[4:]
		if code == 0 {
			if size != 0 || len(b) != 0 {
				return fmt.Errorf("invalid end-of-options marker")
			}
			return nil
		}
		padded := (size + 3) &^ 3
		if padded > len(b) {
			return fmt.Errorf("truncated option value")
		}
		if visit != nil {
			if err := visit(code, b[:size]); err != nil {
				return err
			}
		}
		b = b[padded:]
	}
	return nil
}

func pcapngInterface(b []byte, order binary.ByteOrder, context CaptureContext) (CaptureInterface, error) {
	i := CaptureInterface{CaptureContext: context, Resolution: 6}
	if len(b) < 8 {
		return i, fmt.Errorf("truncated interface description")
	}
	i.LinkType = uint32(order.Uint16(b[:2]))
	i.Snaplen = order.Uint32(b[4:8])
	if order.Uint16(b[2:4]) != 0 {
		return i, fmt.Errorf("nonzero interface reserved field")
	}
	seen := map[uint16]bool{}
	err := walkPCAPNGOptions(b[8:], order, func(code uint16, value []byte) error {
		size := 0
		switch code {
		case 9, 13:
			size = 1
		case 10:
			size = 4
		case 14:
			size = 8
		default:
			return nil
		}
		if seen[code] || len(value) != size {
			return fmt.Errorf("duplicate or invalid interface option %d", code)
		}
		seen[code] = true
		switch code {
		case 9:
			i.Resolution = value[0]
		case 10:
			if order.Uint32(value) != 0 {
				i.UnsupportedReason = "unsupported_timestamp_timezone"
			}
		case 13:
			if value[0] != 0 {
				i.UnsupportedReason = "unsupported_link_metadata"
			}
		case 14:
			i.TimeOffset = int64(order.Uint64(value))
		}
		return nil
	})
	return i, err
}

func pcapngTimestamp(ticks uint64, resolution uint8, offset int64) (time.Time, string) {
	var scale uint64 = 1
	exponent := resolution & 127
	if resolution&128 != 0 {
		if exponent > 63 {
			return time.Time{}, "unsupported_timestamp_resolution"
		}
		scale <<= exponent
	} else {
		if exponent > 19 {
			return time.Time{}, "unsupported_timestamp_resolution"
		}
		for n := uint8(0); n < exponent; n++ {
			scale *= 10
		}
	}
	seconds := ticks / scale
	if seconds > math.MaxInt64 {
		return time.Time{}, "invalid_timestamp"
	}
	sec := int64(seconds)
	if offset > 0 && sec > math.MaxInt64-offset {
		return time.Time{}, "invalid_timestamp"
	}
	sec += offset
	// Reports encode RFC3339 timestamps, whose years must fit four digits.
	if sec < -62135596800 || sec > 253402300799 {
		return time.Time{}, "invalid_timestamp"
	}
	// Keep integer precision for binary and sub-nanosecond resolutions. Report
	// times are floored to nanoseconds; the original ticks remain in evidence.
	hi, lo := bits.Mul64(ticks%scale, 1000000000)
	ns, _ := bits.Div64(hi, lo, scale)
	return time.Unix(sec, int64(ns)).UTC(), ""
}

func parsePCAPNG(data []byte, it Item, recordBudget, flowBudget int) (events []Event, flows []NetworkFlow, s CaptureSummary) {
	events, flows = []Event{}, []NetworkFlow{}
	s = newCaptureSummary(it)
	s.Format, s.Resolution = "PCAPNG", "per-interface"
	recordBudget = max(0, min(recordBudget, pcapRecordLimit))
	flowBudget = max(0, min(flowBudget, pcapFlowLimit))
	index := map[captureFlowKey]int{}
	var order binary.ByteOrder
	var interfaces []CaptureInterface
	sectionEnd := -1
	fail := func(pos int, message string) { s.Error = fmt.Sprintf("%s at byte %d", message, pos) }
	skip := func(reason string) { s.Skipped++; s.SkipReasons[reason]++ }
	for pos := 0; pos < len(data); {
		if s.Blocks >= pcapngBlockLimit {
			s.Limited = true
			break
		}
		if len(data)-pos < 12 {
			fail(pos, "truncated pcapng block header")
			break
		}
		isSection := binary.BigEndian.Uint32(data[pos:pos+4]) == pcapngSectionBlock
		if sectionEnd >= 0 && ((isSection && pos != sectionEnd) || (!isSection && pos >= sectionEnd)) {
			fail(pos, "section length does not match section boundary")
			break
		}
		if isSection {
			switch string(data[pos+8 : pos+12]) {
			case "\x4d\x3c\x2b\x1a":
				order = binary.LittleEndian
			case "\x1a\x2b\x3c\x4d":
				order = binary.BigEndian
			default:
				fail(pos, "invalid pcapng byte-order magic")
				return
			}
		} else if order == nil {
			fail(pos, "missing section header")
			break
		}
		kind := order.Uint32(data[pos : pos+4])
		length := uint64(order.Uint32(data[pos+4 : pos+8]))
		if length < 12 || length%4 != 0 || length > uint64(len(data)-pos) {
			fail(pos, "invalid or truncated pcapng block length")
			break
		}
		end := pos + int(length)
		if !isSection && sectionEnd >= 0 && end > sectionEnd {
			fail(pos, "block exceeds section length")
			break
		}
		if order.Uint32(data[end-4:end]) != uint32(length) {
			fail(pos, "mismatched pcapng block lengths")
			break
		}
		body := data[pos+8 : end-4]
		if (kind == 2 || kind == 3 || kind == 6) && s.Records >= recordBudget {
			s.Limited = true
			break
		}
		s.Blocks++
		switch kind {
		case pcapngSectionBlock:
			if s.Sections >= pcapngSectionLimit {
				s.Limited = true
				return
			}
			if len(body) < 16 {
				fail(pos, "truncated section header")
				return
			}
			minor := order.Uint16(body[6:8])
			if order.Uint16(body[4:6]) != 1 || (minor != 0 && minor != 2) {
				fail(pos, "unsupported pcapng version")
				return
			}
			sectionLength := order.Uint64(body[8:16])
			sectionEnd = -1
			if sectionLength != math.MaxUint64 {
				if sectionLength%4 != 0 || sectionLength > uint64(len(data)-end) {
					fail(pos, "invalid or truncated section length")
					return
				}
				sectionEnd = end + int(sectionLength)
			}
			if err := walkPCAPNGOptions(body[16:], order, nil); err != nil {
				fail(pos, err.Error())
				return
			}
			s.Sections++
			interfaces = nil
			byteOrder := "little"
			if order == binary.BigEndian {
				byteOrder = "big"
			}
			if s.ByteOrder == "" {
				s.ByteOrder = byteOrder
			} else if s.ByteOrder != byteOrder {
				s.ByteOrder = "mixed"
			}
		case 1:
			if len(s.Interfaces) >= pcapngInterfaceLimit {
				s.Limited = true
				return
			}
			i, err := pcapngInterface(body, order, CaptureContext{Section: s.Sections, InterfaceID: uint32(len(interfaces))})
			if err != nil {
				fail(pos, err.Error())
				return
			}
			interfaces = append(interfaces, i)
			s.Interfaces = append(s.Interfaces, i)
		case 2, 3, 6:
			minimum := 20
			if kind == 3 {
				minimum = 4
			}
			if len(body) < minimum {
				fail(pos, "truncated packet block")
				return
			}
			var interfaceID uint32
			if kind == 6 {
				interfaceID = order.Uint32(body[:4])
			}
			if kind == 2 {
				interfaceID = uint32(order.Uint16(body[:2]))
			}
			if uint64(interfaceID) >= uint64(len(interfaces)) {
				fail(pos, "packet references undefined interface")
				return
			}
			i := interfaces[interfaceID]
			var captured, original uint32
			if kind == 3 {
				original = order.Uint32(body[:4])
				captured = original
				if i.Snaplen != 0 {
					captured = min(captured, i.Snaplen)
				}
			} else {
				captured, original = order.Uint32(body[12:16]), order.Uint32(body[16:20])
			}
			if captured > original || (i.Snaplen != 0 && captured > i.Snaplen) || captured > 1<<20 {
				fail(pos, "invalid or over-limit packet lengths")
				return
			}
			padded := (int(captured) + 3) &^ 3
			if padded > len(body)-minimum {
				fail(pos, "truncated packet data or padding")
				return
			}
			options := body[minimum+padded:]
			packetFCS := false
			if kind == 3 {
				if len(options) != 0 {
					fail(pos, "unexpected simple packet block data")
					return
				}
			} else {
				seenFlags := false
				err := walkPCAPNGOptions(options, order, func(code uint16, value []byte) error {
					if code != 2 {
						return nil
					}
					if seenFlags || len(value) != 4 {
						return fmt.Errorf("duplicate or invalid packet flags")
					}
					seenFlags = true
					packetFCS = order.Uint32(value)&0x1e0 != 0
					return nil
				})
				if err != nil {
					fail(pos, err.Error())
					return
				}
			}
			s.Records++
			if captured < original {
				s.TruncatedPackets++
			}
			if kind == 3 {
				skip("missing_timestamp")
				break
			}
			if kind == 2 {
				skip("obsolete_packet_block")
				break
			}
			if i.UnsupportedReason != "" {
				skip(i.UnsupportedReason)
				break
			}
			if packetFCS {
				skip("unsupported_link_metadata")
				break
			}
			ticks := uint64(order.Uint32(body[4:8]))<<32 | uint64(order.Uint32(body[8:12]))
			stamp, reason := pcapngTimestamp(ticks, i.Resolution, i.TimeOffset)
			if reason != "" {
				skip(reason)
				break
			}
			h, reason := decodeCapturePacket(body[minimum:minimum+int(captured)], i.LinkType, int64(original))
			if reason != "" {
				skip(reason)
				break
			}
			s.Parsed++
			ev := Event{CaptureContext: i.CaptureContext, Time: stamp, Type: "pcap_packet", Evidence: it.ID, Source: it.Source, SourceIP: h.src, DestinationIP: h.dst, ByteOffset: int64(pos), Packet: s.Records, Protocol: h.protocol, SourcePort: h.sport, DestinationPort: h.dport, CapturedLength: int64(captured), OriginalLength: int64(original), TCPFlags: h.tcpFlags}
			events = append(events, ev)
			flows = appendCaptureFlow(flows, index, flowBudget, ev, &s)
		default:
			s.IgnoredBlocks++
		}
		pos = end
	}
	return
}
