package core

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"
)

type ngByteOrder interface {
	binary.ByteOrder
	binary.AppendByteOrder
}

func ngBlock(order ngByteOrder, kind uint32, body []byte) []byte {
	b := make([]byte, 8)
	order.PutUint32(b[:4], kind)
	length := uint32(12 + len(body))
	order.PutUint32(b[4:8], length)
	b = append(b, body...)
	return order.AppendUint32(b, length)
}
func ngOption(order ngByteOrder, code uint16, value []byte) []byte {
	b := order.AppendUint16(nil, code)
	b = order.AppendUint16(b, uint16(len(value)))
	b = append(b, value...)
	return append(b, make([]byte, (-len(value))&3)...)
}
func ngSection(order ngByteOrder) []byte {
	b := order.AppendUint32(nil, 0x1a2b3c4d)
	b = order.AppendUint16(b, 1)
	b = order.AppendUint16(b, 0)
	b = order.AppendUint64(b, math.MaxUint64)
	return ngBlock(order, pcapngSectionBlock, b)
}
func ngInterface(order ngByteOrder, link uint16, options ...[]byte) []byte {
	b := order.AppendUint16(nil, link)
	b = order.AppendUint16(b, 0)
	b = order.AppendUint32(b, 0) // PCAPNG zero snaplen means unlimited.
	for _, option := range options {
		b = append(b, option...)
	}
	return ngBlock(order, 1, b)
}
func ngPacket(order ngByteOrder, iface uint32, ticks uint64, frame []byte, original int, options ...[]byte) []byte {
	b := order.AppendUint32(nil, iface)
	b = order.AppendUint32(b, uint32(ticks>>32))
	b = order.AppendUint32(b, uint32(ticks))
	b = order.AppendUint32(b, uint32(len(frame)))
	b = order.AppendUint32(b, uint32(original))
	b = append(b, frame...)
	b = append(b, make([]byte, (-len(frame))&3)...)
	for _, option := range options {
		b = append(b, option...)
	}
	return ngBlock(order, 6, b)
}
func ngJoin(blocks ...[]byte) []byte { return bytes.Join(blocks, nil) }

func TestPCAPNGSectionsInterfacesAndProvenance(t *testing.T) {
	le, be := binary.LittleEndian, binary.BigEndian
	frame := packet4(false)
	first := ngJoin(ngSection(le), ngInterface(le, 101), ngInterface(le, 101, ngOption(le, 9, []byte{9}), ngOption(le, 14, le.AppendUint64(nil, 10))))
	offset1 := len(first)
	packet1 := ngPacket(le, 0, 1600000000123456, frame, len(frame))
	packet2 := ngPacket(le, 1, 1600000000123456789, frame, len(frame))
	first = ngJoin(first, packet1, packet2, packet1)
	second := ngJoin(ngSection(be), ngInterface(be, 101, ngOption(be, 9, []byte{128 | 10})))
	offset4 := len(first) + len(second)
	data := ngJoin(first, second, ngPacket(be, 0, 1600000000*1024+512, frame, len(frame)))
	events, flows, s := parsePCAP(data, Item{ID: "E", Source: "test.pcapng"}, 100, 100)
	if s.Error != "" || s.Sections != 2 || s.ByteOrder != "mixed" || len(s.Interfaces) != 3 || s.Records != 4 || s.Parsed != 4 || s.Blocks != 9 || len(flows) != 3 {
		t.Fatalf("%+v %+v", s, flows)
	}
	want := []time.Time{time.Unix(1600000000, 123456000), time.Unix(1600000010, 123456789), time.Unix(1600000000, 123456000), time.Unix(1600000000, 500000000)}
	for n, e := range events {
		if !e.Time.Equal(want[n]) || e.Packet != n+1 || e.SourceIP != "192.0.2.10" {
			t.Fatal(e)
		}
	}
	if events[0].ByteOffset != int64(offset1) || events[3].ByteOffset != int64(offset4) || events[3].Section != 2 || events[3].InterfaceID != 0 || events[1].InterfaceID != 1 {
		t.Fatal(events)
	}
	if flows[0].Packets != 2 || flows[1].Section != 1 || flows[1].InterfaceID != 1 || flows[2].Section != 2 || flows[0].References[1].Packet != 3 || flows[1].References[0].CaptureContext != events[1].CaptureContext {
		t.Fatal(flows)
	}
}

func cookedPacket(ip []byte, link uint32) []byte {
	typ := uint16(0x0800)
	if ip[0]>>4 == 6 {
		typ = 0x86dd
	}
	var b []byte
	if link == 113 {
		b = make([]byte, 16)
		binary.BigEndian.PutUint16(b[2:4], 1)
		binary.BigEndian.PutUint16(b[4:6], 6)
		binary.BigEndian.PutUint16(b[14:16], typ)
	} else {
		b = make([]byte, 20)
		binary.BigEndian.PutUint16(b[:2], typ)
		binary.BigEndian.PutUint32(b[4:8], 7)
		binary.BigEndian.PutUint16(b[8:10], 1)
		b[11] = 6
	}
	return append(b, ip...)
}
func TestCaptureLinuxCookedLinks(t *testing.T) {
	for _, link := range []uint32{113, 276} {
		for _, ip := range [][]byte{packet4(true), packet6(0)} {
			frame := cookedPacket(ip, link)
			for _, order := range []ngByteOrder{binary.LittleEndian, binary.BigEndian} {
				for _, data := range [][]byte{pcapBytes(order, false, link, frame), ngJoin(ngSection(order), ngInterface(order, uint16(link)), ngPacket(order, 0, 1234567, frame, len(frame)))} {
					events, _, s := parsePCAP(data, Item{}, 10, 10)
					if s.Error != "" || s.Parsed != 1 || len(events) != 1 {
						t.Fatalf("link %d: %+v", link, s)
					}
				}
			}
			headerSize := 16
			if link == 276 {
				headerSize = 20
			}
			for n := 0; n < headerSize; n++ {
				decodeCapturePacket(frame[:n], link, int64(len(frame)))
			}
			for _, hardware := range []uint16{770, 803, 824} {
				bad := bytes.Clone(frame)
				offset := 2
				if link == 276 {
					offset = 8
				}
				binary.BigEndian.PutUint16(bad[offset:offset+2], hardware)
				if _, reason := decodeCapturePacket(bad, link, int64(len(bad))); reason != "unsupported_link_protocol" {
					t.Fatal(reason)
				}
			}
		}
	}
	bad := cookedPacket(packet4(false), 276)
	bad[2] = 1
	if _, reason := decodeCapturePacket(bad, 276, int64(len(bad))); reason != "invalid_link_header" {
		t.Fatal(reason)
	}
}

func TestPCAPNGTimestampPrecisionAndRange(t *testing.T) {
	for _, c := range []struct {
		ticks           uint64
		resolution      uint8
		offset, sec, ns int64
	}{
		{1600000000123456, 6, 0, 1600000000, 123456000}, {1600000000123456789, 9, -10, 1599999990, 123456789},
		{12345, 128 | 10, 0, 12, 55664062}, {math.MaxUint64, 128 | 63, 0, 1, 999999999},
		{math.MaxUint64, 19, 0, 1, 844674407}, {12, 0, -20, -8, 0}, {0, 6, -62135596800, -62135596800, 0},
	} {
		stamp, reason := pcapngTimestamp(c.ticks, c.resolution, c.offset)
		if reason != "" || stamp.Unix() != c.sec || int64(stamp.Nanosecond()) != c.ns {
			t.Fatalf("%+v: %s %s", c, stamp, reason)
		}
		if _, err := json.Marshal(stamp); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []struct {
		ticks      uint64
		resolution uint8
		offset     int64
		reason     string
	}{
		{1, 20, 0, "unsupported_timestamp_resolution"}, {1, 192, 0, "unsupported_timestamp_resolution"},
		{math.MaxUint64, 0, 0, "invalid_timestamp"}, {1, 0, math.MaxInt64, "invalid_timestamp"},
		{0, 6, math.MinInt64, "invalid_timestamp"}, {253402300800, 0, 0, "invalid_timestamp"},
	} {
		if _, reason := pcapngTimestamp(c.ticks, c.resolution, c.offset); reason != c.reason {
			t.Fatal(c, reason)
		}
	}
}

func TestPCAPNGMalformedFraming(t *testing.T) {
	o := binary.LittleEndian
	f := packet4(false)
	valid := func() []byte { return ngJoin(ngSection(o), ngInterface(o, 101), ngPacket(o, 0, 1, f, len(f))) }
	for name, mutate := range map[string]func([]byte) []byte{
		"byte order":                  func(b []byte) []byte { b[8] = 0; return b },
		"version":                     func(b []byte) []byte { b[12] = 2; return b },
		"minor version":               func(b []byte) []byte { b[14] = 1; return b },
		"short block":                 func(b []byte) []byte { o.PutUint32(b[4:8], 8); return b },
		"unaligned block":             func(b []byte) []byte { o.PutUint32(b[4:8], 27); return b },
		"huge block":                  func(b []byte) []byte { o.PutUint32(b[4:8], math.MaxUint32); return b },
		"footer":                      func(b []byte) []byte { b[24] = 0; return b },
		"section too long":            func(b []byte) []byte { o.PutUint64(b[16:24], uint64(len(b))); return b },
		"section too short":           func(b []byte) []byte { o.PutUint64(b[16:24], 0); return b },
		"section crossing":            func(b []byte) []byte { o.PutUint64(b[16:24], 4); return b },
		"negative section length":     func(b []byte) []byte { o.PutUint64(b[16:24], math.MaxUint64-1); return b },
		"reserved":                    func(b []byte) []byte { b[38] = 1; return b },
		"interface":                   func(b []byte) []byte { o.PutUint32(b[56:60], 1); return b },
		"length":                      func(b []byte) []byte { o.PutUint32(b[64+4:72], math.MaxUint32); return b },
		"original length":             func(b []byte) []byte { o.PutUint32(b[72:76], 1); return b },
		"snaplen":                     func(b []byte) []byte { o.PutUint32(b[40:44], 1); return b },
		"truncated":                   func(b []byte) []byte { return b[:len(b)-1] },
		"trailing bytes":              func(b []byte) []byte { return append(b, 0) },
		"no interface in new section": func(b []byte) []byte { return ngJoin(b, ngSection(o), ngPacket(o, 0, 1, f, len(f))) },
	} {
		t.Run(name, func(t *testing.T) {
			_, _, s := parsePCAP(mutate(valid()), Item{}, 10, 10)
			if s.Error == "" {
				t.Fatal("accepted malformed input", s)
			}
		})
	}
	for _, options := range [][]byte{
		ngOption(o, 9, []byte{6, 7}), ngJoin(ngOption(o, 9, []byte{6}), ngOption(o, 9, []byte{9})),
		ngOption(o, 14, []byte{1}), ngOption(o, 13, []byte{1, 2}),
		{9, 0, 255, 255}, ngJoin(ngOption(o, 0, nil), ngOption(o, 9, []byte{6})),
	} {
		_, _, s := parsePCAP(ngJoin(ngSection(o), ngInterface(o, 101, options)), Item{}, 10, 10)
		if s.Error == "" {
			t.Fatal("accepted invalid options", options)
		}
	}
	for _, option := range [][]byte{ngOption(o, 2, []byte{1}), ngJoin(ngOption(o, 2, o.AppendUint32(nil, 0)), ngOption(o, 2, o.AppendUint32(nil, 0)))} {
		_, _, s := parsePCAP(ngJoin(ngSection(o), ngInterface(o, 101), ngPacket(o, 0, 1, f, len(f), option)), Item{}, 10, 10)
		if s.Error == "" || s.Records != 0 {
			t.Fatal(s)
		}
	}
	// Declared section lengths exclude their own SHB; minor 1.2 is compatible.
	b := valid()
	o.PutUint64(b[16:24], uint64(len(b)-28))
	o.PutUint16(b[14:16], 2)
	_, _, s := parsePCAP(ngJoin(b, valid()), Item{}, 10, 10)
	if s.Error != "" || s.Parsed != 2 {
		t.Fatal(s)
	}
}

func TestPCAPNGSkippedPacketsAndMetadata(t *testing.T) {
	o := binary.BigEndian
	f := packet4(false)
	for _, c := range []struct {
		link    uint16
		options []byte
		reason  string
	}{
		{999, nil, "unsupported_link_type"}, {101, ngOption(o, 9, []byte{20}), "unsupported_timestamp_resolution"},
		{101, ngOption(o, 10, o.AppendUint32(nil, 1)), "unsupported_timestamp_timezone"},
		{101, ngOption(o, 13, []byte{32}), "unsupported_link_metadata"},
		{101, ngOption(o, 14, o.AppendUint64(nil, math.MaxInt64)), "invalid_timestamp"},
	} {
		b := ngJoin(ngSection(o), ngInterface(o, c.link, c.options), ngPacket(o, 0, 1000000, f, len(f)))
		_, _, s := parsePCAP(b, Item{}, 10, 10)
		if s.Error != "" || s.SkipReasons[c.reason] != 1 || s.Records != 1 {
			t.Fatal(c, s)
		}
	}
	simple := ngBlock(o, 3, append(o.AppendUint32(nil, uint32(len(f))), f...))
	old := ngPacket(o, 0, 1, f, len(f))
	o.PutUint32(old[:4], 2)
	flags := ngPacket(o, 0, 1, f, len(f), ngOption(o, 2, o.AppendUint32(nil, 4<<5)))
	data := ngJoin(ngSection(o), ngInterface(o, 101), simple, old, ngBlock(o, 0xdeadbeef, []byte("META")), flags, ngPacket(o, 0, 1, f[:len(f)-4], len(f)))
	ev, _, s := parsePCAP(data, Item{}, 10, 10)
	if s.Error != "" || s.Records != 4 || s.Parsed != 1 || s.Skipped != 3 || s.IgnoredBlocks != 1 || s.TruncatedPackets != 1 || ev[0].Packet != 4 {
		t.Fatal(s)
	}
	for _, reason := range []string{"missing_timestamp", "obsolete_packet_block", "unsupported_link_metadata"} {
		if s.SkipReasons[reason] != 1 {
			t.Fatal(s)
		}
	}
}

func TestPCAPNGBudgetsAndTruncatedPrefix(t *testing.T) {
	o := binary.LittleEndian
	f := packet4(false)
	prefix := ngJoin(ngSection(o), ngInterface(o, 101))
	packet := ngPacket(o, 0, 1, f, len(f))
	data := ngJoin(prefix, bytes.Repeat(packet, pcapRecordLimit+1))
	for _, budget := range []int{-1, 0, 1, 21, pcapRecordLimit + 1} {
		ev, flows, s := parsePCAP(data, Item{}, budget, 1)
		if s.Error != "" || !s.Limited || s.Records != max(0, min(budget, pcapRecordLimit)) || len(ev) != s.Records {
			t.Fatal(s)
		}
		if s.Records > 20 && (!flows[0].ReferencesTruncated || len(flows[0].References) != 20) {
			t.Fatal(flows)
		}
	}
	_, flows, s := parsePCAP(data, Item{}, 1, -1)
	if len(flows) != 0 || s.FlowOmittedPackets != 1 {
		t.Fatal(s)
	}
	for name, b := range map[string][]byte{
		"blocks":     ngJoin(ngSection(o), bytes.Repeat(ngBlock(o, 0xdeadbeef, nil), pcapngBlockLimit)),
		"sections":   bytes.Repeat(ngSection(o), pcapngSectionLimit+1),
		"interfaces": ngJoin(ngSection(o), bytes.Repeat(ngInterface(o, 101), pcapngInterfaceLimit+1)),
	} {
		_, _, s := parsePCAP(b, Item{}, 10, 10)
		if !s.Limited || s.Error != "" || s.Sections > pcapngSectionLimit || len(s.Interfaces) > pcapngInterfaceLimit || s.Blocks > pcapngBlockLimit {
			t.Fatal(name, s)
		}
	}
	valid := ngJoin(prefix, packet)
	for n := 4; n < len(valid); n++ {
		_, _, s := parsePCAP(valid[:n], Item{}, 10, 10)
		if n != 28 && n != 48 && s.Error == "" {
			t.Fatal("accepted truncated prefix", n)
		}
	}
	_, _, s = parsePCAP(ngJoin(valid, []byte{1, 2, 3}), Item{}, 10, 10)
	if s.Parsed != 1 || !strings.Contains(s.Error, "byte") {
		t.Fatal(s)
	}
}

func FuzzPCAPNG(f *testing.F) {
	for _, o := range []ngByteOrder{binary.LittleEndian, binary.BigEndian} {
		frame := packet4(false)
		f.Add(ngJoin(ngSection(o), ngInterface(o, 101, ngOption(o, 9, []byte{128 | 10})), ngPacket(o, 0, 12345, frame, len(frame))))
		f.Add(ngJoin(ngSection(o), ngInterface(o, 101), ngSection(o), ngInterface(o, 101), ngPacket(o, 0, 12345, frame, len(frame))))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			t.Skip()
		}
		events, flows, s := parsePCAPNG(b, Item{}, 100, 10)
		if len(b) == 0 {
			return
		}
		if s.Records != s.Parsed+s.Skipped || len(events) != s.Parsed || s.Records > 100 || len(flows) > 10 || len(s.Interfaces) > pcapngInterfaceLimit {
			t.Fatal("accounting/bounds", s)
		}
		total := s.FlowOmittedPackets
		for _, flow := range flows {
			total += flow.Packets
			if len(flow.References) > pcapReferenceLimit || flow.Section < 1 {
				t.Fatal(flow)
			}
		}
		if total != s.Parsed {
			t.Fatal("flow accounting", s)
		}
		if _, err := json.Marshal(events); err != nil {
			t.Fatal(err)
		}
		for _, link := range []uint32{113, 276} {
			decodeCapturePacket(b, link, int64(len(b)))
		}
	})
}
