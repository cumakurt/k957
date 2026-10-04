package core

import (
	"bytes"
	"encoding/binary"
	"encoding/csv"
	"fmt"
	"net/netip"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const networkStreamLimit = 64 << 10
const networkReassemblyLimit = 4 << 20
const networkSessionLimit = 10000

type NetworkSession struct {
	CaptureContext
	ID                  string            `json:"id"`
	Evidence            string            `json:"evidence"`
	Source              string            `json:"source"`
	EndpointA           string            `json:"endpoint_a"`
	EndpointB           string            `json:"endpoint_b"`
	First               time.Time         `json:"first"`
	Last                time.Time         `json:"last"`
	Packets             int               `json:"packets"`
	Bytes               int               `json:"reassembled_bytes"`
	SYNObserved         bool              `json:"syn_observed"`
	Closed              bool              `json:"close_observed"`
	Gaps                bool              `json:"capture_gaps"`
	Conflict            bool              `json:"conflicting_overlap"`
	Retransmissions     int               `json:"retransmissions"`
	Limited             bool              `json:"limited"`
	Checksums           map[string]int    `json:"checksums"`
	References          []PacketReference `json:"references"`
	ReferencesTruncated bool              `json:"references_truncated"`
}

type ProtocolObservation struct {
	CaptureContext
	Evidence            string            `json:"evidence"`
	Source              string            `json:"source"`
	Session             string            `json:"session,omitempty"`
	Protocol            string            `json:"protocol"`
	DNS                 *DNSMetadata      `json:"dns,omitempty"`
	HTTP                *HTTPMetadata     `json:"http,omitempty"`
	TLS                 *TLSMetadata      `json:"tls,omitempty"`
	References          []PacketReference `json:"references"`
	ReferencesTruncated bool              `json:"references_truncated"`
	PartialStream       bool              `json:"partial_stream"`
}

type DNSMetadata struct {
	ID        uint16        `json:"id"`
	Response  bool          `json:"response"`
	RCode     uint8         `json:"rcode"`
	Questions []DNSQuestion `json:"questions"`
	Answers   []DNSAnswer   `json:"answers,omitempty"`
	Omitted   bool          `json:"omitted"`
}
type DNSQuestion struct {
	Name  string `json:"name"`
	Type  uint16 `json:"type"`
	Class uint16 `json:"class"`
}
type DNSAnswer struct {
	Name  string `json:"name"`
	Type  uint16 `json:"type"`
	Value string `json:"value"`
}
type HTTPMetadata struct {
	Method  string `json:"method,omitempty"`
	Target  string `json:"target,omitempty"`
	Host    string `json:"host,omitempty"`
	Status  int    `json:"status,omitempty"`
	Version string `json:"version"`
}
type TLSMetadata struct {
	ServerName         string   `json:"server_name,omitempty"`
	ALPN               []string `json:"alpn,omitempty"`
	AdvertisedVersions []uint16 `json:"advertised_versions,omitempty"`
	LegacyVersion      uint16   `json:"legacy_version"`
}

type NetworkInterpretation struct {
	MetadataBytes int                   `json:"metadata_bytes"`
	Evidence      string                `json:"evidence"`
	Sessions      []NetworkSession      `json:"sessions"`
	Observations  []ProtocolObservation `json:"observations"`
	Omissions     map[string]int        `json:"omissions"`
	Checksums     map[string]int        `json:"checksums"`
	Limited       bool                  `json:"limited"`
}

type streamSegment struct {
	offset  int64
	payload []byte
	ref     PacketReference
	event   int
}
type tcpStream struct {
	base       uint32
	known, syn bool
	segments   []streamSegment
	bytes      int
	fin        bool
}
type interpretedSession struct {
	row                 NetworkSession
	streams             [2]tcpStream
	initialSYN          uint32
	initialSYNDirection int
}
type captureInterpreter struct {
	it                                Item
	active                            map[string]int
	sessions                          []interpretedSession
	result                            NetworkInterpretation
	bytes                             int
	sessionBudget                     int
	observationBudget, metadataBudget int
	attachments                       map[int][]ProtocolObservation
}

func parseCaptureAdvanced(data []byte, it Item, records, flows, sessions, observations, metadataBytes int) ([]Event, []NetworkFlow, CaptureSummary, NetworkInterpretation) {
	i := &captureInterpreter{it: it, active: map[string]int{}, attachments: map[int][]ProtocolObservation{}, sessionBudget: min(max(sessions, 0), networkSessionLimit), observationBudget: min(max(observations, 0), 5000), metadataBudget: min(max(metadataBytes, 0), 4<<20), result: NetworkInterpretation{Evidence: it.ID, Sessions: []NetworkSession{}, Observations: []ProtocolObservation{}, Omissions: map[string]int{}, Checksums: map[string]int{}}}
	events, flowRows, summary := parsePCAPWithInterpreter(data, it, records, flows, i)
	i.finish(events)
	return events, flowRows, summary, i.result
}

func (i *captureInterpreter) addObservation(o ProtocolObservation, event int) {
	size := len(JSON(o))
	if len(i.result.Observations) >= i.observationBudget || i.result.MetadataBytes+size > i.metadataBudget {
		i.result.Limited = true
		i.omit("protocol_metadata_limit")
		return
	}
	i.result.MetadataBytes += size
	i.result.Observations = append(i.result.Observations, o)
	i.attachments[event] = append(i.attachments[event], o)
}

func packetReference(ev Event) PacketReference {
	return PacketReference{CaptureContext: ev.CaptureContext, Packet: ev.Packet, ByteOffset: ev.ByteOffset, Time: ev.Time, CapturedLength: ev.CapturedLength, OriginalLength: ev.OriginalLength}
}

func (i *captureInterpreter) omit(reason string) { i.result.Omissions[reason]++ }

func (i *captureInterpreter) observe(h packetHeader, ev Event, event int) {
	i.result.Checksums["transport_"+h.transportChecksum]++
	if h.ipChecksum != "" {
		i.result.Checksums["ip_"+h.ipChecksum]++
	}
	ref := packetReference(ev)
	if h.protocol == "UDP" {
		if (h.sport == 53 || h.dport == 53) && h.complete {
			dns, e := parseDNS(h.payload)
			if e != nil {
				i.omit("dns_malformed_or_unsupported")
			} else {
				i.addObservation(ProtocolObservation{CaptureContext: ev.CaptureContext, Evidence: ev.Evidence, Source: ev.Source, Protocol: "DNS", DNS: dns, References: []PacketReference{ref}}, event)
			}
		}
		return
	}
	a := netip.AddrPortFrom(netip.MustParseAddr(h.src), h.sport).String()
	b := netip.AddrPortFrom(netip.MustParseAddr(h.dst), h.dport).String()
	direction := 0
	if a > b {
		a, b = b, a
		direction = 1
	}
	key := fmt.Sprintf("%d/%d/%s/%s", ev.Section, ev.InterfaceID, a, b)
	idx, found := i.active[key]
	newSYN := h.tcpFlags&0x12 == 0x02
	if found {
		previous := &i.sessions[idx]
		if (newSYN && (previous.row.Closed || !previous.row.SYNObserved || previous.initialSYN != h.sequence || previous.initialSYNDirection != direction)) || ev.Time.Sub(previous.row.Last) > 10*time.Minute {
			found = false
		}
	}
	if !found {
		if len(i.sessions) >= i.sessionBudget {
			i.result.Limited = true
			i.omit("session_limit")
			return
		}
		idx = len(i.sessions)
		i.active[key] = idx
		i.sessions = append(i.sessions, interpretedSession{row: NetworkSession{CaptureContext: ev.CaptureContext, ID: fmt.Sprintf("%s-S%d", ev.Evidence, idx+1), Evidence: ev.Evidence, Source: ev.Source, EndpointA: a, EndpointB: b, First: ev.Time, Last: ev.Time, Checksums: map[string]int{}, References: []PacketReference{}}})
	}
	s := &i.sessions[idx]
	s.row.Packets++
	if ev.Time.Before(s.row.First) {
		s.row.First = ev.Time
	}
	if ev.Time.After(s.row.Last) {
		s.row.Last = ev.Time
	}
	s.row.Checksums[h.transportChecksum]++
	if len(s.row.References) < pcapReferenceLimit {
		s.row.References = append(s.row.References, ref)
	} else {
		s.row.ReferencesTruncated = true
	}
	if s.row.Closed && len(h.payload) > 0 && h.tcpFlags&4 == 0 && h.tcpFlags&1 == 0 {
		s.row.Gaps = true
		i.omit("payload_after_close_ambiguous")
		return
	}
	stream := &s.streams[direction]
	if h.tcpFlags&2 != 0 {
		if !stream.known {
			stream.base = h.sequence + 1
			stream.known = true
		}
		stream.syn = true
		if newSYN {
			s.row.SYNObserved = true
			s.initialSYN = h.sequence
			s.initialSYNDirection = direction
		}
	}
	if h.tcpFlags&1 != 0 {
		stream.fin = true
	}
	if h.tcpFlags&4 != 0 || (s.streams[0].fin && s.streams[1].fin) {
		s.row.Closed = true
	}
	if !h.complete {
		s.row.Gaps = true
		i.omit("truncated_tcp_payload")
		return
	}
	if len(h.payload) == 0 {
		return
	}
	sequence := h.sequence
	if h.tcpFlags&2 != 0 {
		sequence++
	}
	if !stream.known {
		stream.base = sequence
		stream.known = true
	}
	offset := int64(int32(sequence - stream.base))
	if offset > networkStreamLimit || offset < -networkStreamLimit || len(stream.segments) >= 256 || stream.bytes+len(h.payload) > networkStreamLimit || i.bytes+len(h.payload) > networkReassemblyLimit {
		s.row.Limited = true
		i.result.Limited = true
		i.omit("stream_limit")
		return
	}
	for _, segment := range stream.segments {
		start, end := max(offset, segment.offset), min(offset+int64(len(h.payload)), segment.offset+int64(len(segment.payload)))
		if start < end {
			if !bytes.Equal(h.payload[start-offset:end-offset], segment.payload[start-segment.offset:end-segment.offset]) {
				s.row.Conflict = true
				i.omit("conflicting_tcp_overlap")
				return
			}
			if offset == segment.offset && bytes.Equal(h.payload, segment.payload) {
				s.row.Retransmissions++
				return
			}
		}
	}
	copyBytes := append([]byte(nil), h.payload...)
	stream.segments = append(stream.segments, streamSegment{offset: offset, payload: copyBytes, ref: ref, event: event})
	stream.bytes += len(copyBytes)
	i.bytes += len(copyBytes)
}

func contiguousStream(stream *tcpStream) ([]byte, []PacketReference, int, bool) {
	if len(stream.segments) == 0 {
		return nil, nil, 0, false
	}
	sort.SliceStable(stream.segments, func(i, j int) bool { return stream.segments[i].offset < stream.segments[j].offset })
	base := stream.segments[0].offset
	gap := stream.syn && base != 0
	if base > 0 && stream.syn {
		return nil, nil, 0, true
	}
	output := []byte{}
	refs := []PacketReference{}
	first := stream.segments[0].event
	for _, segment := range stream.segments {
		offset := segment.offset - base
		if offset > int64(len(output)) {
			gap = true
			break
		}
		remaining := offset + int64(len(segment.payload)) - int64(len(output))
		if remaining > 0 {
			output = append(output, segment.payload[len(segment.payload)-int(remaining):]...)
			if len(refs) < pcapReferenceLimit {
				refs = append(refs, segment.ref)
			}
		}
	}
	return output, refs, first, gap
}

func (i *captureInterpreter) finish(events []Event) {
	for n := range i.sessions {
		s := &i.sessions[n]
		for direction := range s.streams {
			stream := &s.streams[direction]
			payload, refs, first, gap := contiguousStream(stream)
			s.row.Gaps = s.row.Gaps || gap
			s.row.Bytes += len(payload)
			if len(payload) == 0 || s.row.Conflict {
				continue
			}
			observation := ProtocolObservation{CaptureContext: s.row.CaptureContext, Evidence: s.row.Evidence, Source: s.row.Source, Session: s.row.ID, References: refs, ReferencesTruncated: len(stream.segments) > len(refs), PartialStream: !stream.syn || s.row.Gaps || s.row.Limited}
			endpointA, _ := netip.ParseAddrPort(s.row.EndpointA)
			endpointB, _ := netip.ParseAddrPort(s.row.EndpointB)
			if endpointA.Port() == 53 || endpointB.Port() == 53 {
				if len(payload) >= 2 {
					size := int(binary.BigEndian.Uint16(payload[:2]))
					if size <= len(payload)-2 {
						dns, e := parseDNS(payload[2 : 2+size])
						if e == nil {
							observation.Protocol = "DNS"
							observation.DNS = dns
						} else {
							i.omit("dns_malformed_or_unsupported")
						}
					}
				}
			} else if http, e := parseHTTPMetadata(payload); e == nil {
				observation.Protocol = "HTTP"
				observation.HTTP = http
			} else if tls, e := parseTLSClientHello(payload); e == nil {
				observation.Protocol = "TLS"
				observation.TLS = tls
			}
			if observation.Protocol != "" {
				i.addObservation(observation, first)
			}
		}
		i.result.Sessions = append(i.result.Sessions, s.row)
	}
	for event, observations := range i.attachments {
		if event >= 0 && event < len(events) {
			events[event].Network = append(events[event].Network, observations...)
		}
	}
}

func checksumStatus(b []byte) string {
	if internetChecksum(b) == 0 {
		return "valid"
	}
	return "invalid_or_offloaded"
}
func internetChecksum(b []byte) uint16 {
	var sum uint32
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b[:2]))
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	return ^uint16(sum)
}
func transportChecksumStatus(version byte, src, dst string, protocol byte, payload []byte) string {
	a, b := netip.MustParseAddr(src), netip.MustParseAddr(dst)
	var pseudo []byte
	if version == 4 {
		aa, bb := a.As4(), b.As4()
		pseudo = append(pseudo, aa[:]...)
		pseudo = append(pseudo, bb[:]...)
		pseudo = append(pseudo, 0, protocol, byte(len(payload)>>8), byte(len(payload)))
	} else {
		aa, bb := a.As16(), b.As16()
		pseudo = append(pseudo, aa[:]...)
		pseudo = append(pseudo, bb[:]...)
		pseudo = binary.BigEndian.AppendUint32(pseudo, uint32(len(payload)))
		pseudo = append(pseudo, 0, 0, 0, protocol)
	}
	return checksumStatus(append(pseudo, payload...))
}

func exportNetworkInterpretations(rows []NetworkInterpretation, out string) error {
	var b bytes.Buffer
	w := csv.NewWriter(&b)
	if e := w.Write([]string{"evidence", "source", "session", "protocol", "packet_references", "metadata_json", "partial_stream"}); e != nil {
		return e
	}
	for _, row := range rows {
		for _, o := range row.Observations {
			if e := w.Write([]string{o.Evidence, csvSafe(o.Source), o.Session, o.Protocol, strconv.Itoa(len(o.References)), csvSafe(string(JSON(o))), strconv.FormatBool(o.PartialStream)}); e != nil {
				return e
			}
		}
	}
	w.Flush()
	if e := w.Error(); e != nil {
		return e
	}
	return WriteNew(filepath.Join(out, "network-protocols.csv"), b.Bytes())
}

func validProtocolText(s string) bool {
	if len(s) > 4096 {
		return false
	}
	for _, r := range s {
		if r < 32 || r > 126 {
			return false
		}
	}
	return true
}
func protocolError() error {
	return fmt.Errorf("malformed, incomplete or unsupported application header")
}

func parseHTTPMetadata(payload []byte) (*HTTPMetadata, error) {
	end := bytes.Index(payload, []byte("\r\n\r\n"))
	if end < 0 || end > 16<<10 {
		return nil, protocolError()
	}
	lines := strings.Split(string(payload[:end]), "\r\n")
	if len(lines) > 128 {
		return nil, protocolError()
	}
	first := strings.SplitN(lines[0], " ", 3)
	if len(first) != 3 {
		return nil, protocolError()
	}
	m := &HTTPMetadata{}
	if first[0] == "HTTP/1.0" || first[0] == "HTTP/1.1" {
		m.Version = first[0]
		code, e := strconv.Atoi(first[1])
		if e != nil || code < 100 || code > 599 {
			return nil, protocolError()
		}
		m.Status = code
	} else {
		switch first[0] {
		case "GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "CONNECT":
		default:
			return nil, protocolError()
		}
		if first[2] != "HTTP/1.0" && first[2] != "HTTP/1.1" {
			return nil, protocolError()
		}
		if !validProtocolText(first[1]) {
			return nil, protocolError()
		}
		m.Method, m.Target, m.Version = first[0], first[1], first[2]
	}
	hosts := 0
	for _, line := range lines[1:] {
		if line == "" || line[0] == ' ' || line[0] == '\t' {
			return nil, protocolError()
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok || !validProtocolText(name) || !validProtocolText(strings.TrimSpace(value)) {
			return nil, protocolError()
		}
		if strings.EqualFold(name, "Host") {
			hosts++
			m.Host = strings.TrimSpace(value)
		}
	}
	if hosts > 1 || (m.Method != "" && m.Version == "HTTP/1.1" && hosts != 1) {
		return nil, protocolError()
	}
	return m, nil
}
