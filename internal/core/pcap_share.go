package core

import (
	"context"
	"path/filepath"
	"strconv"
	"time"
)

type SharedPacketReference struct {
	CaptureContext
	Packet         int        `json:"packet"`
	ByteOffset     int64      `json:"byte_offset"`
	Time           *time.Time `json:"time,omitempty"`
	CapturedLength int64      `json:"captured_length"`
	OriginalLength int64      `json:"original_length"`
}
type SharedNetworkFlow struct {
	CaptureContext
	Evidence            string                  `json:"evidence"`
	Source              string                  `json:"source"`
	Protocol            string                  `json:"protocol"`
	SourceIP            string                  `json:"source_ip"`
	DestinationIP       string                  `json:"destination_ip"`
	SourcePort          uint16                  `json:"source_port"`
	DestinationPort     uint16                  `json:"destination_port"`
	Packets             int                     `json:"packets"`
	CapturedBytes       int64                   `json:"captured_bytes"`
	OriginalBytes       int64                   `json:"original_bytes"`
	First               *time.Time              `json:"first,omitempty"`
	Last                *time.Time              `json:"last,omitempty"`
	References          []SharedPacketReference `json:"references"`
	ReferencesTruncated bool                    `json:"references_truncated"`
}
type SharedCaptureSummary struct {
	Sections           int            `json:"sections,omitempty"`
	InterfaceCount     int            `json:"interface_count,omitempty"`
	Blocks             int            `json:"blocks,omitempty"`
	IgnoredBlocks      int            `json:"ignored_blocks,omitempty"`
	Evidence           string         `json:"evidence"`
	Source             string         `json:"source"`
	Format             string         `json:"format"`
	Records            int            `json:"records"`
	Parsed             int            `json:"parsed"`
	Skipped            int            `json:"skipped"`
	TruncatedPackets   int            `json:"truncated_packets"`
	SkipReasons        map[string]int `json:"skip_reasons"`
	FlowOmittedPackets int            `json:"flow_omitted_packets"`
	Limited            bool           `json:"limited"`
	HasError           bool           `json:"has_error"`
}

func shareNetworkProtocol(s string) string {
	if s == "" {
		return ""
	}
	return shareEnum(s, "TCP", "UDP")
}
func projectSharedNetwork(a Analysis, s *SharedReport, m *shareMasker, sourceID func(string) string) {
	for _, f := range a.NetworkFlows {
		n := SharedNetworkFlow{CaptureContext: f.CaptureContext, Evidence: sourceID(f.Evidence), Source: m.value("paths", f.Source), Protocol: shareNetworkProtocol(f.Protocol), SourceIP: m.value("ips", f.SourceIP), DestinationIP: m.value("ips", f.DestinationIP), SourcePort: f.SourcePort, DestinationPort: f.DestinationPort, Packets: f.Packets, CapturedBytes: f.CapturedBytes, OriginalBytes: f.OriginalBytes, First: m.stamp(f.First), Last: m.stamp(f.Last), References: []SharedPacketReference{}, ReferencesTruncated: f.ReferencesTruncated}
		for _, r := range f.References {
			n.References = append(n.References, SharedPacketReference{CaptureContext: r.CaptureContext, Packet: r.Packet, ByteOffset: r.ByteOffset, Time: m.stamp(r.Time), CapturedLength: r.CapturedLength, OriginalLength: r.OriginalLength})
		}
		s.NetworkFlows = append(s.NetworkFlows, n)
	}
	for _, c := range a.CaptureSummaries {
		reasons := map[string]int{}
		for k, v := range c.SkipReasons {
			key := shareEnum(k, "invalid_timestamp", "short_link_header", "vlan_depth_limit", "unsupported_link_protocol", "short_ip_header", "unsupported_link_type", "ip_version_mismatch", "invalid_ip_length", "fragment", "zero_ipv6_payload_unsupported", "unsupported_ip_version", "extension_depth_limit", "short_extension_header", "invalid_extension_length", "short_transport_header", "invalid_transport_length", "unsupported_ip_protocol", "invalid_link_header", "missing_timestamp", "obsolete_packet_block", "unsupported_timestamp_resolution", "unsupported_timestamp_timezone", "unsupported_link_metadata")
			reasons[key] += v
		}
		s.CaptureSummaries = append(s.CaptureSummaries, SharedCaptureSummary{Sections: c.Sections, InterfaceCount: len(c.Interfaces), Blocks: c.Blocks, IgnoredBlocks: c.IgnoredBlocks, Evidence: sourceID(c.Evidence), Source: m.value("paths", c.Source), Format: shareEnum(c.Format, "PCAP", "PCAPNG"), Records: c.Records, Parsed: c.Parsed, Skipped: c.Skipped, TruncatedPackets: c.TruncatedPackets, SkipReasons: reasons, FlowOmittedPackets: c.FlowOmittedPackets, Limited: c.Limited, HasError: c.Error != ""})
	}
	if len(a.CaptureSummaries) > 0 {
		s.Notes = append(s.Notes, "Shared PCAP/PCAPNG fields contain TCP/UDP packet headers and directional flow totals; payload bytes, checksum details and session reconstruction are omitted from this projection. Flows group packets by directional five-tuple, separately for each PCAPNG section/interface. MAC/VLAN and SLL2 operating-system interface identity are not grouping keys. Untimed/obsolete packet blocks are skipped; other blocks are counted only. Ports, lengths, counts and packet positions are retained; inspect the coverage table for omissions.")
	}
}
func exportSharedNetwork(s SharedReport, out string) error {
	return exportSharedNetworkContext(context.Background(), s, out)
}
func exportSharedNetworkContext(ctx context.Context, s SharedReport, out string) error {
	if len(s.NetworkFlows) > 0 {
		rows := [][]string{}
		for _, f := range s.NetworkFlows {
			rows = append(rows, []string{f.Evidence, f.Source, f.Protocol, f.SourceIP, strconv.Itoa(int(f.SourcePort)), f.DestinationIP, strconv.Itoa(int(f.DestinationPort)), strconv.Itoa(f.Packets), strconv.FormatInt(f.CapturedBytes, 10), strconv.FormatInt(f.OriginalBytes, 10), sharedTime(f.First), sharedTime(f.Last), strconv.Itoa(len(f.References)), strconv.FormatBool(f.ReferencesTruncated), strconv.Itoa(f.Section), strconv.FormatUint(uint64(f.InterfaceID), 10)})
		}
		if e := sharedCSVContext(ctx, filepath.Join(out, "network.csv"), []string{"evidence", "source", "protocol", "source_ip", "source_port", "destination_ip", "destination_port", "packets", "captured_bytes", "original_bytes", "first", "last", "reference_count", "references_truncated", "section", "interface_id"}, rows); e != nil {
			return e
		}
	}
	if len(s.CaptureSummaries) > 0 {
		rows := [][]string{}
		for _, c := range s.CaptureSummaries {
			rows = append(rows, []string{c.Evidence, c.Source, c.Format, strconv.Itoa(c.Records), strconv.Itoa(c.Parsed), strconv.Itoa(c.Skipped), strconv.Itoa(c.TruncatedPackets), strconv.Itoa(c.FlowOmittedPackets), strconv.FormatBool(c.Limited), strconv.FormatBool(c.HasError), string(JSON(c.SkipReasons)), strconv.Itoa(c.Sections), strconv.Itoa(c.InterfaceCount), strconv.Itoa(c.Blocks), strconv.Itoa(c.IgnoredBlocks)})
		}
		return sharedCSVContext(ctx, filepath.Join(out, "captures.csv"), []string{"evidence", "source", "format", "records", "parsed", "skipped", "truncated_packets", "flow_omitted_packets", "limited", "has_error", "skip_reasons", "sections", "interface_count", "blocks", "ignored_blocks"}, rows)
	}
	return nil
}
