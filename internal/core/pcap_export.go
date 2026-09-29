package core

import (
	"net"
	"path/filepath"
	"strconv"
	"time"
)

func networkEndpoint(ip string, port uint16) string {
	return net.JoinHostPort(ip, strconv.Itoa(int(port)))
}

func exportNetwork(a Analysis, out string) error {
	if len(a.NetworkFlows) > 0 {
		rows := [][]string{}
		for _, f := range a.NetworkFlows {
			rows = append(rows, []string{f.Evidence, f.Source, f.Protocol, f.SourceIP, strconv.Itoa(int(f.SourcePort)), f.DestinationIP, strconv.Itoa(int(f.DestinationPort)), strconv.Itoa(f.Packets), strconv.FormatInt(f.CapturedBytes, 10), strconv.FormatInt(f.OriginalBytes, 10), f.First.Format(time.RFC3339Nano), f.Last.Format(time.RFC3339Nano), strconv.Itoa(len(f.References)), strconv.FormatBool(f.ReferencesTruncated), strconv.Itoa(f.Section), strconv.FormatUint(uint64(f.InterfaceID), 10)})
		}
		if e := sharedCSV(filepath.Join(out, "network.csv"), []string{"evidence", "source", "protocol", "source_ip", "source_port", "destination_ip", "destination_port", "packets", "captured_bytes", "original_bytes", "first", "last", "reference_count", "references_truncated", "section", "interface_id"}, rows); e != nil {
			return e
		}
	}
	if len(a.CaptureSummaries) > 0 {
		rows := [][]string{}
		for _, s := range a.CaptureSummaries {
			rows = append(rows, []string{s.Evidence, s.Source, s.Format, strconv.Itoa(s.Records), strconv.Itoa(s.Parsed), strconv.Itoa(s.Skipped), strconv.Itoa(s.TruncatedPackets), strconv.Itoa(s.FlowOmittedPackets), strconv.FormatBool(s.Limited), s.Error, string(JSON(s.SkipReasons)), strconv.Itoa(s.Sections), strconv.Itoa(len(s.Interfaces)), strconv.Itoa(s.Blocks), strconv.Itoa(s.IgnoredBlocks)})
		}
		return sharedCSV(filepath.Join(out, "captures.csv"), []string{"evidence", "source", "format", "records", "parsed", "skipped", "truncated_packets", "flow_omitted_packets", "limited", "error", "skip_reasons", "sections", "interface_count", "blocks", "ignored_blocks"}, rows)
	}
	return nil
}
