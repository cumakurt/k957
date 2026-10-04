# Classic PCAP analysis — v0.9.0

`analyze`/`share` recognize capture candidates by `.pcap`, `.cap`, `.pcapng` or supported magic bytes, including extensionless classic PCAP. This document covers classic-PCAP behavior introduced in 0.9.0. PCAPNG and Linux SLL/SLL2 arrived in 0.10.0; see [PCAPNG.md](PCAPNG.md). Current session/protocol/checksum extensions are in [EXAMINATION_WORKFLOWS.md](EXAMINATION_WORKFLOWS.md#network-sessions-and-protocol-metadata). The historical filename is retained; its content is English.

```sh
k957 collect --root /source/network --out /evidence/network.k957 \
  --case CASE-001 --operator Examiner --scope "Authorized captures"
k957 analyze --in /evidence/network.k957 --out /reports/network-001
k957 share --in /evidence/network.k957 --out /sharing/network-001
```

Only existing captures are read. No live interfaces, packet transmission, external enrichment or DNS resolution are performed; libpcap/Npcap is not required.

## Supported headers

- PCAP v2.4, little/big endian, microsecond/nanosecond timestamps converted to UTC.
- Ethernet (link type 1), raw IPv4/IPv6 (101), plus current SLL/SLL2 extensions.
- Up to two 802.1Q/802.1ad VLAN tags.
- IPv4 header/total lengths, addresses and protocol.
- IPv6 base header and up to eight Hop-by-Hop, Routing, Destination Options or AH extensions.
- TCP/UDP ports and the lower eight TCP flag bits.
- Evidence/source/packet ordinal/record-header byte references.

IP fragments are not reassembled. IPv4 fragments and all IPv6 Fragment headers, including atomic fragments, are skipped. IPv6 jumbograms, ESP, other transports, ARP, Wi-Fi/radiotap and extra link/FCS metadata remain unsupported. Unsupported/short headers are disclosed.

Current analysis adds bounded TCP reconstruction/session candidates, selected DNS/initial HTTP/TLS fields and complete-packet checksum checks. It does not decrypt TLS, extract files or run literal payload rules. Original v0.9 header parsing did not validate checksums; current results expose invalid-or-offloaded uncertainty. SHA-256 verifies captured bytes independently of traffic authenticity or complete protocol validity/IPv6 extension ordering.

## Directional flows

Packets with matching **protocol + source IP/port + destination IP/port** share a directional group within one evidence object. Reverse traffic is separate. Flow totals merge repeated tuples across time and are independent of the newer bounded session candidates. MAC/VLAN identities are not flow keys; PCAPNG sections/interfaces are scoped separately.

Each group retains packet count, captured/original byte totals, minimum/maximum time and bounded packet references. Bytes are **recorded frame lengths**, not application data or successfully delivered network bytes. Captured length below original length counts as truncation. Complete required headers can still be interpreted; incomplete headers are skipped.

Capture order can differ from timestamp order. First/last values use time extrema. Capture-host clock skew is not measured and timezone is not inferred.

## Outputs and references

- `analysis.json`: capture summaries, directional flows and packet timeline events; newer interpretations have their own records.
- `report.html`: coverage, skips, flows and references.
- `network.csv` when a parsed flow exists; `captures.csv` when a capture candidate exists.
- `timeline.csv`: packet, protocol, ports, lengths, flags and capture scope.

Packet IPs participate in basic cross-object shared-value correlations. `byte_offset` identifies the beginning of the **16-byte PCAP record header**, rather than the IP/payload position. Ordinals begin at 1 and include complete skipped records. Shared IP does not prove identity or independent corroboration.

Whole-object SHA-256 rules apply; literal text rules do not scan raw capture payload. They continue to apply to separate text/log sources.

## Counts and resource ceilings

- 64 MiB per capture and 256 MiB total. Oversized files are skipped rather than partially parsed.
- 20,000 records per file and a shared 50,000-unit log/capture budget. Logs consume emitted events; captures consume each complete read record. Metadata events are separate.
- 10,000 directional flows per analysis. New-flow excess increments `flow_omitted_packets`; earlier groups continue counting and packet timeline entries can remain.
- First 20 references per flow; extra references set `references_truncated` while totals continue.
- 1 MiB maximum captured record data; lengths cannot exceed snaplen/original size. Malformed lengths/short record headers/bodies stop that file without guessing resynchronization.

`records` counts complete bounded records; `parsed + skipped = records`. A malformed partial tail is excluded and reported as an error. Reasons distinguish invalid time, short headers, unsupported protocol and fragments. `truncated_packets` can include parsed/skipped records. `limited` discloses file/byte/record limits; flow omissions are separate. None establishes complete examination of the source.

## Sharing

Packet timeline, flows, references and coverage use the separate sharing model. IPs/paths default to aliases and source times are omitted; protocol, ports, flags, lengths, counts, ordinals and byte positions remain. No anonymity guarantee is provided. Retained categories/cross-field masking follow [SHARING_TR.md](SHARING_TR.md).

## Validation and format references

Tests cover four timestamp/endian variants, IPv4/IPv6, VLAN/extensions, fragments, malformed lengths, truncation, record/flow/reference limits and reverse traffic. `scripts/pcap_integration.py` independently constructs captures with Python struct and compares times/positions/sizes. Original v0.9 results in [TEST_REPORT.md](TEST_REPORT.md) and `pcap-fuzz.txt` are historical; current validation has separate receipts. Broad real-world capture compatibility remains open.

Primary format references used during implementation:

- [libpcap savefile format](https://github.com/the-tcpdump-group/libpcap/blob/master/pcap-savefile.manfile.in)
- [tcpdump link types](https://github.com/the-tcpdump-group/tcpdump-htdocs/blob/master/linktypes.html)
- [IPv4, RFC 791](https://www.rfc-editor.org/rfc/rfc791.html)
- [IPv6, RFC 8200](https://www.rfc-editor.org/rfc/rfc8200.html)
- [UDP, RFC 768](https://www.rfc-editor.org/rfc/rfc768.html)
- [TCP, RFC 9293](https://www.rfc-editor.org/rfc/rfc9293.html)

This is a bounded subset, not a complete standards implementation. Original format review: 2026-09-28.
