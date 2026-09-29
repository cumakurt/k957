# PCAPNG and Linux cooked captures — v0.10.0

`analyze` and `share` detect PCAPNG from its magic bytes or a `.pcapng` extension. Use the existing collection and analysis commands; no additional flags or dependencies are required.

```sh
k957 collect --root /captures --out /evidence/network.k957 \
  --case CASE-001 --operator Analyst --scope "Authorized capture files"
k957 analyze --in /evidence/network.k957 --out /reports/network
k957 share --in /evidence/network.k957 --out /reports/network-shared
```

## Supported input

- Section Header Blocks (SHB), Interface Description Blocks (IDB) and Enhanced Packet Blocks (EPB). Sections may use different byte orders. Version 1.0 and the compatible minor version 1.2 are accepted.
- Ethernet (1), raw IP (101), Linux SLL (113) and SLL2 (276). SLL/SLL2 also work in classic PCAP. The existing IPv4/IPv6, VLAN and TCP/UDP header limits apply.
- Interface-specific timestamp resolution and signed offsets. Decimal exponents 0–19 and binary exponents 0–63 are supported. Missing resolution defaults to microseconds. Fractions are converted with integer arithmetic and floored to nanoseconds. Timestamps outside years 0001–9999, overflowing second counts and unsupported resolutions are skipped with a reason.
- Multiple interfaces, with IDs reset at each section. A zero PCAPNG snaplen means unlimited capture length, subject to the application's packet size limit.

Simple Packet Blocks (SPB) have no timestamps and are counted as `missing_timestamp`; no time is inferred. Obsolete Packet Blocks are counted as `obsolete_packet_block`. Their framing, interface and packet lengths are validated before counting. Nonzero FCS metadata and nonzero legacy timezone options are unsupported and cause packet skips. Unsupported link types affect only packets using that interface.

Other block bodies, including names, statistics, custom metadata and decryption secrets, are not interpreted. Their outer framing is checked and they contribute to `ignored_blocks`. Interface names, comments, addresses, hardware strings and packet payloads are never copied into analysis reports. SLL hardware types with non-EtherType semantics (Netlink, radiotap and Frame Relay) are skipped.

## Provenance and output

PCAPNG events, flow groups, packet references and correlation references add `section` and `interface_id`. Sections start at 1; interfaces start at 0 within each section. Zero-valued context fields are omitted in JSON; an absent `interface_id` on a PCAPNG record means interface 0. Classic PCAP and non-packet events have no section context (CSV uses 0).

`byte_offset` points to the beginning of the PCAPNG packet block, including its block type, rather than the packet payload. Packet numbers start at 1 across the entire file, including validated skipped packet blocks. Classic PCAP offsets still point to the 16-byte packet record header.

Flows are grouped by evidence object, section, interface and directional IP/protocol/port tuple. Matching tuples on different PCAPNG interfaces or sections remain separate. MAC, VLAN and the operating-system interface index within an SLL2 header are not grouping keys. Repeated sessions, retransmissions and duplicate captures are not deduplicated.

Full capture summaries include section/block counts and numeric interface descriptions. For PCAPNG, the legacy top-level `link_type` is not applicable (0); use `interfaces[].link_type`. `timestamp_resolution` is `per-interface`, and `timestamp_resolution_raw` holds the IDB resolution byte. `byte_order` becomes `mixed` when sections differ. `blocks` counts blocks whose outer framing was accepted, including a block that subsequently fails content validation or the section/interface limit.

HTML displays section/interface context and ignored block counts. The existing CSV columns retain their order; new context/count columns are appended to `timeline.csv`, `network.csv` and `captures.csv`.

Shared reports retain numeric section/interface references and aggregate counts. They omit interface descriptions, timestamp offsets and raw error text. Existing IP/path masking and timestamp policy also apply to PCAPNG. Retaining ports, lengths and relationships does not guarantee anonymity.

## Bounds and failures

The existing capture budgets apply jointly to PCAP and PCAPNG: 64 MiB per file, 256 MiB in total, 20,000 packet records per file, 50,000 shared log-event/capture-record units, 10,000 flows and 20 stored references per flow. Each captured packet is limited to 1 MiB. PCAPNG additionally permits at most 100,000 inspected blocks, 256 sections and 1,024 total interfaces per file.

Both block length copies, alignment, declared section boundaries, interface references, packet lengths and interpreted option framing are validated before use. Duplicate interpreted options and bytes after an explicit option terminator are rejected. A missing terminator at the exact block boundary is accepted. Unknown option semantics are not validated. Malformed framing stops that file and reports its byte offset; already parsed records remain visible. No resynchronization is attempted.

`parsed + skipped = records`. Structurally invalid or incomplete packet blocks do not increment `records`. `truncated_packets` counts valid records whose captured length is smaller than the original length; they may still contain complete transport headers. `ignored_blocks` is separate from skipped packet counts. Limits are reported through `limited` and `flow_omitted_packets`.

This remains header analysis of existing files. Live capture, payload decoding, fragment reassembly, checksum validation, DNS lookup and connection reconstruction are not implemented.

## Compatibility and validation

Evidence schemas v1/v2 remain readable. Checkpoints and review ledgers are bound to the producing application/analyzer version, as before. Finish a 0.9.0 work directory with its original binary; do not edit its version to force migration. Preserve older signed review histories and recreate an analysis with 0.10.0 before new review work. The packaged 0.9.0 example reports remain historical examples.

Run `go test ./...`, `go vet ./...`, `go test -race ./...` and `python3 scripts/pcapng_integration.py`. The Python test independently constructs mixed-endian captures and checks packet bytes, timestamps, offsets, flow separation, report columns, redaction and evidence immutability. `FuzzPCAPNG` checks malformed inputs and accounting invariants. These synthetic tests do not establish broad compatibility with field captures or actual Windows/macOS operation.

Format references: [PCAPNG draft, revision 05](https://www.ietf.org/archive/id/draft-tuexen-opsawg-pcapng-05.html), [tcpdump SLL definition](https://github.com/the-tcpdump-group/tcpdump-htdocs/blob/master/linktypes/LINKTYPE_LINUX_SLL.html), [tcpdump SLL2 definition](https://github.com/the-tcpdump-group/tcpdump-htdocs/blob/master/linktypes/LINKTYPE_LINUX_SLL2.html). Only the subset described here is implemented.
