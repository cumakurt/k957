# k957 0.4.0 — Structured logs and cross-source correlations

`analyze` extracts time, user, host and IP fields from UTF-8 CSV/JSONL without network services. Collect logs using the existing collector and then analyze. The historical filename is retained; this document is in English.

```sh
k957 collect --root logs --out case.k957 --case CASE-004 --operator Examiner --scope "Authorized logs"
k957 analyze --in case.k957 --out report
```

## Supported schema

- Time: `timestamp`, `time`, `@timestamp`.
- Description: `message`, `event`.
- User: `user`, `username`.
- Host: `host`, `hostname`.
- Source IP: `src_ip`, `source_ip`.
- Destination IP: `dst_ip`, `destination_ip`.

Time is required as RFC3339 with an explicit offset, such as `2026-09-27T14:00:00+03:00` or `2026-09-27T11:00:00Z`. Other fields are optional strings; numbers/objects are rejected and null means empty. Conflicting nonempty aliases skip the record. Invalid nonempty IPs skip the whole event. JSON names are case-sensitive; unknown fields remain in original evidence but are not interpreted.

```csv
timestamp,user,host,src_ip,dst_ip,message
2026-09-27T14:00:00+03:00,alice,workstation,192.0.2.1,198.51.100.2,login
```

JSONL requires one object per physical line:

```json
{"timestamp":"2026-09-27T11:01:00Z","username":"alice","hostname":"workstation","destination_ip":"192.0.2.1","message":"access"}
```

- CSV supports commas, a header, quoted/multiline fields and CRLF. Header names are trimmed/lowercased; empty/duplicate names are rejected, with at most 128 columns.
- JSONL/NDJSON rejects duplicate keys and does not permit multiline objects.
- Other UTF-8 files support lines beginning with explicit RFC3339 or a JSON object.
- This text parser does not infer separators, years, timezones or nested ECS fields, nor parse UTF-16/native journal/EVTX. Separate current native workers are documented in [ARTIFACTS.md](ARTIFACTS.md).

## Source traceability

Events retain evidence ID, source path, physical line, zero-based byte offset, original timestamp and UTC conversion. Multiline CSV references identify the record start rather than an individual field. CSV CRLF normalization can affect parsed descriptions; original bytes remain authoritative. Description projection is bounded at 400 Unicode characters.

`parse_summaries` and the HTML parsing-coverage table expose examined nonempty records, emitted events and skips. Empty lines are not counted. CSV structural/column errors stop parsing that file with diagnostics. `limited=true` discloses an event-budget stop; its `rows` is not the complete file count.

Unexamined text/binary/size-budget inputs are disclosed separately. Literal rules remain physical-line-based; they do not run as a separate engine over joined multiline CSV fields.

## Correlation

A shared user/host/IP across at least two evidence objects creates a candidate correlation. IPs are canonicalized, including mapped IPv4; hosts are lowercased with a trailing dot removed; users are trimmed and case-sensitive. Equal source/destination IP in one event counts once with both roles.

Results retain event/object counts, first/last times and bounded references in JSON/HTML, with summaries in `correlations.csv`. Ordering is deterministic.

**Shared values do not establish identity, a common device or an attack.** NAT, shared accounts, duplicate files, reused IPs and name collisions can create matches. Two objects are not necessarily independent sources. These basic correlations do not infer causality/time proximity or perform DNS/WHOIS/threat-intelligence lookups. Current examiner-supplied temporal estimates are a separate workflow.

## Resource limits

- 8 MiB per text file and 128 MiB total UTF-8 scanning.
- 50,000 parsed log events; file metadata events are additional.
- 65,536-byte JSONL lines/CSV cells.
- 256-byte user/host/IP fields; oversized records are skipped.
- 20,000 distinct entity keys; later new values are omitted with a note.
- 200 references per correlation; processed event/object counts continue beyond reference projection. Inspect `references_truncated` and the full timeline.
- Finding truncation is disclosed; current analysis continues supported parsing after reaching the finding cap.

## Version compatibility

v1/v2 packages remain readable. Reviews are bound to analyzer version; preserve earlier signed histories and reanalyze for new decisions. Complete old checkpoints with their producing binary and analyze the final package using a compatible current reader.
