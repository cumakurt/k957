# Case examination (0.15.0)

`k957 case` reads every collection under a store (default `./output`), verifies each one, and writes a derived dossier. The dossier is not a new evidence package. The signed collection directories remain the evidence.

Default output is `./case/<UTC timestamp>/`, outside `output/`, so a later `verify` does not treat the dossier as a collection. `--out` must be a new directory. `--store` selects another collection root. `--trusted-key` is the same external trust check used by `verify`. `--hash-set` applies an examiner SHA-256 list.

## Outputs

| File | Role |
|---|---|
| `case.json` | `k957-case/1` summary: hosts, failures, duplicate groups, hash matches, signature mismatches, media counts, collection boundaries |
| `report.html` | Examiner brief for that summary |
| `inventory.csv` | Every acquired object, up to 100,000 |
| `timeline.csv` | Collection start/finish, memory acquisition, and file modification times |
| `duplicates.csv` | SHA-256 values shared by two or more non-empty objects |
| `hash-matches.csv` | Objects listed in the examiner set |
| `bodyfile.txt` | Sleuth Kit body file for `mactime` |

`bodyfile.txt` fills mtime only. atime, ctime, crtime, uid, gid and the MD5 column are zero. SHA-256 in the inventory is the authoritative hash. The mode column is `r/r--------` because logical collection does not claim the original permission bits.

A duplicate hash means the acquired bytes match. It does not prove that one file was copied from the other or that the same person acted. An extension mismatch means the magic bytes and the file name disagree. It is a triage signal, not proof of concealment.

Collections that fail verification are listed and are not inventoried. The command exits 1 when any collection fails.

Piped stdout is one JSON summary. The report navigation hint and progress appear on stderr. This corrects the earlier `Case:` prefix on stdout; scripts that removed that prefix should now parse stdout directly.

## Hash sets

`analyze`, `share` and `case` accept `--hash-set`. Two forms are accepted:

- `k957-hashset/1` JSON: `{"schema":"k957-hashset/1","entries":[{"sha256":"<64 hex>","verdict":"known-bad","label":"optional"}]}`
- Lines. A bare SHA-256 is `known-bad`. `known-good <hash> [label]` and `known-bad <hash> [label]` are explicit. `#` starts a comment.

`known-bad` becomes an unreviewed finding on `analyze` and `share`. `known-good` is recorded and is not a finding. Neither verdict is a trust decision or a malware conclusion. Labels appear in full findings. The masked sharing projection omits descriptions and labels. The set is limited to 32 MiB and 500,000 hashes. Conflicting verdicts or labels for one hash are rejected.

## File signatures

Analysis classifies the first 560 bytes of each evidence object. Recognized families include PE, ELF, Mach-O, PDF, PNG, JPEG, GIF, ZIP, gzip, 7-Zip, RAR, OLE, SQLite, EVTX, registry hives, PCAP, PCAPNG, LiME, scripts and XML. The result is `filetypes.csv`. Classification uses header bytes retained during SHA-256 verification. Selected SQLite/WAL, EVTX, clean Registry and binary launchd plist formats have separate native workers; most classified families remain inventory only.

## Collector identity

Full-mode `collection.json` includes `collector_sha256`, the SHA-256 of the `k957` executable that wrote the record. The collection signature covers that field. Compare it with a copy of the tool obtained independently. A generated signing key still only proves internal consistency.

## What this release does not do

Physical-device imaging, MFT, USN v4/live journal acquisition, in-process kernel reconstruction and trusted timestamping remain pending. Separate Sleuth Kit and offline Volatility workflows retain input/tool provenance. Reports remain derived documents. Court use still requires the examiner to confirm each cited object from the signed collection.

## Unified examination index

`case-index.sqlite` and streamed `examination.csv` add scoped events, findings, validated review history, activity, symbol-free RAM observations and acquisition boundaries from verified collections. `--rules`, repeatable `--review` and `--review-key` select analysis/review inputs. The index is a rebuildable derived artifact, limited to one million rows/2 GiB; queries have five-second timeouts and up to 200 rows per page. `case-query`, `case-serve`, `case-correlate` and signed `case-bookmark` workflows are documented in [EXAMINATION_WORKFLOWS.md](EXAMINATION_WORKFLOWS.md). Legacy inventory output remains bounded at 100,000 objects.

Legacy inventory, file modification timeline and bodyfile exports use additive `case_inventory` and `case_boundary` tables in that same derived database. Existing schema-1 readers ignore these tables. They are populated in the existing transaction with prepared statements and remain independent of the examination row ceiling: reaching that ceiling does not silently truncate a permitted legacy inventory. SQLite orders seconds/nanoseconds numerically; exact ties keep inventory insertion order first, then chronological/type-sorted acquisition boundaries. Zero modification time is omitted from the timeline and remains zero in the bodyfile.

Inventory/timeline/examination CSV and bodyfile rows stream directly to exclusively created files. CSV formula escaping and the previous columns are retained. Case HTML also writes directly; failed output generation removes its newly created file, and a failed case operation removes the new dossier directory. Complete files are synced and closed before success. The case still retains the verified manifest, per-collection analysis, duplicate groups and summary arrays in memory; the SQLite export change does not make the whole examination constant-memory.

An explicit synthetic collection/case check is available through `scripts/validate.py --source-objects 100000` or standalone `scripts/source_scale.py`. See [SOURCE_SCALE.md](SOURCE_SCALE.md) for scope, measurements and the remaining resumable/analysis JSON work.

## Default documents and complete memory results

Case and bookmarked-record exports now include native `report.pdf` and `documents.json` alongside HTML. The incident reading edition samples indexed rows and discloses its projection. Exact offline indicator matches support `case-query --kind indicator_match`. Complete memory scan sidecars and configured kernel suite files are retained separately from the bounded general case index; reaching inventory/index capacity does not stop memory examination. Kernel failures, unavailable plugins, image hashes and complete result references remain visible. See [reporting](REPORTING.md), [memory configuration](MEMORY.md) and [next development scopes](DEVELOPMENT_PLAN.md).

## Exact native record lookup

`case-query` and `case-bookmark` accept three additional event-row filters:

- `--native-parser`: exact, case-sensitive `native.parser` value, up to 64 bytes (for example `USN`, `SQLite` or `EVTX`).
- `--native-record`: exact, case-sensitive `native.record` value, up to 256 bytes.
- `--usn-file-id`: 16 or 32 hex characters copied from `file_id_le_hex`, with no `0x` prefix; uppercase input is normalized to lowercase. Preserve leading zeroes and byte order.

```sh
k957 case-query --case ./case-dossier --native-parser USN --native-record 4096 --limit 50
k957 case-query --case ./case-dossier --digest '<collection-sha256>' --evidence E000001 --usn-file-id 0100000000000100
```

Replace the digest placeholder with the collection digest from the case index. Filters are combined with each other and the existing host, evidence, collection and time scopes. Native reference filters imply event rows; specifying a different `--kind` is rejected. Equal record/file IDs across unrelated collections do not establish identity.

Exact filters read the stored event payload, so existing schema-1 indexes containing those fields remain usable without modification. Missing fields do not match. New case builds additionally include native parser/table/record IDs and USN file/parent IDs/USNs in literal text search; older indexes need a new derived case build for that expanded text search. Query parameters remain bound values, JSON paths are fixed, and the existing five-second timeout and 200-row page maximum apply. No query performance improvement is claimed.

The local viewer exposes the same filters. A USN row's **Related file records** button clears prior filters and applies its collection digest, evidence ID and file ID. New searches cancel older requests and discard stale responses. Pagination uses the last submitted filter set; editing a field takes effect when Search is submitted. These are read-only queries. `case-serve` opens the viewer; its on-page controls select filters.

Signed `case-bookmark` exports retain the exact filter values in `selection.json` alongside the selected page and source-index digest. This records the examiner's selection, not a complete file history.
