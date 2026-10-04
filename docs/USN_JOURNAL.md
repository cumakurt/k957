# Offline USN journal examination

k957 interprets exported raw Windows USN journal record streams through the isolated native parser worker. Supported layouts are `USN_RECORD_V2` 2.0 and `USN_RECORD_V3` 3.0. This is an offline parser; it does not acquire NTFS alternate data streams or issue live journal control calls.

## Input and workflow

Collect an examiner-exported stream named `*.usn`, `$J` or `$UsnJrnl:$J` in a logical evidence package, then analyze the signed package:

```sh
k957 collect --root ./exported-journal --out ./journal.k957 --case CASE-001 --operator Examiner --scope "Offline journal export"
k957 analyze --in ./journal.k957 --out ./journal-report
```

These names are candidate hints because USN has no fixed file signature. A recognized conflicting file signature takes precedence. The parser validates each record boundary, version, filename extent, UTF-16 surrogate sequence and timestamp before producing an event. It accepts aligned raw records and zero-filled sparse/padding regions. DeviceIoControl response buffers containing a leading next-USN cursor are not this raw stream format; export the records separately and preserve that transformation's provenance.

The worker receives a private hash-checked copy and retains the existing native input, output, time and event budgets: 128 MiB input, 32 MiB worker output, 30-second parent timeout and the shared 50,000-event projection. USN events also have an 8 MiB projection budget. These bounds apply to this logical artifact parser, not memory analysis. Inspect parser and coverage records for omissions.

## Retained evidence references

Each `usn_change` timeline event records:

- Evidence ID, original source and byte offset within the exported stream.
- Record version, length, decimal USN and raw FILETIME alongside UTC.
- Exact 64-bit or 128-bit file/parent identifiers as **little-endian byte hex**.
- Original filename, raw reason mask and decoded reason flags (unknown bits retained).
- Source flags, security ID and file attributes.

`analysis.json` retains the structured `usn` object. `usn.csv` exports all emitted USN events with these fields; HTML links it beside the timeline. Native PDF/DOCX timeline entries include journal and file/parent references within their disclosed reading-edition limits. Shared outputs retain the safe event type and masked source/time projection; filenames, raw identifiers and USN-specific metadata are excluded.

Rules accept `usn.name`, `usn.file_id`, `usn.parent_id`, `usn.number` and `usn.reasons`. IDs use the raw little-endian hex representation above. `usn.reasons` joins symbolic flags with `|`; for example, an event rule can require `type equals usn_change` and `usn.reasons contains FILE_DELETE`. Matches remain review candidates.

## Interpretation and unsupported scope

A filename and parent ID do not establish a full historical path. IDs must remain scoped to their source volume/journal; they cannot identify the same file across unrelated collections automatically. Reasons can accumulate several changes in one record. The parser does not pair rename records, infer a responsible user/process, reconstruct MFT paths or assert journal completeness. It does not recover deleted records or carve through malformed boundaries.

Unsupported versions, including version 4 extent records, are counted as skipped records. Invalid filename/time payloads have separate omission reasons. Invalid record boundaries stop parsing with an explicit error and retain any earlier emitted records. Zero-filled regions do not create events. Original acquired bytes remain authoritative.

The implementation follows Microsoft's [V2 record layout](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/d2a2b53e-bf78-4ef3-90c7-21b918fab304), [V3 layout](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/bb07c6b8-74be-49b5-9723-04f4d9e3e44d) and [reason/alignment semantics](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-usn_record_v2). Compilation is not forensic accuracy assurance; no new runtime/reference tests were run for this addition.

## File record groups

Full analysis exports now include `usn-files.json` and `usn-files.csv`. Groups are keyed by evidence object, source, record version and exact file ID. They retain every emitted record's byte offset and decimal USN, all distinct observed names/parent IDs, observed reason flags and minimum/maximum recorded times. Duplicate records remain counted; the count is not a count of distinct filesystem operations. Files in different journal objects are never automatically merged.

The JSON receipt binds the evidence digest and exact analysis JSON digest. CSV names, parent IDs and references use JSON arrays inside properly quoted cells, preserving embedded delimiters. These groups cover only emitted analysis records: unsupported, malformed and budget-omitted records remain governed by parser coverage. No full historical path, rename pair, file lifetime or responsible process/user is inferred.

HTML and PDF/DOCX show the first 100 deterministically ordered groups and up to five names and parents per group. Additional names and parents are explicitly counted. `documents.json` records group/name/parent omissions as well as the existing overall text limits. Full grouped exports have no additional group-count cutoff. Shared projections do not include the private groups or their filenames/IDs. `report-documents` renders groups from the supplied analysis but does not copy the original report's JSON/CSV sidecars.

## Case navigation

Use `case-query --usn-file-id` to filter by the raw file ID, optionally combined with `--native-parser USN`, `--native-record`, collection digest and evidence ID. The local viewer can open source-scoped related file records directly from a USN row. Signed bookmarks retain these exact filters. See [case lookup](CASE.md#exact-native-record-lookup).
