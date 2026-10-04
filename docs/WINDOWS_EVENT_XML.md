# Windows event XML exports (0.12.0)

Analyze recognizes `.xml` filenames case-insensitively as candidates for a bounded Windows event export parser. This works on all compiled targets without Windows APIs. This XML decoder does not parse binary EVTX, query live event logs, load provider/message DLLs or resolve SIDs. A separate bounded EVTX worker is available in 0.15.0; see EXAMINATION_WORKFLOWS.md. Existing evidence packages can be analyzed again without changing their bytes.

## Input and use

Supported inputs are a single `Event`, a sequence of `Event` fragments, or an `Events` wrapper. Every event must use `http://schemas.microsoft.com/win/2004/08/events/event`; namespace prefixes are allowed. The wrapper may have that namespace or no namespace. Unrelated XML roots are reported as unsupported, rather than searched recursively for event-like descendants.

Input may be UTF-8 (with or without BOM), or UTF-16 LE/BE with a BOM. A supplied encoding declaration must agree with those bytes. UTF-16 without a BOM, other encodings, incomplete code units and unpaired surrogates are rejected. XML declarations are allowed only at the beginning. DTDs, directives, custom entities and other processing instructions are rejected. No external resources are read. Standard XML character references are decoded by Go's strict XML decoder.

For an already acquired EVTX file, Microsoft documents read-only XML queries using `wevtutil qe` with `/lf:true`, `/f:xml`, a root wrapper (`/e:Events`) and Unicode output (`/uni:true`). An example in Windows **cmd.exe**, using a new output path, is:

```bat
wevtutil qe "C:\case\Security.evtx" /lf:true /f:xml /e:Events /uni:true > "D:\exports\security.xml"
```

Shell redirection can replace an existing file; choose a new path. Preserve and hash the original EVTX and record how its XML derivative was produced. The source references below describe the command; this release's local validation uses synthetic exports and has not executed this command on native Windows. PowerShell versions can transcode redirected native output, so confirm the resulting encoding rather than assuming cmd.exe semantics.

Collect the exported directory with the existing authorized collection workflow, then analyze the package:

```sh
k957 analyze --in case.k957 --out report
```

The report contains the original inventory plus Windows event entries in `analysis.json`, a Windows section in `report.html`, and `windows-events.csv` when at least one event is accepted. Existing timeline exports include these events. No new collection option or external dependency is required.

## Interpretation and provenance

- Required fields: one `System`, one `Provider` with at least a name/GUID/legacy source, one decimal unsigned 16-bit `EventID`, one `TimeCreated` with supported `SystemTime`, and a nonempty `Computer` of at most 256 UTF-8 bytes.
- `SystemTime` requires an explicit `Z` or `±HH:MM` offset and zero to nine fractional digits. UTC and the original timestamp string are retained. Zone-less, sub-nanosecond and `RawTime` values are skipped, without guessing epoch/unit/timezone. Clock skew is not measured.
- Optional provider GUID/legacy source, unsigned 16-bit qualifiers, channel, unsigned 8-bit level/version, and unsigned 64-bit record ID are retained. Record IDs are decimal **strings** in JSON to preserve precision. Empty supplied numeric fields and duplicate interpreted elements are rejected.
- Computer names are lowercased and lose one trailing dot for the existing cross-evidence host index. `Security/UserID` is retained as an unresolved, case-sensitive identifier, with a 256-byte limit. Host/SID equality can produce correlations with other structured evidence; it does not establish attribution. Data fields are not mined for speculative users, addresses or actions.
- Direct `EventData/Data` children remain an ordered list of name/value pairs. Repeated names and unnamed entries are preserved. Values undergo standard XML entity and line-ending normalization. Nested content inside a `Data` field causes the event to be skipped.
- `RenderingInfo/Message`, when present, supplies detail text, trimmed and limited to 400 Unicode code points, with `message_truncated` indicating clipping. Messages over the field byte limit cause the event to be rejected rather than partially parsed.
- `UserData`, binary/complex payloads and other unsupported event payload children set `payload_omitted`. Only the documented System and rendering fields are projected; execution, correlation, task, opcode, keywords, other rendered labels and unknown System fields are not interpreted. This parser validates its supported subset, **not the full Microsoft XSD**.
- Each event identifies the evidence object, source path, one-based XML line and zero-based byte offset of its opening tag in the **original encoded bytes**, including BOM. UTF-16 offsets account for surrogate pairs. For the existing timeline JSON schema, omitted `byte_offset` means zero. Record IDs are source metadata, not evidence identifiers.

Full report values are HTML escaped and CSV formula prefixes are protected. Literal rules scan decoded XML lines, including unsupported or malformed XML if decoding succeeded; they do not scan a provider-interpreted field model. Rule matches and structured event acceptance are separate results.

## Bounds and partial results

The analyzer's text budget is 8 MiB per source file and 128 MiB total. XML also shares the existing 50,000 log/capture budget. Counted XML records consume that budget even if semantically rejected.

Per-file limits are 20,000 event records and 250,000 XML tokens. Each event is bounded to 256 KiB decoded bytes, depth 32 and 2,048 elements. Each element permits 32 attributes; text and attribute values permit 4,096 UTF-8 bytes each. At most 64 Data entries are retained per event, with names up to 256 bytes. Namespace declarations count as attributes. Whitespace stored inside an element counts toward its text limit.

A semantic field failure skips that event and permits later events to be examined. Malformed XML, unsupported structure/directives or a structural resource bound stop that file. Previously completed events remain available. `parse_summaries` reports rows, parsed/skipped counts, `skip_reasons`, a stop error and the limit flag. An incomplete counted event contributes one skip. Files rejected before event discovery may have an error with zero rows. The HTML summary exposes the reasons; a partially parsed file is not evidence of complete coverage.

## Sharing and compatibility

The separately typed shared report preserves event types and aggregate parser counts, applies existing host/user/path/time policies, and omits **all Windows-specific context**, Data fields, messages and raw parser errors. Even explicit keep policies do not copy that context. Sharing does not guarantee anonymity.

Evidence schemas v1/v2 remain readable. Checkpoints and review histories are still bound to their producing version: finish existing work directories using the original binary, and retain old signed reviews with their original analysis. Create a new 0.14.0 analysis for new review work. Historical packaged 0.9.0 example reports are unchanged.

## Validation and primary references

Go regression tests cover encodings and declaration mismatches, CRLF and multibyte byte positions, namespace aliases, ordered/omitted payloads, numeric/time ambiguity, malicious XML, partial recovery and resource bounds. A dedicated fuzz target checks count/provenance invariants. `scripts/windows_xml_integration.py` uses Python's independent XML parser on fixed synthetic fixtures, then checks the CLI's metadata, correlations, exports, all shared artifacts and unchanged evidence hashes. See [TEST_REPORT.md](TEST_REPORT.md) for actual environments and retained results.

- [Microsoft Event schema](https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-eventtype-complextype)
- [System properties and numeric/time field definitions](https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-systempropertiestype-complextype)
- [EventData structure](https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-eventdatatype-complextype)
- [wevtutil query/output options](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil)
