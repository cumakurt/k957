# Examination workflows in 0.15.0

This developer preview adds bounded examination capabilities to the existing signed logical acquisition workflow. [IMPLEMENTATION_PROGRESS.md](IMPLEMENTATION_PROGRESS.md) records the remaining work. All explicit output paths must be new. Use `k957 <command> -h` for current flags.

## Acquisition guarantees and metadata

Ordinary collection records `logical-live-files`, original file bytes and descriptor-sampled metadata. Resumable collection records separate acquisition epochs. Neither method creates a filesystem snapshot or atomic multi-file acquisition. Linux metadata includes ownership, device/inode/link identifiers, access/change/birth times where available, extended attributes and raw POSIX ACL attributes. Darwin collects descriptor timestamps, ownership and xattrs but reports native ACL omission. Windows collects handle identifiers, timestamps and owner/group/DACL as SDDL; alternate-stream contents and SACL are explicitly omitted. Native Windows/macOS runtime checks are pending.

Metadata is bounded: 128 xattrs per object, 64 KiB name/value buffers and an 8 MiB aggregate attribute projection budget. Missing permissions and limits are partial outcomes. Filesystem identifiers do not prove physical-device separation. Snapshot/VSS adapters are not implemented.

Use a separate SQLite logical backup when transaction consistency is required:

```sh
k957 sqlite-acquire --in ./History --out ./history-backup.k957 --case CASE --operator Examiner --scope "Authorized browser history backup" --sign-key ./examiner.key
```

This uses SQLite's online backup API in a private worker and records `logical_backup` provenance. The source connection is read-only; SQLite locking/shared-memory mechanisms may be used. The backup is a derived consistent database. Acquire original database/WAL/journal files separately when raw bytes are needed. Acquisition of those live files does not guarantee matching transaction state.

## Native artifact support

Native workers copy signed, verified inputs into a private read-only staging directory. SHA-256 is checked before and after parsing. Inputs are capped at 128 MiB, worker output at 32 MiB and wall time at 30 seconds. Linux additionally denies network/exec/ptrace using seccomp and limits CPU time. The Go memory target is soft, and filesystem access is not fully sandboxed. Non-Linux workers have process isolation and time/output limits without an equivalent OS sandbox. Unix cancellation terminates the child process group; other platforms terminate the direct child.

Supported projections:

- SQLite: selected Chromium/Firefox/Safari visit schemas, read-only SQL, selected WAL/journal sidecars, original numeric times, explicit time encodings and table/row IDs. Unrecognized schemas are unsupported. Per-query row limits include invalid records; a lookahead row marks truncation even when no valid events were emitted. A limited scan never establishes the full database record count.
- EVTX: file/chunk/record extents and CRC validation, binary XML system metadata and bounded data fields. Record IDs, exact header FILETIME and byte offsets are retained. Provider message DLLs are not loaded.
- Registry: clean primary REGF 1.3–1.6 hives, allocated NK tree, RI/LI/LF/LH indexes, last-write FILETIME and selected VK values. Root/key and value cell offsets are retained. Supported values include bounded raw data, UTF-16 string, DWORD and QWORD projections. Dirty hives, transaction-log replay, deleted cells, large segmented data and volatile subkey trees are unsupported or explicitly omitted. Last-write time does not establish value creation or execution.
- Binary launchd plist: bounded `bplist00` root dictionary with Label, Program, ProgramArguments, UserName, RunAtLoad and Disabled. Object references, cycles, nesting and expanded graph size are checked before general decoding. Other properties are counted as omitted. File metadata time does not prove execution.

MFT, USN v4/live journal acquisition, binary journal/unified logs, Amcache/SRUM/TCC interpretation, compressed Prefetch and complete systemd drop-in semantics remain pending. Existing text/XML task, launchd, systemd and selected Prefetch header readers remain available.

The independent integration compares SQLite against Python sqlite3, a public EVTX record against python-evtx 0.8.1, generated plist bytes against plistlib and a generated clean hive against python-registry 1.3.1. This narrow corpus does not establish broad OS/version accuracy. Test dependencies are in `scripts/requirements-test.txt`.

## Unified case index and examiner interface

```sh
k957 case --store ./output --out ./case-dossier --rules ./examples/event-rules.json
k957 case-query --case ./case-dossier --kind event --text "example" --limit 100
k957 case-serve --case ./case-dossier
```

Every collection is verified before analysis. The verified record and signer bytes are retained for that examination; later record/key path changes cannot replace their metadata. The package is staged against its signed archive SHA-256 into a private read-only copy before opening. This adds archive I/O and requires archive-size free staging space plus a 64 MiB reserve (archive ceiling 1 TiB). Default RAM scanning uses one read-only descriptor and hashes the exact consumed stream, accepting results only against the signed image SHA-256; it creates no image-sized temporary copy. External Volatility examination still stages its own private image copy. Progress byte estimates do not measure all temporary-copy I/O. A rebuildable `case-index.sqlite` combines events, findings, reviews, activity, symbol-free memory observations, acquisition boundaries and inventory. A local evidence ID is scoped by signed collection digest. Explicit `case --review <ledger>` inputs are validated against freshly computed findings; `--review-key` supplies independent signer trust. External collection RAM is authenticated against its signed artifact SHA-256 during the in-process scan.

`examination.csv` streams indexed examination rows. The index has a one-million-row and 2 GiB ceiling. Query pages are limited to 200 rows, offset to one million and execution to five seconds. Search is a literal substring, not FTS. Coverage reports observed totals, omissions and whether a total is known. Analysis timeline/findings/correlation CSV files now write directly to disk, but analysis JSON, legacy case inventory and several other exports still retain arrays in memory.

The viewer binds only `127.0.0.1`, uses a random token, validates Host/Origin/method and renders evidence fields using text nodes. It is a single-examiner read-only interface. Roles, multi-user authentication, collaborative updates and a full accessibility audit are not implemented.

Save a signed investigation note and explicitly covered query page:

```sh
k957 case-bookmark --case ./case-dossier --out ./selected-records --title "Review notes" --analyst Examiner --note "Reason for this selection" --kind event --text example --limit 100 --sign-key ./examiner.key
k957 report-verify --report ./selected-records --trusted-key ./examiner.pub
```

The bookmark binds the index hash and row references. A query page is not represented as the entire result set.

## Time and identity estimates

```sh
k957 case-correlate --case ./case-dossier --field user --window 5m --policy ./clock-policy.json --out ./temporal.json
```

Policy schema `k957-temporal-policy/1` contains `clocks` and `identities` arrays. Clock records use `collection_digest`, optional `source_host`, `offset_ns`, `uncertainty_ns` and `reference`. A positive offset means the source clock was ahead of UTC; the estimate is source time minus offset. Identity records use `collection_digest`, `field: "user"`, `original`, `identity` and `reason`. Same-named users are scoped by collection and host unless explicitly mapped. Host/IP matches are shared values, not identities. Unknown clock uncertainty remains unbounded.

Original timestamps are preserved. Candidate groups are bounded to 100,000 selected events, 20,000 entities, 2,000 disjoint groups and 200 references per group. They do not establish causality or exhaustively enumerate every overlapping window.

## Structured rules and evaluation

`examples/event-rules.json` demonstrates all/any conditions over approved typed fields. Operations include equality, contains with explicit case semantics, bounded RE2 regular expressions and IP CIDR membership. Literal, exact SHA-256 and event rules are mutually exclusive within one rule. Event matches retain source/record references and per-rule counters.

```sh
k957 rules-evaluate --rules ./examples/event-rules.json --corpus ./labelled-events.json --out ./rule-results.json
```

Corpus schema `k957-rule-corpus/1` has `name`, `events` (Event projections) and `positive` entries with `rule` and zero-based `event_index`. Every unlisted event/rule pair is negative under this closed-world contract. The result binds decoded corpus/rule hashes and reports TP/FP/FN/TN, precision and recall; undefined ratios are omitted. Synthetic evaluation is not production accuracy. Temporal sequence rules and Sigma/YARA importers are pending.

## Network sessions and protocol metadata

PCAP/PCAPNG interpretation adds bounded bidirectional TCP session candidates, initial stream reconstruction, DNS queries/selected answers, first complete HTTP/1.0–1.1 headers and TLS ClientHello SNI/ALPN/advertised versions. Sessions remain scoped to capture/section/interface. SYN reuse, idle timeout, RST and both FINs define candidate boundaries. Packet references preserve exact capture offsets.

Reassembly caps are 64 KiB per stream, 256 segments per stream and 4 MiB per file. Gaps, conflicting overlap, ambiguous data after close, unsupported extensions and limits are explicit. Metadata is capped at 5,000 observations/4 MiB per file with 20 references per observation. Complete IPv4 header and TCP/UDP pseudoheader checksums are checked. `invalid_or_offloaded` accounts for capture offload and is not a malicious verdict. Authentication/cookie/body content is not projected. IP fragments, all application messages, TLS decryption, QUIC and live capture are not implemented. Raw capture bytes remain in the original evidence.

## Native documents and report authentication

```sh
k957 report-documents --analysis ./report/analysis.json --out ./documents --format both
k957 report-seal --report ./documents --key ./examiner.key
k957 report-verify --report ./documents --trusted-key ./examiner.pub
```

HTML and native PDF are generated by default for analysis, sharing, case and bookmarked records. DOCX remains explicit. See [reporting](REPORTING.md). PDF and DOCX use one bounded reading projection: 500 findings, 500 timeline events, 200 notes, 400 acquisition/collection issues and 200 coverage records; text is capped at 16 KiB per paragraph and 1 MiB total. `documents.json` states omissions. Full `analysis.json` remains in the document bundle. The embedded Unicode font has a retained license. Unsupported PDF glyphs become recorded visible code-point escapes; original text is preserved in HTML/JSON and DOCX.

`report.seal.json` lists every bundle file's name, byte size and SHA-256 with source bindings. Raw `report.seal.sig` is Ed25519 over `k957-report-seal/1` followed by NUL and the exact manifest bytes. Verification rejects unexpected, missing, modified, symlink and unsafe-path files. An embedded key verifies consistency; independently supplied `--trusted-key` establishes signer trust. Full and masked share projections have separate bindings; masked seals do not expose the hidden full evidence digest. Seals do not certify conclusions or provide trusted time.

## Custody key lifecycle and independent head retention

An external `k957-custody-trust/1` may include `lifecycle` policies alongside actor/key identities. Each policy specifies `public_key`, optional `valid_from`, `valid_until`, `revoked_at`, `revocation_mode` (`from_time` or `all_history`) and revocation reason. Historical validation uses the entry's declared recorded time. Newly appended events use the actual current clock. Rotation keeps old keys for historical checks and adds the new actor/key identity.

```sh
k957 custody-anchor --ledger ./custody.json --trust ./trust.json --sign-key ./witness.key --witness Witness --reference "External retention record" --out ./head-anchor.json
k957 custody-verify --in ./evidence.k957 --ledger ./custody.json --trust ./trust.json --anchor ./head-anchor.json --anchor-key ./witness.pub
```

The externally trusted witness signs the exact ledger head, length, evidence identity and trust-policy digest. Retain the current anchor independently from evidence and old revisions. Verification rejects a valid old ledger prefix when the current anchor is supplied. A compromised signer can backdate declarations; validity intervals are not a timestamp authority. Hardware signing, TSA and organizational key-management integration are pending.

## Disk-image examination and recovery

```sh
k957 disk-examine --image ./disk.raw --sha256 <expected-sha256> --tool /path/to/fls --out ./disk-list
k957 disk-recover --image ./disk.raw --sha256 <expected-sha256> --tool /path/to/icat --inode <listed-inode> --out ./recovered
```

These commands use examiner-selected Sleuth Kit binaries on a verified private raw-image copy, with image/sector/offset/inode provenance and tool hashes. A matching expected image digest is mandatory for recovery. Image size is capped at 8 GiB, listing at 32 MiB/100,000 entries, recovered file at 128 MiB and tool time at two minutes. This is image import/examination, not physical-device imaging. No carving, encrypted-volume unlocking or promised deleted-directory recursion. Generated ext2 deleted-file recovery was independently compared with debugfs and source bytes remained unchanged. Other filesystem/device accuracy remains unvalidated.

Successful receipts have `status: interpreted`. A completed failed tool invocation returns a nonzero exit code and retains `status: failed`, invocation/diagnostic hashes and `listing.partial.txt` or `recovered.partial.bin`. Failed recovery never publishes `recovered.bin` or a successful recovered-content hash. Source/hash/pre-invocation failures remove the newly created output directory. Failed receipts make no post-invocation staged-image integrity claim. These additive status/error fields require readers to check status before treating a disk receipt as successful.

## Offline external RAM enumeration

```sh
k957 memory-examine --image ./memory.lime --sha256 <expected-sha256> --tool /path/to/vol --symbols ./offline-symbols --plugin linux.pslist.PsList --out ./kernel-objects
```

The command stages the full image and JSON/compressed symbol bundle without automatic image/symbol/result/runtime ceilings, invokes the selected Volatility 3 plugin with `--offline --parallelism off`, and retains invocation/tool/symbol hashes, JSON object output and stderr. Missing symbols, incompatible layers and tool failure produce a failed receipt and nonzero exit status. They do not fall back to kernel-object claims based on strings. Tool executable hashes do not bind all interpreter modules; complete external-tool OS sandboxing is not asserted. A real Volatility 3 version 2.28.2 negative test passed, but no valid kernel-reference image was available to establish enumeration accuracy.

The default plugin is now `all`: discovered platform and global banner/YARA methods are attempted with advertised dump/thread options, retained failures and unavailable-module records. Use `--work-dir` or `K957_MEMORY_WORK_DIR` for staging. Automatic store/package/case kernel examination uses `K957_VOLATILITY` and `K957_MEMORY_SYMBOLS`. See [memory](MEMORY.md).

## Offline CloudTrail exports

```sh
k957 source-import --kind cloudtrail --in ./selected-cloudtrail --out ./cloudtrail.k957 --case CASE --operator Examiner --scope "Authorized offline export" --sign-key ./examiner.key
k957 analyze --in ./cloudtrail.k957 --out ./cloudtrail-report --rules ./examples/event-rules.json
```

Selected `.json`/`.json.gz` exports retain original bytes and an import receipt with hashes, parsed counts and unknown provider completeness. Limits: 100 files, 8 MiB raw/decompressed per file, 128 MiB total. The bounded major-version-1 projection includes event ID/time/source/name, selected account/region/identity/source-IP/error fields and native record ordinals. Request/response objects are retained as evidence and are not interpreted. This adapter does not access AWS APIs, validate CloudTrail digest chains or establish export completeness. Literal byte rules do not scan these provider objects; structured event rules may use supported CloudTrail fields. Mobile/VM/container/cloud live acquisition adapters remain pending.

## Evidence-grounded local assistant

```sh
k957 case-assistant --case ./case-dossier --endpoint http://127.0.0.1:11434 --model <cached-model:tag> --model-digest <expected-model-sha256> --question "Select records relevant to this review" --kind event --text example --limit 20 --out ./assistant.json
k957 assistant-review --in ./assistant.json --case ./case-dossier --out ./assistant-decision --analyst Examiner --decision accept --note "Reviewed each cited field" --sign-key ./examiner.key
```

The client uses only an explicit literal loopback IP, disables proxies/redirects, requires an already cached Ollama model and checks its reported digest before/after inference. No model download is attempted. The model sees at most 20 bounded scalar row projections and no arbitrary source objects. Accepted observations must quote an exact whole supplied field and row ID. Invented citations, altered quotations and tool calls are rejected. Suggestions remain unverified and pending examiner approval. A signed decision separately binds the original index/model/source projection; stale index or changed citations fail approval. Source evidence, automatic findings and review ledgers are unchanged.

Loopback transport does not attest that the independently installed daemon cannot forward data. Configure and inspect the runtime separately for offline use. Actual local Ollama 0.33.3 inference with cached `qwen2.5:0.5b` was exercised on three synthetic scalar-quotation tasks, including Unicode and an instruction embedded in a source field. The current retained run passed all three citation contracts and requested-field tasks, signed examiner review and unchanged-index checks. An earlier run selected a valid source quotation from the wrong field on the injection task; that task-quality failure is retained. Exact citation validation does not establish question understanding or forensic reasoning quality. Cloud features were disabled by runtime configuration; complete OS egress isolation was not attested. See [model setup](validation/0.15.0/local-model-preparation.json), [initial task miss](validation/0.15.0/model-initial-task-failure.log) and [current evaluation](validation/0.15.0/linux-amd64-final/assistant_model_integration.log).

`scripts/assistant_model_integration.py` runs only when `K957_ASSISTANT_ENDPOINT` and `K957_ASSISTANT_MODEL` explicitly identify a cached local runtime/model; otherwise it records an optional skip. Downloading the small model was explicit test preparation, separate from product inference. Protocol/citation failure fails the test; requested-field task misses remain visible as `task_quality_result: failed` even when citation checks pass. Release metadata preserves these separate measurements and keeps forensic-quality assurance false.

## Build, validation and migration

Go 1.26+ and pinned modules in `go.mod` are required to build. CGO remains disabled in distributed binaries. Original dependency notices are retained under `licenses/`, with [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md). Optional external tools and test-only Python dependencies are separately installed.

```sh
python3 scripts/release.py
python3 scripts/validate.py --out docs/validation/0.15.0/linux-amd64-final --binary dist/k957-linux-amd64 --expect-target linux-amd64
python3 scripts/release.py --no-build --validation docs/validation/0.15.0/linux-amd64-final/validation.json
python3 scripts/fuzz.py --out ./validation-fuzz --seconds 10
python3 scripts/fuzz.py --out ./validation-registry --seconds 60 --target FuzzRegistry
k957 build-info
```

`SOURCE.json` fingerprints Go sources, core fonts/testdata and module inputs, including embedded assets and fixtures. Every released binary embeds that SHA-256. Validation checks the native target, executable source identity, hashes and unchanged source inputs. `RELEASE.json` lists native runtime receipts separately from cross compilation and signing status. Checksums are integrity metadata, not a publisher signature.

The fuzz runner uses two workers and limits each minimization attempt to one second; the default Go minimization budget was consuming most of the short campaigns. Original counterexamples still fail the target and remain reproducible even when minimization is bounded. Per-target counts and command lines are retained; aggregate execution counts do not establish equal format coverage.

Existing v1/v2 evidence packages remain readable. New optional metadata fields may be rejected by older strict readers. Retain the previous tool for previous review ledgers: analysis/review bases include analyzer version and findings, so regenerate analyses and create a new review basis for 0.15.0 rather than relabelling old ledgers. Historical receipts/example reports remain attributed to their original versions. Cross compilation does not replace native permission/device/cancellation validation.

Current execution record: Linux AMD64 passed 30 checks with 76.4% unit statement coverage, and six targets cross compiled. Nine fuzz targets passed 1084678 executions in the ten-second-per-target campaign, including Registry, binary plist and external JSON. Retained receipts carry exact source/executable hashes. The one-million-row benchmark measures derived-index behavior only. Source and test coverage are not a forensic accuracy certificate.

## Exported USN journal records

Offline USN v2/v3 record streams now use the isolated worker and flow into timeline, structured rules, full analysis JSON, usn.csv and native document references. See [format and limitations](USN_JOURNAL.md). The existing independent reference measurements above predate this parser; this addition has not received new runtime/reference validation.

Temporal candidate grouping excludes events without an absolute timestamp. Those events remain queryable in the original index; temporal coverage records `missing_absolute_time` and reports the count that actually entered timestamped buckets. Zero time is never converted into a fabricated candidate date.
