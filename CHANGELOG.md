# Changelog

## 0.15.0 — developer preview

- Source-quality audit: refuse report seals containing the active signing key, hard links to it or exact key-file copies. Preserve the original key and leave no partial seal on rejection.
- Exclude untimed events from temporal candidate grouping and disclose missing absolute timestamps while retaining original indexed records.
- Route small-file writes through exclusive, synced failure cleanup. Stream shared CSV/HTML instead of retaining an additional serialized copy; preserve caller-owned CSV rows and propagate cancellation through shared JSON/CSV/HTML/PDF exports.

- Added exact native parser/record and USN file-ID filters to case queries, the local viewer and signed bookmarks. New indexes include native reference IDs in literal search. Related USN navigation retains collection/evidence scope; viewer requests cancel/discard stale results and paginate the last submitted filter set.

- Added source-scoped USN file record groups with complete emitted-record references and grouped JSON/CSV exports. HTML/PDF/DOCX show names, parents, reason flags and observed time bounds with explicit group/property omission counts; shared projections omit private groups.

- Added isolated offline USN v2/v3 examination, original file/parent identifiers and FILETIME/offset references, decoded reason flags, structured event rule fields and usn.csv. Unsupported/malformed records and projection limits are explicit; live USN acquisition, full-path reconstruction and native reference validation remain pending.

- Added a colored Bash build console with target progress, artifact sizes, durations, failure diagnostics, plain redirected output and final source-consistency checks.
- Extended signed adaptive acquisition to Linux executable file mappings and Windows loaded modules/DLLs. Retained virtual addresses, Linux mapping/device/inode references, Windows module metadata, observed paths and explicit failures; report summaries expose mapping coverage.

- Corrected little-endian LiME identification so renamed packaged memory images enter the memory pipeline. Removed the 4 MiB report-seal manifest ceiling while preserving version 1 signatures, strict JSON checks and per-file integrity verification. Manifest reads now check regular-file identity and support cancellation.

- Added default native PDF folios for analysis, masked sharing, cases and selected records, with embedded fonts, source/omission receipts, page totals and recorded glyph escapes. Redesigned HTML and corrected printing of paginated/filterable rows.
- Removed artificial memory image/range/result/tool runtime/output/symbol limits. Added complete hashed private string/URL/hit/observation JSONL, streaming full CSV, temporary/output filesystem staging, and discovery of all installed platform/global plugins with dump/thread options and failed/unavailable method receipts.
- Added signed adaptive process-executable acquisition, exact offline SHA-256/IP/domain indicators with native/packet references, documented review ordering, Timesketch JSONL, observed hash/IP lists and explicitly supplied ATT&CK rule mappings.
- Added independent report/IOC/portable-export and synthetic >8 GiB memory orchestration checks. Documented the remaining development and validation plan.

- Removed image-sized temporary staging from default store/case RAM scanning. One read-only descriptor supplies both the scanner and SHA-256; results require the signed image hash plus file identity/size/mtime checks. External tools retain private staging. Added zero-capacity/unavailable-temp, mutation, replacement and cancellation regressions and signed CLI integration.
- Labelled verification/analysis byte progress as read workload and mark failed batch operations as failed without forcing success checkmarks or 100%.

- Standardized wizard, CLI help, shared HTML/JSON notices, operational documentation and current synthetic examples on English. The root README_TR.md remains the sole localized document. Local assistant instructions require English investigation suggestions while preserving exact source quotations.

- Corrected the mismatch between the 100,000-object collection ceiling and the former 16 MiB manifest ceiling. Manifest generation/verification now share a 128 MiB bound and exact-byte-compatible per-entry encoding; checkpoint limits and preflight allowances were aligned.
- Streamed legacy case inventory/timeline/bodyfile exports using additive SQLite projection tables, preserving numeric nanosecond ordering, stable ties and CSV escaping independently of the examination index limit. Case HTML and examination CSV now use synced exclusive output with failed-file cleanup.
- Corrected piped case stdout to contain only its JSON summary; report navigation moved to stderr. Added regression checks and an explicit independently verified synthetic source/case load runner.

- Added native SQLite/WAL browser-history, EVTX, clean Registry and binary launchd plist workers with verified private inputs, process/time/output limits and Linux seccomp/CPU controls.
- Added explicit logical acquisition guarantees, separately identified SQLite online backups, bounded descriptor metadata and acquisition-epoch sampling. Full platform snapshots/ACL/ADS fidelity remain pending.
- Added verified collection-record/signer snapshots and private archive copies bound to signed artifact hashes, preventing later path replacement from supplying unverified metadata. These copies require additional temporary disk space and I/O.
- Added uniform stage coverage, immutable examination/hash checks, scoped case events/findings/reviews/activity/memory/boundary index, pagination and loopback read-only viewer.
- Added structured all/any typed event rules, labelled-corpus confusion metrics, examiner-supplied clock/identity policies, signed case bookmarks and covered subset exports.
- Added bounded TCP session candidates/reassembly, selected DNS/HTTP/TLS metadata and complete-packet checksums, with gap/overlap/offload semantics and packet provenance.
- Added native Unicode PDF/DOCX, checked JSON writes, streamed analysis CSV, and domain-separated report-bundle signatures with file/source bindings and full/shared disclosure separation.
- Added external offline Volatility enumeration, Sleuth Kit raw-image examination/inode recovery, and selected offline CloudTrail import with input/tool/provider scope provenance.
- Added failed disk-tool receipts with bounded, hashed diagnostic outputs and explicit partial-file names; canceled/failed recovery never publishes a successful recovered file. Pre-invocation/hash failures still remove new output directories.
- Added a loopback cached-model assistant accepting exact cited field quotations, with separate signed examiner decisions. Actual local inference passed three synthetic quotation tasks in the current retained run; an earlier wrong-field task miss is retained. Citation validity, requested-task quality and forensic assurance are recorded separately.
- Added custody key validity/revocation policy and externally trusted witness head anchors. Trusted timestamping/hardware signing remain pending.
- Added source fingerprints, build-info, pinned dependency notices and coherent six-target build/release/checksum generation. Native execution remains Linux AMD64; cross compilation is not device assurance.
- Fixed PDF mid-word wrapping, Windows C-runtime DLL suffix checks and a stale CLI error test that accidentally invoked live full acquisition. Expanded independent artifact/document/tool comparisons and measured one-million-row derived-index behavior.
- Disclosed unsupported known string properties in binary launchd projections. Added native Registry/binary plist and external JSON fuzz targets, and retained incremental fuzz diagnostics on command failure/timeout.
- Fixed SQLite query-limit coverage when invalid rows produce no events: the lookahead now marks truncation, including skipped records. Added a regression that failed before the fix.
- Evidence schemas v1/v2 remain readable. Older strict readers may reject new optional metadata; old checkpoint/review bases must be used with their producing analyzer version. Regenerate analysis/review bases for 0.15.0.
- See docs/EXAMINATION_WORKFLOWS.md and docs/IMPLEMENTATION_PROGRESS.md for precise implemented scope, current validation and outstanding work. The eighteen-area plan is not fully complete.

## 0.14.0

- Relicensed under the GNU Affero General Public License v3 or later. See `LICENSE`.
- Full-mode collection records now include `collector_sha256`, the SHA-256 of the executable that wrote them. The collection signature covers that field.
- Analysis identifies file signatures from the first 560 bytes and writes `filetypes.csv`. An extension that disagrees with the signature is recorded, not turned into a finding by itself.
- `analyze` and `share` accept `--hash-set`. `known-bad` SHA-256 values become unreviewed findings. `known-good` values are recorded and are not findings.
- Analysis writes a Sleuth Kit `bodyfile.txt`. Only mtime is populated.
- Added `k957 case`, which verifies every collection in a store and writes a derived dossier: inventory, cross-collection duplicate hashes, hash-set matches, signature mismatches, a bodyfile and an HTML brief. The dossier is not a new evidence package.
- Collection records from 0.13.0 still verify. Resume checkpoints remain bound to the version that created them.
- Evidence schemas v1/v2 remain readable. Physical disk imaging, native EVTX/registry/MFT parsing and in-process kernel reconstruction remain unimplemented. See `docs/CASE.md`.
- Expanded Linux, Windows and macOS triage profiles: persistence locations, registry hives other than the password databases, Amcache, SRUM, Prefetch, browser history files, macOS quarantine/TCC/Safari history, and package metadata. Password hashes and browser credential stores are not collected.
- Live snapshots add Linux logins, timers and package lists; Windows firewall, Winlogon, Sysmon, Defender, Terminal Services and BITS event XML; macOS kernel extensions, SIP, packages and a 30-minute unified log extract.
- Analysis extracts scheduled-task commands, launchd program arguments, systemd ExecStart lines and Prefetch executable names into `persistence.csv`. See `docs/ARTIFACTS.md`.
- Analysis interprets collected host evidence into `activity.csv`: SSH, sudo, cron, account creation, shell and PowerShell history, and Windows logon, process, service, task, account and PowerShell events.
- `collect`, `preflight`, `verify`, `analyze`, `case` and `share` write a live stderr summary: phase, current item, percent when the work quantity is known, and an estimated remaining time. The summary is not stored as evidence.
- Ctrl+C stops the process immediately from any command or phase and exits 130. The in-progress operation is not finished.
- A terminal full `collect` prints a grouped summary instead of the collection record. The complete record remains `collection.json`. Piped stdout still receives JSON.
- Terminal `verify`, `analyze` and `case` print a grouped summary of counts and per-collection status. Failed collections show a short reason. Piped stdout still receives JSON.
- Memory analysis folds ASCII case without `bytes.ToLower`. Invalid UTF-8 in an image used to expand that copy, and an index into it could panic the scan.
- `verify` reports bytes read. A single collection no longer shows 100% before its files are hashed.
- `analyze` reports the same byte progress through verification and the memory scan. A single collection no longer shows 100% before that work starts.
- `analyze` writes an English examination report: a brief, grouped literal-match samples, and browser pages for findings and inventory. The full timeline stays in `timeline.csv`. At that historical release, the masked shared report retained its original locale; it is English in 0.15.0.
- A memory banner match is kept only when `linux version` is followed by a digit. Collector notes that contain those words no longer hide a later version line.
- Memory analysis no longer depends on Volatility for triage. A stream of the image records ELF, PE and Mach-O headers, passwd-style accounts, `/proc/net` text rows, module `vermagic` strings, NUL-separated command lines, selected environment keys, and PEM headers in `memory-observations.csv`. Password hashes, secret values, and private-key bodies are omitted. These rows are presence in the image, not a kernel task or socket walk.

## 0.13.0

- Added zero-argument full mode: `collect` acquires physical memory, live system snapshots and the OS artifact profile; `verify` and `analyze` cover every `output/<hostname>/<UTC timestamp>/` collection.
- Added a signed `k957-collection/1` record, `signing.pub`, and a coreutils-compatible `SHA256SUMS` list. A generated signing key is discarded after use; its fingerprint is printed.
- Added Linux LiME v1 memory acquisition from `/proc/iomem` and `/proc/kcore`, plus an external-tool path for Windows and macOS. Images carry SHA-256, SHA-1 and MD5.
- Added streaming LiME/raw analysis: literal ASCII and UTF-16LE rules, kernel banner, URL indicators, zero-page counts and Volatility 3 command lines. Reports add `memory.csv` and `memory-hits.csv`.
- Store analysis uses a built-in literal triage rule set when `--rules` is omitted and writes every supported report plus a masked shared report.
- A source read error now keeps the readable prefix instead of discarding the collection. Oversized snapshot files keep their prefix. `help` reports the current version and `-h` exits 0.
- Live command snapshots now stop at 4 MiB. The previous cap was bypassed because `io.Copy` used `bytes.Buffer.ReadFrom`.
- Evidence schemas v1/v2 remain readable. In-process process-list reconstruction, macOS native RAM capture and physical disk imaging remain unimplemented. See `docs/MEMORY.md`.

## 0.12.0

- Added bounded Windows event XML export analysis for UTF-8 and BOM-marked UTF-16 LE/BE, including event fragments and Events wrappers.
- Retained provider/event/record identifiers, explicit-zone timestamps, host/SID fields, ordered EventData values and original encoded byte provenance.
- Added per-record skip reasons, partial-prefix recovery, strict numeric/time validation and XML resource bounds; external resources and DTDs are rejected.
- Added Windows event JSON/CSV/HTML reporting with escaping, omission flags and existing host/SID correlations.
- Kept Windows-specific metadata/messages/data out of shared reports, including explicit keep policies.
- Added independent XML/CLI integration, malformed-input fuzzing and regression coverage. Binary EVTX parsing remains unimplemented; see `docs/WINDOWS_EVENT_XML.md`.
- Evidence schemas remain readable; older checkpoints/reviews still require their producing version.

## 0.11.0

- Added read-only `preflight --resume` planning from a frozen checkpoint, including authenticated encrypted checkpoints with the original key.
- Added `collect --resume --check-space`, retaining the collector's source-prefix and chunk integrity verification.
- Reported saved logical bytes, remaining bytes/parts and completed files; staging estimates exclude already recorded bytes while budgeting the final package in full.
- Accounted separately for existing work/chunk mount points, combining shared filesystem needs and applying one reserve per target filesystem.
- Blocked locked work, mismatched options, unavailable/wrong-size chunks, changed incomplete source metadata and exhausted acquisition epochs.
- Extended independent plain/encrypted process-termination tests and completed-work reuse checks; corrected test capacity probes for symlinked temporary directory roots.
- Checkpoint/review version binding remains unchanged. Finish older work with its original binary; earlier evidence schemas remain readable. See `docs/RESUME_PREFLIGHT.md`.

## 0.10.1

- Fixed unchanged Windows source files being skipped: source identity checks now use `os.Lstat` metadata instead of directory enumeration metadata.
- Windows checkpoint replacement retries brief sharing/access conflicts for up to one second. Persistent failures return an error and preserve the previous checkpoint.
- Added collection coverage for Unicode/nested/empty files and checkpoint reader conflicts, including preservation after failed replacement.
- All 11 independent integration scripts select the native executable, use explicit UTF-8 and support Windows process termination and capacity checks.
- Added one validation command with per-step logs, environment identification and a JSON receipt, plus a six-target GitHub Actions workflow.
- Evidence v1/v2 remains readable. Existing checkpoints and signed reviews remain version-bound; use the original producing binary for earlier work directories. See `docs/PLATFORM_TESTING.md` for compatibility and actual execution status.

## 0.10.0

- Bounded PCAPNG section/interface/enhanced-packet parsing with mixed byte orders.
- Per-interface decimal/binary timestamps, signed offsets and nanosecond flooring.
- Linux SLL/SLL2 headers in classic PCAP and PCAPNG.
- Separate flow groups and source references for each PCAPNG section/interface.
- Strict framing checks, packet skip reasons and ignored metadata block counts.
- Section/interface provenance and counters in full and masked HTML/JSON/CSV reports.
- Independent Python CLI integration and a dedicated malformed-input fuzz target.
- Evidence v1/v2 compatibility is preserved. Version-bound 0.9.0 checkpoints and review ledgers require the original binary; no migration is performed. See `docs/PCAPNG.md`.

## 0.9.0

- Classic PCAP v2.4 with four byte-order/time variants, Ethernet/raw IPv4/IPv6 TCP/UDP.
- Two VLAN tags and bounded IPv6 extensions; explicit fragment skips.
- Packet ordinal/byte references, nanosecond times, ports and TCP flags.
- Per-object directional flow summaries and size/count/limit reports.
- Shared packet/log IP correlations and full/masked HTML/JSON/CSV.
- Explicit unsupported PCAPNG/link metadata errors in this historical release; no payload interpretation.
- Independent Python fixture checks and a short 153,041-input fuzz campaign.

## 0.8.0

- Separate restricted-schema sharing HTML/JSON/CSV.
- Default case/user/host/IP/path/location aliases and omitted source times.
- Omitted free text, original identifiers/hashes/signatures and reverse mappings.
- Strict disclosure categories/literal policies and cross-field longer-match masking.
- Verified examiner/custody projections with leakage checks across every output.
- Six binaries, example sharing reports and operational documentation.

## 0.7.0

- Per-event Ed25519 custody signatures with register/transfer/accept/cancel/note.
- Pending transfer until recipient acceptance, external actor/key trust and identity checks.
- Manifest/case/package binding, previous head, sequence and time validation.
- Independently retained current heads reject older valid history.
- HTML/JSON/CSV history preserves original signatures in new revisions.
- Duplicate/ambiguous JSON rejection and independent Python signature/hash checks.

## 0.6.0

- Metadata-only JSON acquisition preflight and path/destination/file-limit checks.
- OS capacity queries, combined same-filesystem budgets, encrypted overhead and per-filesystem reserves.
- pass/warning/unknown/blocked outcomes; optional collection gating refuses insufficient/unknown capacity.
- Controlled capacity tests, native Linux integration and six updated binaries.

## 0.5.0

- AES-256-GCM checkpoint/chunk staging with purpose-separated keys, HMAC names and fresh nonces.
- Direct final ZIP encryption without a plaintext intermediate.
- Encrypted status/resume, wrong-key/mode/ciphertext rejection and summary stdout.
- Independent cryptography, output-failure and 192 MiB termination/recovery tests.

## 0.4.0

- Explicit UTF-8 CSV/JSONL event schema with multiline CSV, timezone conversion and original line/byte references.
- Parsed/skipped coverage, user/host/IP fields and cross-object shared-value references.
- Bounded entity/reference storage and correlation CSV.
- Invalid IPs, conflicting/duplicate fields and malformed records produce explicit skips/errors.
- Parser fuzzing and independent CLI integration.

## 0.3.0

- Reproducible finding IDs and version/evidence/rule/result-bound examiner reviews.
- Required examiner/reason, confirmed/rejected/needs-review decisions and retained prior history in new files.
- Optional Ed25519 signatures with previous-signature verification on extension.
- Evidence revalidation/reanalysis before applying reviews; HTML/JSON history and findings CSV.
- Tampered history, wrong basis/key and report-injection regression tests.

## 0.2.0

- Resumable 8 MiB logical-file chunks, checkpoints and frozen case/scope/inventory/limits.
- Completed chunk/file verification and acquired-source-prefix rereading.
- Writer locks, path separation and staging symlink/traversal rejection.
- Read-only work status/part verification, v2 part ranges/epochs and preserved v1 reading.
- HTML/JSON acquisition epochs and frozen-inventory limits.
- Process-termination recovery tests and six targets.

Encryption during acquisition, physical disk/RAM acquisition and cloud integration were outside this historical release.

## 0.1.0

Initial Go core: logical collection, optional system snapshots, SHA-256/Ed25519, encrypted transport, basic log/rule analysis and HTML/JSON/CSV reporting.

### Release readiness regression checks

- Correct Linux process mapping and document coverage test expectations without hiding unavailable acquisition outcomes or omitted document content.
- Add USN v2/v3, exact native case query and scoped grouping regressions, a synthetic collection/report/signed-selection integration and a Chromium request-ordering/navigation check.
- Retain a current native Linux validation receipt; other native target acceptance remains pending.

### Windows console rendering

- Detect Windows console handles with GetConsoleMode and enable processed output/virtual terminal processing before rendering ANSI progress or colors. Preserve existing console flags.
- Fall back to plain progress and uncolored summaries when VT setup fails or TERM=dumb. Apply the same capability check to Ctrl+C cursor restoration. NO_COLOR disables colors without disabling supported cursor control.
