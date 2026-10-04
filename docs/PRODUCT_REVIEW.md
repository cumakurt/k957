# Product review and engineering improvements

Review date: 2026-09-30. Scope: the existing working tree of k957 0.14.0, including changes that were already present when the review began. This is a source and synthetic-fixture assessment. It is not a certification of forensic accuracy on native Windows, macOS or physical devices.

## Product assessment

k957 is a functioning offline triage CLI with a useful evidence lifecycle: acquire bounded logical files, verify their bytes, interpret selected formats, retain evidence references, record analyst decisions and export reports. The strongest areas are bounded acquisition, SHA-256 integrity checking, optional Ed25519 authentication, resumable encrypted staging, independent interoperability checks and a separate allowlisted sharing projection. The weakest areas are native artifact depth, analysis completeness reporting, large-case storage and platform validation.

The code has no external Go dependencies. CLI concerns live in `cmd/k957`; acquisition, verification, parsers, review ledgers and reporting live in `internal/core`. Platform-specific behavior uses Go build constraints. This keeps deployment simple. The core package has grown to include many different responsibilities, and large orchestration functions make shared budgets and error handling harder to maintain. Focused helpers for finding admission and context-aware verification were added without replacing the architecture.

### Collection and data quality

Logical acquisition enforces file, byte and time limits; writes new outputs exclusively; records partial scope and read failures; avoids ordinary source symlinks; and compares source metadata around reads. Resumable acquisition freezes the inventory and preserves per-part hashes and acquisition epochs. Preflight estimates capacity without reserving space. Full collection gathers platform profiles, live snapshots and memory when supported.

Source identity after single-pass acquisition now includes `os.SameFile`, closing a gap where a replacement file with the same size and modification time could go unreported. This improves change detection; it does not produce an atomic snapshot. Native snapshots, extended attributes, ACLs, Windows alternate streams, disk imaging and physical power-loss validation remain separate work.

### Verification and trust

Archive verification checks listed objects, sizes, hashes, signatures and resumable part metadata. Full-mode verification additionally checks collection records, artifacts, checksum lists and memory structure. Embedded-key verification establishes internal consistency; externally supplied trusted keys are required for an external trust anchor.

Manifest, collection, rule and hash-set JSON now reuse the existing strict decoder: duplicate keys, noncanonical keys, unknown fields, invalid UTF-8 and excessive nesting are rejected. Collection evidence references must name a regular file inside the collection; artifact and memory checks reject symlink files. A failed collection signature is no longer overwritten with a success description when no external key is supplied.

These checks do not provide a hardened sandbox against an adversary concurrently modifying parent directories. Collection storage should be immutable during examination. Parser process isolation and verified file-handle reuse across all verification and analysis steps remain architectural work.

### Analysis and interpretation

Supported interpretation includes UTF-8 text, CSV, JSONL, exported Windows event XML, bounded PCAP/PCAPNG headers and directional flows, selected persistence formats, activity heuristics, magic-byte hints, exact SHA-256 lists and literal memory scanning. Evidence identifiers, source locations and original timestamps make derived rows traceable.

The 10,000-finding cap previously stopped the entire item loop, causing later inventory, file classification and timeline rows to disappear. Finding admission now records truncation while remaining supported analysis continues. Prefetch extraction now consumes the shared 50,000-event budget. Unsupported binary/text objects and text budget omissions receive explicit per-object parse summaries.

Systemd interpretation now limits directives to `[Service]`, applies the final `User=` regardless of its position, honors empty command assignments that reset earlier commands and records the source line. Task Scheduler and launchd values now preserve XML token fragments, including CDATA and entity boundaries. Scheduled-task recognition requires the expected root and namespace; both persistence XML readers enforce depth limits.

Cancellation now propagates through package hashing, object reads, packaged memory reads and store examination. Canceled analyses are marked and cannot be exported or shared as ordinary completed reports. Existing immediate Ctrl+C behavior remains a CLI process-exit mechanism.

These remain bounded triage interpretations. Native EVTX, Registry, MFT/USN, SQLite/WAL, journal and unified-log parsing are absent. Memory string and executable-header observations are not reconstructed kernel processes or sockets. Correlations join common field values across evidence objects; they do not resolve identities, compensate clock skew, reconstruct sessions or establish causality. Systemd drop-in merging and complete runtime configuration semantics are not implemented.

### Reporting and analyst workflow

Reports provide HTML, JSON, CSV, a bodyfile, inventory, findings, timeline, network, activity and persistence outputs. HTML output escapes evidence text; CSV cells protect against spreadsheet formulas. Shared reports project allowed fields separately, omit free text and maintain aliases.

New report behavior exposes finding truncation in both full and shared outputs, per-object parse limits/errors/skips in full HTML, PCAPNG section/interface provenance and capture omissions. Hash-set metadata records the supplied file SHA-256, entry count, total matching object count and detail truncation. A used set with no matches is distinguished from an absent set. Hash-set findings are generated before review-ledger decisions are applied, so those findings can be reviewed on reanalysis.

Case timeline sorting now compares actual timestamps, preventing RFC3339Nano lexical ordering from reversing whole-second and fractional-second events. Native PDF/DOCX generation, a durable search index, browser-scale pagination for all large sections, report signatures and complete case-output truncation metadata remain development areas.

## Implemented fixes and regression evidence

The new suites are `internal/core/quality_regression_test.go` and `cmd/k957/hashset_review_test.go`, with twelve regression tests covering:

1. Finding-cap behavior preserves later evidence and warns in full/shared reports.
2. Canceled analysis and verification cannot publish a normal report.
3. Duplicate manifest fields and ambiguous rule inputs are rejected.
4. Systemd user, section and command-reset semantics preserve source lines.
5. Used hash sets with no matches and omitted known-bad findings are reported.
6. External evidence paths and symlink artifacts are rejected.
7. Unsupported object coverage is visible in HTML.
8. Fragmented XML values are preserved and unrelated task XML is rejected.
9. Whole and fractional seconds sort chronologically in case CSV.
10. Failed collection signatures retain a failed description.
11. PCAPNG context and parser errors render successfully.
12. Hash-set findings retain analyst decisions after reanalysis.

Three cases were also run against a separate copy of the pre-change source: duplicate manifests, systemd interpretation and external collection references. All three reproduced the original problems. Integration assertions were updated to the documented English full-report language and the newly explicit unparsed EVTX coverage; the corresponding parsing, masking and unchanged-evidence checks remain present.

## Validation and reproducibility

The repository validation workflow is `scripts/validate.py`. The initial review receipt and individual command logs are at `/tmp/k957-review-validation-complete/`; the tested executable is `/tmp/k957-review-build/k957`. The workflow passed all 21 recorded steps: formatting, vet, unit tests with coverage, the race detector, a native build, all twelve CLI integration scripts, independent cryptography interoperability, and tool/version checks. The retained machine-readable receipt is [product-review-linux-amd64.json](validation/product-review-linux-amd64.json). Aggregate statement coverage was 86.2%. CLI coverage was 86.5%; core coverage was 86.2%. Coverage is a test-execution measure, not a forensic accuracy measure. The second audit below records the latest validation.

Linux, Windows and macOS builds for AMD64 and ARM64 all succeeded with CGO disabled. All six artifacts passed `scripts/check_static.py`; these cross-platform builds are under `/tmp/k957-review-platform-builds/`. Native execution in this review was Linux AMD64 only.

Temporary build products are separate from the existing release artifacts. This review does not publish a release or replace the existing release checksums. Test success does not establish real-device behavior or parser fidelity on every operating-system version.

## Second audit (2026-09-30)

The follow-up audit repeated the existing checks and examined collection trust, report identity, acquisition completeness, cancellation and ambiguous input. Passing tests had missed the following defects; focused regression fixtures reproduced them before the fixes:

1. **Full report trust was overstated.** Opening the logical package with the collection's `signing.pub` made its report claim verification against a supplied trusted key even when the caller supplied none. Full analysis now uses the collection verification result. Embedded-key consistency and an explicitly supplied external trust anchor have distinct descriptions.
2. **Full reports did not bind the complete acquisition.** Logical reports used the package manifest digest, omitting separately acquired RAM; memory-only reports used the signing-key fingerprint, which can be reused across collections. Full-mode `evidence_digest` now hashes the exact signed `collection.json` bytes, including the recorded artifact hashes. `package_digest` retains the logical package manifest digest when a package is present. Finding identifiers are recalculated from the full collection identity before memory and hash-set findings are admitted.
3. **Failed memory acquisition disappeared from report status.** A complete logical package could conceal a partial overall collection. Additive `collection_status` and `collection_issues` fields retain the signed collection outcome; full HTML and masked reports now expose that outcome and the combined issue count. The original package manifest remains intact.
4. **Malformed records could claim successful authentication.** Verification now starts with `not authenticated` and only reports successful signature verification after it actually occurs.
5. **Canceled cases could publish an output.** Case verification now uses the caller's context; cancellation after progress callbacks, the final collection and report writes returns an error and removes the partial case directory. Artifact hashing and memory reads also honor cancellation when no byte estimate is available.
6. **Review ledgers and resume checkpoints accepted duplicate JSON keys.** Both readers now use the same strict JSON decoder as the evidence lifecycle, rejecting duplicate/noncanonical keys, invalid UTF-8, unknown fields and excessive nesting.
7. **Task XML accepted commands from a foreign namespace.** Every element in a recognized Task Scheduler path now requires the expected namespace, preventing unrelated `Exec` and `Command` elements from creating persistence events.

The additional suite is `internal/core/recheck_test.go`, with seven test functions. Trust and digest tests cover logical and memory-only collections with and without a supplied key. The first five functions and the namespace fixture failed against their corresponding pre-fix implementations. The final unknown-size reader test also covers SHA-256, artifact hashing and memory scanning cancellation.

### Compatibility

Standalone package `evidence_digest` and finding identifiers are unchanged. Existing full collection reports remain readable, but new full analyses have a corrected evidence identity and therefore different finding IDs and review bases. Preserve historical reports and signed ledgers; create a fresh ledger for a newly generated full analysis. Do not rewrite signed historical IDs to force compatibility. The JSON fields added by this audit are optional for older records.

### Repeated validation

The final `scripts/validate.py` run passed all **21 steps**, including unit tests, the race detector, vet, formatting, all integration scripts and independent cryptography interoperability. Aggregate, CLI and core statement coverage were each **86.5%**. Logs are under `/tmp/k957-recheck-validation-final/`; the tested native executable is `/tmp/k957-recheck-build/k957`. The retained receipt is [product-recheck-linux-amd64.json](validation/product-recheck-linux-amd64.json).

All six existing fuzz targets passed a short campaign requesting five seconds per target with two workers: rules, encrypted envelopes, structured logs, PCAP, PCAPNG and Windows event XML. They recorded **799,168 executions** in total. This campaign preceded the final unknown-size cancellation adjustment; the parser implementations were unchanged by that adjustment. It is a bounded malformed-input check, not a proof of parser security. Logs are under `/tmp/k957-recheck-fuzz/`.

Final-source builds for Linux, Windows and macOS on AMD64 and ARM64 succeeded with CGO disabled, and all six passed `scripts/check_static.py`. Artifacts are under `/tmp/k957-recheck-platform-builds/`. Execution and integration validation were native **Linux AMD64 only**; Windows/macOS builds were cross-compiled. The retained [extra checks receipt](validation/product-recheck-extra.json) records artifact hashes, fuzz results and release-checksum findings.

### Distribution checks

All six existing `dist/` binaries match their entries in `SHA256SUMS.txt`. The same checksum list does **not** validate the current working tree: 21 listed source/documentation files differ, and new audit files are not listed. Existing distribution artifacts were not replaced by this audit. A new release must regenerate binaries and metadata together and run the release validation workflow; these source fixes are not present in the existing distributed binaries merely because their listed hashes match.

The untracked root `quick_start.sh` is a JumpServer installer, outside the k957 workflow. It was inspected, left untouched and not executed. The documented k957 launchers remain `start-unix.sh` and `start-windows.cmd`.

## Remaining development priorities and acceptance criteria

1. **Native artifact fidelity.** Start with a bounded SQLite/WAL and EVTX worker boundary. Acceptance requires independent reference outputs, supported-version fixtures, corrupt/truncated input tests, explicit unsupported states and resource limits. Avoid treating a collected native database as an analyzed database.
2. **Consistent acquisition.** Add snapshot acquisition, native metadata and physical-device identity through platform adapters. Acceptance requires source-change tests, real USB/power interruption recovery and Windows/macOS permission scenarios.
3. **Large-case storage.** Replace whole-analysis in-memory accumulation and repeated archive verification with immutable handles, bounded streaming and a case index. Measure peak memory, bytes read and latency before changing algorithms. Preserve evidence references and stable finding identities.
4. **Parser isolation.** Execute native parsers in workers with CPU/memory/time limits and explicit cancellation. Acceptance requires malformed-input campaigns, sandbox escape checks and visible partial outcomes.
5. **Case completeness.** Add structured coverage for every parser, observation and case grouping cap, including duplicate and mismatch caps. Propagate this into masked reports without revealing raw paths or parser errors.
6. **Platform release assurance.** Validate on native Windows/macOS and both architectures, compare memory/image fixtures with independent tools, and run the signed release workflow. Cross-compilation alone is insufficient.
7. **Examination experience.** Add case search, temporal correlation windows, clock uncertainty and reviewable relationship views; support native report documents only after traceability and omission reporting are preserved.

There is no claim that the remaining platform capabilities were implemented by this review. They require reference data, platform access and their own acceptance tests.
