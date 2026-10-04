# Source quality and logic audit — 2026-10-04

Current source: `9a6bc153e7f6ef5100e76fddd924293f51c473cb76bdd4a59d8c4e0373fbadd3`.

[Native Linux AMD64 validation](validation/0.15.0/linux-amd64-quality-audit-20261004/validation.json) passed **34 checks with two explicit optional skips**: no configured cached local assistant, and no configured real Volatility tool/reference-image check. Statement coverage is **75.6%**. The run includes uncached units, race detection, vet, source-bound native build, the million-row index benchmark, independent cryptographic/native-artifact/document checks, memory streaming/synthetic suite, custody/review/share/resume checks and a synthetic 2,000-object collection/case load. Existing physical-device and valid kernel-reference accuracy limits remain open.

The [pre-fix reproduction](validation/0.15.0/linux-amd64-quality-audit-20261004/pre-fix-regressions.log) runs new regressions against an isolated copy of the previous committed source. It deliberately fails on three signing-key inclusion variants (direct file, hard link and exact copy) and on false temporal grouping of untimed events. These same regressions pass on the corrected source. The new tests also cover cancellation, CSV formula escaping without caller-row mutation, failure cleanup and preservation of existing outputs.

Corrections:

- Report sealing rejects the active private-key file and its hard links before hashing those files, and rejects exact key-file copies before writing a seal. Rejection preserves the key and creates no partial seal. This prevents those specific accidental key-inclusion paths; it is not a general secret scanner for arbitrary report text or memory strings.
- Temporal grouping requires an absolute timestamp. Missing-time events remain in the case index; temporal coverage counts them as omitted and reports `missing_absolute_time`.
- Small new-file writes reuse exclusive, synced publication and failed-file cleanup. Shared CSV/HTML output streams directly; shared exports pass cancellation through JSON/CSV/HTML/PDF, preserve caller-owned rows and remove incomplete newly created bundles.

The first [sandbox attempt](validation/0.15.0/linux-amd64-quality-audit-20261004/sandbox-attempt/validation.json) failed units/race because `httptest` was denied a local TCP listening socket. The same complete validation passed after local socket access was authorized. That failed receipt is retained rather than represented as a passing run.

All six release targets also compiled and passed platform-library checks; see the [build log](validation/0.15.0/linux-amd64-quality-audit-20261004/six-target-build.log).

This revision has current native Linux AMD64 execution. Earlier Windows AMD64 results below remain bound to their older source, and do not certify these new changes on native Windows. Release status remains developer preview.

# Previous native Windows and developer-credit validation — 2026-10-04

Recorded source: `41535d7226d87ad2293d06c043aaec4401d33c81c078cfddea0de2252be4fdac`.

[Linux AMD64 validation](validation/0.15.0/linux-amd64-developer-20261004/validation.json) passed 33 checks with two explicit optional-tool/model skips; statement coverage is 75.6%. [Native Windows AMD64 validation](validation/0.15.0/windows-amd64-developer-20261004/validation.json) passed 29 checks with six explicit skips: five Go source checks delegated to the [native supplemental execution](validation/0.15.0/windows-amd64-developer-20261004/supplement/result.json), plus the unconfigured local assistant. All eight supplemental checks passed, including native build, vet, units, the million-row index benchmark and native execution of cross-compiled race binaries. Windows statement coverage is 74.1%.

Cuma Kurt's public developer name, email, repository and LinkedIn links are included in help/version, build-info, HTML and PDF/DOCX software credits. Independent PDF and DOCX extraction checks all four values; HTML and build-info have matching checks. Credits identify the software developer separately from the case operator/examiner. All six [release binaries](../RELEASE.json) bind the same source and passed library checks; the manifest now accepts multiple native platform receipts and retains both Linux/Windows source and executable bindings.

Native Windows found and corrected SQLite drive-URI serialization, asynchronous cancellation cleanup retaining SQLite handles, console VT capability detection, prebuilt fixture lookup and PDF reference-tool encoding. POSIX fixtures keep their original platform expectations; Windows sharing protection preserves evidence hash assertions. The latest Windows ANSI/OEM command-output normalization has native code-page regressions. The [earlier Console Host visual check](validation/0.15.0/windows-amd64-native-20261004/console-host.png) shows rendered colors/progress and no literal ANSI sequences against the earlier `014179...` source.

The [100,000-source-object receipt](validation/0.15.0/windows-amd64-scale-20261004/source-scale/scale.json) passed collection, independent signatures/hashes, package verification, CSV/bodyfile/index counts, chronology and duplicate checks against source `23b094...`, before developer credits were added. The surrounding full run retained one checkpoint-poll sharing error in the Python restart harness; it is not presented as a successful full run. The harness now retries Windows EACCES only while polling an active collector inside the existing 20-second deadline; persistent access denial still fails the interruption assertion, retaining the interruption, stale-lock and independent part/hash assertions. An earlier 600-second outer deadline also expired; the repeated load check used explicit longer harness deadlines. Initial portable-Python path mistakes were corrected before the retained source-bound final run.

Live Windows snapshots and event exports produced a declared partial collection on the earlier source: two optional Registry paths and the Sysmon channel were absent. Integrity verification and analysis succeeded; raw VM evidence remains in the task-owned guest directory and is excluded from release artifacts. Synthetic RAM tools and actual offline Volatility invalid-image handling do not establish valid Windows kernel-object accuracy or driver-backed RAM acquisition.

[Native Windows large-memory receipt](validation/0.15.0/windows-amd64-developer-20261004/large-memory-windows.json) passed an 8 GiB + 1 byte synthetic image, three plugin attempts including a declared failure, 100,002 rows, 39,400,789 output bytes, retained diagnostics and unchanged source SHA-256. Automatic tool timeout remained zero. This tests orchestration and staging; it does not validate kernel objects.

Windows ARM64, native macOS, physical RAM/device acquisition, USB/power interruption, enterprise controls and distribution signing remain unvalidated. The release remains a developer preview. Earlier sections below retain their original scope and source bindings.

# Windows console correction — 2026-10-02

Source: `cfb66fd7585e5c141faade76c87af685280ee382a61230835c584931ded0eabd`.

Windows progress previously assumed character-device output supported ANSI control sequences. The renderer now verifies a console handle and enables virtual terminal processing before emitting cursor/color commands. Failed setup and TERM=dumb use plain output; summaries and interrupt cursor restoration share the capability check.

This correction has no new runtime test receipt. Earlier Linux validation below applies only to its recorded source. Native Windows Console Host/Terminal visual acceptance remains pending; see [console acceptance](PLATFORM_TESTING.md#windows-console-acceptance). Cross-build results are retained in [the build log](validation/0.15.0/six-target-windows-console-build.log).

# Release readiness recheck — 2026-10-02

Source: `258dc1a8f2dd65f1c21d3b3c9a3ff7e74fe5ed855a82f0bf9a9e680e72f80aed`.

Fixed two outdated test assumptions: missing Linux process maps now produce explicit unavailable mapping references, and document omission assertions locate coverage by stage instead of row position. Added regressions for exact native case filters, invalid filters, scoped USN identities, USN v2/v3 decoding, record limits and truncated-input partial results.

The [native Linux receipt](validation/0.15.0/linux-amd64-release-readiness/validation.json) records **34 passed, zero failed, one skipped**. It includes uncached units, race detection, vet, the million-row case benchmark, native artifact references, RAM streaming/tool suites, report documents, cryptographic checks and a new synthetic USN acquisition-to-signed-selection integration. Statement coverage is **75.6%**. Cached local model integration was skipped because no runtime/model endpoint was configured.

A separate [Chromium check](validation/0.15.0/linux-amd64-release-readiness/case-viewer-browser.log) passed cancellation, stale-response rejection, submitted-filter pagination and source-scoped related navigation using synthetic responses. It does not establish accessibility or full browser compatibility.

Release status remains **developer preview**. Native Windows, macOS and ARM64 runtime acceptance, positive real-memory/symbol accuracy and physical-device scenarios remain open. No configured Git remote is available to dispatch the existing native-platform CI matrix. Passing Linux checks and cross compilation do not establish production readiness across all advertised targets. Original acquired evidence was not accessed or changed.

# Latest source status

Date: 2026-10-02. Source: `42049c6b6ff11131fa75fae2a49b64736ee57676472431fd4822f776dbdb8a39`. Added exact native parser/record and USN file-ID filters to CLI queries, the local viewer and signed bookmarks. New indexes include reference identifiers in literal search. Related USN navigation retains collection/evidence scope; new viewer searches cancel/discard stale responses, and pagination retains submitted filters.

All six targets compiled and passed platform-library checks; [build log](validation/0.15.0/six-target-native-case-search-build.log). No new tests were added or run. SQL runtime, browser interaction and bookmark acceptance for this addition remain pending. Earlier receipts remain source-bound historical measurements.

# Previous USN grouping source status

Date: 2026-10-02. Source: `dfc8f68fadcd33fd06502d9065e62a90e1d13a75db3cb59c8827cc14b267a2cf`. Added USN file record groups scoped by evidence/source/version/file ID, complete emitted-record references in `usn-files.json` and `usn-files.csv`, and HTML/PDF/DOCX group views with explicit group/name/parent omission coverage. No full path, rename pair or file lifetime is inferred.

All six targets compiled and passed platform-library checks; [build log](validation/0.15.0/six-target-usn-groups-build.log). No new tests were added or run. Runtime/reference and rendered-output acceptance for these additions remain pending; previous receipts remain bound to their original source.

# Previous adaptive/USN source status

Date: 2026-10-02. Current source: `85b25ecb2a3fa67b2c601a597c240274deab8f31927fdc16d0cdd7093d534bae`. The Bash builder now has terminal colors, target stages, artifact sizes, elapsed time, failure diagnostics and a final source-consistency check. Adaptive acquisition adds Linux executable file mappings and Windows Tool Help loaded modules; offline USN v2/v3 interpretation adds structured events, rule fields, native record references and `usn.csv`.

All six release targets compiled and passed their platform-library checks; see [final build log](validation/0.15.0/six-target-adaptive-usn-final-build.log). No new tests were added or run. Current runtime/reference acceptance remains pending, and `RELEASE.json` has no current native validation receipt. Earlier measurements below certify only their recorded source revisions.

# Previous LiME/seal source status

The subsequent LiME/seal correction has source fingerprint `4f19638a7535720a25f801679f1dbacf25578d080d71c397e5abeb547bf7d9eb`. It corrects renamed LiME image identification, removes the report-seal manifest size ceiling, checks manifest file identity and cleans up partial seal writes. Six-target compilation is recorded separately in [the build log](validation/0.15.0/six-target-lime-seal-build.log). No tests were run for this correction; all runtime measurements below remain bound to earlier source. `RELEASE.json` intentionally has no current native validation receipt.

# k957 0.15.0 collection, memory and reporting upgrade validation

Date: 2026-10-01. [Native Linux AMD64 receipt](validation/0.15.0/linux-amd64-report-memory-upgrade/validation.json): **35/35 checks passed**, source `265b94b0c47d619b6ffd67eb9b00b2c903f5bbb6b1ee4fe9f6e65be1c9610b50`. Formatting, vet, uncached units, race checks, source-bound build, release/library/language policy, all integrations, actual local-model quotation tasks and the 100,000-source-object check passed. Statement coverage is 76.3%. [Six-target build log](validation/0.15.0/six-target-report-memory-build.log) records cross compilation and platform-library checks; native runtime acceptance remains Linux AMD64.

The [large-image suite receipt](validation/0.15.0/linux-amd64-report-memory-upgrade/large-memory-suite.json) uses an 8,589,934,593-byte synthetic sparse source with a full private staged copy, 100,002 output rows, 39,400,789 bytes of JSON and diagnostics above 64 KiB. It checks unchanged source hashes, dump/thread options, all retained output hashes, partial failure and output-filesystem staging when `/tmp` is too small. This is orchestration/I/O assurance, not a real kernel accuracy test. The [actual Volatility suite negative check](validation/0.15.0/linux-amd64-report-memory-upgrade/real-memory-suite-negative.json) separately records installed plugin discovery and invalid-image/missing-symbol outcomes.

[Independent reporting/IOC integration](validation/0.15.0/linux-amd64-report-memory-upgrade/report_upgrade_integration.log) checks default native PDF/receipts, real SQLite browser row provenance, exact offline domain matches, explicit ATT&CK candidate counts, Timesketch fields, documented review ordering, masked PDF privacy and inclusion of default PDF in the signature contract. Full CSV/JSONL regressions retain matches/observations beyond former cutoffs; long ASCII/UTF-16LE strings and URL segments reconstruct across tiny input windows. Suite record/output mutation and unrecorded nested receipts are rejected. Signed adaptive process-executable acquisition has synthetic reference, scope-preservation and tamper checks; native Windows/macOS discovery remains unmeasured.

[Chromium visual/print receipt](validation/0.15.0/linux-amd64-report-memory-upgrade/visual-check.json) confirms all 60 finding/inventory rows are included for print after filtering, the prior filtered state is restored, there are no page script errors and a 390-pixel viewport has no document-wide horizontal overflow. The native PDF [cover](validation/0.15.0/linux-amd64-report-memory-upgrade/pdf-page-1.png), [body](validation/0.15.0/linux-amd64-report-memory-upgrade/pdf-page-4.png) and [HTML view](validation/0.15.0/linux-amd64-report-memory-upgrade/html-desktop.png) were visually inspected. This is a synthetic rendering check, not an accessibility or broad renderer audit.

The [initial full attempt](validation/0.15.0/linux-amd64-report-memory-upgrade-initial/validation.json) is retained: three old privacy harnesses attempted UTF-8 decoding of new binary PDF files. They now independently extract PDF text and retain their original assertions; focused and full repeats passed. Other preexisting work was preserved. Existing example evidence hashes remained unchanged while reports and synthetic signed histories were regenerated. The user's root-owned original memory collection was not read or modified.

[Open development scopes](DEVELOPMENT_PLAN.md) identify the remaining engineering work and external resources. Native operation on every target/device and positive kernel-reference accuracy are not claimed. Earlier measurements below remain historical and source-bound.

# k957 0.15.0 RAM streaming correction validation

Date: 2026-10-01. [Native Linux AMD64 receipt](validation/0.15.0/linux-amd64-memory-stream/validation.json): **33/33 checks passed** against source `3689c22ba7a6fa952970c2d5c402ff9fcb4ac58a6faecc45fb936f5be174115b`. Formatting, vet, uncached units, race detection, native source-bound build, language/release/library policies, all integrations and the explicit 100,000-source-object check passed. Current statement coverage is 76.6%; only Linux AMD64 has current native execution. [Six-target build log](validation/0.15.0/six-target-memory-stream-build.log) records cross compilation and static/platform-library checks.

Default collection/case RAM scanning now hashes the exact stream consumed by the in-process scanner through one read-only descriptor, with signed-hash and identity/size/mtime checks. It creates no image-sized temporary copy. The [new independent CLI integration](validation/0.15.0/linux-amd64-memory-stream/memory_stream_integration.log) exercises a synthetic signed external LiME image with an unavailable temporary directory, including store analysis and case export, exact original hashes and physical addresses. Zero reported staging capacity, wrong hashes, same-metadata modification, path replacement, empty/invalid inputs and cancellation have unit regressions. [The isolated prior-scanner regression](validation/0.15.0/memory-capacity-before.log) reproduces the reported `insufficient private staging space including 64 MiB reserve` error; the [passing regressions](validation/0.15.0/memory-stream-regression.log) supersede it. The earlier [initial regression log](validation/0.15.0/memory-stream-before.log) also records the old temporary-directory dependence and expectations for the new stricter source-path policy.

Verification/analysis progress labels repeated reads as `read workload`; failed batch operations display `failed` rather than completed success markers. External tools and package copies retain private staging. The user's root-owned 31.4 GiB image was neither read nor modified for these checks, and this report does not assert successful analysis of that particular image. Earlier validation sections retain their original source bindings.

# k957 0.15.0 English application validation

Date: 2026-10-01. [Native Linux AMD64 receipt](validation/0.15.0/linux-amd64-english-release/validation.json): **32/32 checks passed** against source `c672c9e826462e1a1e5a43fa50eda8da3d0b4ab3f7d51b7a8298091c1e575dc6`. Formatting, vet, uncached unit tests, race detection, source-bound build, language policy, release/library policies, all integrations, actual local-model inference and the independent 100,000-source-object run passed. Statement coverage is 76.4%. [Six-target build log](validation/0.15.0/six-target-english-release-build.log) records cross compilation and static/platform library checks; only Linux AMD64 has current native execution.

The wizard, shared-report labels/limitations, operational documents and synthetic reports are English. English prompt/report regressions and `scripts/check_language.py` guard the application text. Root `README_TR.md` remains Turkish. Original evidence bytes, arbitrary user content, dependency licenses and raw historical test receipts retain their original content; they are not translated as application labels. The synthetic network demonstration package was recollected with an English scope, and demonstration review/custody histories were freshly signed and verified with temporary keys. Four other compatibility packages retain their original hashes.

The [first attempt](validation/0.15.0/linux-amd64-english/validation.json) is retained as failed: general Go package enumeration encountered a protected generated `dist/output` directory, and the language check found the older synthetic network package's scope declaration. The runner now enumerates both source trees, and the example was regenerated. The final repeat passed every step. Real field/device/native Windows/macOS/ARM64 and browser accessibility assurance remains outside these results. Earlier results below remain historical and source-bound.

# k957 0.12.0 validation

Date: 2026-09-29. Native Linux AMD64 with Go 1.26.8 and Python 3.14.7; Windows AMD64 compatibility execution under Wine 10.0 with Windows Python 3.13.12. Independent cryptography checks use 49.0.0. No third-party Go modules were added.

- All 20 native validation steps passed: formatting, vet, uncached unit tests, coverage reporting, race detection, release build, version and 12 integrations. [Linux receipt and command logs](validation/0.12.0/linux-amd64/validation.json).
- Windows/Wine passed both Go test packages, version and all 12 integrations (15 executed steps). The prebuilt runner explicitly skipped formatting, vet, coverage, race detection and building; the applicable source checks ran on Linux. [Windows/Wine receipt and command logs](validation/0.12.0/windows-amd64-wine/validation.json). Wine emitted environment/process-termination diagnostics; the tests still completed with successful exits and independent content checks.
- New XML tests cover UTF-8/BOM and both UTF-16 byte orders, declarations, CRLF/surrogate-pair source byte positions, namespace prefixes, ordered duplicate Data names, 64-bit record IDs, UTC normalization, semantic skips, malformed-tail recovery, DTD/entity rejection and record/token/depth/node/text/attribute bounds. Exhausted timeline capacity preserves decoded text for independent literal rules.
- The new CLI integration compares fields against Python's XML parser on fixed synthetic fixtures, checks cross-evidence host/SID correlation and CSV/HTML escaping, scans all shared artifacts for private metadata/messages/data, and verifies unchanged evidence and source bytes. [Linux XML integration](validation/0.12.0/linux-amd64/windows_xml_integration.log), [Windows/Wine XML integration](validation/0.12.0/windows-amd64-wine/windows_xml_integration.log).
- The first Windows XML integration exposed a test-fixture error: Python text output translated LF to CRLF while the expected byte offset assumed LF. The fixture now writes explicit CRLF bytes and derives the expected offset from that byte prefix. Both complete platform suites passed after this correction. The [initial failure log](validation/0.12.0/windows-xml-fixture-before-fix.log) is retained; it is superseded by the passing final receipts.
- The final `FuzzWindowsXML` smoke campaign ran with two workers for approximately 16 seconds and executed 235,035 inputs without failure. [Fuzz log](validation/0.12.0/windows-xml-fuzz.log). This short campaign is not exhaustive validation.
- All six release executables built, with ELF, PE and Mach-O formats checked. Additional Windows AMD64/ARM64, Linux ARM64 and both macOS test packages compiled. Windows AMD64 tests then executed under Wine; the other cross-compiled test executables were not run. [Compilation log](validation/0.12.0/cross-compile.log), [binary formats](validation/0.12.0/build-formats.log).
- Both Go packages also passed with a symlinked Linux temporary directory, covering a macOS-like path canonicalization convention without claiming macOS execution. [Alias test log](validation/0.12.0/temporary-directory-alias.log).
- Linux statement coverage is 84.3% overall. Windows-specific source is outside this measurement. [Coverage report and retained profile](validation/0.12.0/linux-amd64/coverage.log).
- Legacy v1 and resumable v2 example evidence verified successfully with 0.12.0. Tested Linux and Windows AMD64 executable hashes match their release files and receipts. [Legacy evidence log](validation/0.12.0/legacy-evidence.log).

Native Windows/macOS and ARM64 runtime validation still require an accessible host or connected CI runner; the prepared workflow has not executed. Binary EVTX parsing and validation against real native Windows exports remain pending. Physical USB/power loss, real disk exhaustion, native system snapshot commands and application signing are not established by these tests. Evidence schemas remain readable; older checkpoints/reviews remain bound to their original version. See [WINDOWS_EVENT_XML.md](WINDOWS_EVENT_XML.md) for the feature's exact interpretation and limits.

# Historical k957 0.11.0 validation

Date: 2026-09-29. Native Linux AMD64 with Go 1.26.8 and Python 3.14.7; Windows AMD64 compatibility tests under Wine 10.0 with Windows Python 3.13.12. Independent cryptography tests use 49.0.0. No third-party Go modules were added.

- All 19 native validation steps passed: formatting, vet, uncached unit tests, coverage reporting, race detection, build, version and 11 integrations. [Linux receipt and command logs](validation/0.11.0/linux-amd64/validation.json).
- Windows/Wine: both Go test packages, version and 11 integrations passed. The prebuilt runner explicitly skipped formatting, vet, coverage, race detection and building. [Windows/Wine receipt and command logs](validation/0.11.0/windows-amd64-wine/validation.json). Wine emitted runtime diagnostics around forced process termination; recovery and independent content checks still completed successfully.
- Resume preflight tests cover plain/encrypted remaining-byte budgets, full final-output allowance, exact sufficient/insufficient capacity boundaries, distinct work/chunk filesystems, unknown chunk capacity, frozen completed-source reuse, wrong keys and cancellation. Rejections cover locks, changed incomplete sources, unavailable/wrong-size chunks, mismatched options, existing outputs and exhausted epoch capacity; saved work remains unchanged by preflight.
- Both 192 MiB process-termination integrations now inspect the locked checkpoint, validate remaining-space counts after confirmed process exit, then resume with `--check-space`. Chunk hashes, source equality, acquisition epochs and encrypted staging verification pass.
- A same-size staged-content mutation deliberately passes metadata-only preflight and is rejected by actual resume integrity verification. Preflight does not replace content verification.
- Tests with a symlinked temporary root reproduced and fixed a canonical-path assumption in the test volume provider. Both Go packages pass with the aliased temporary directory. [Alias test log](validation/0.11.0/temporary-directory-alias.log). This is a Linux portability check, not execution on macOS.
- All six release binaries built. Additional Linux ARM64, Windows ARM64 and both macOS test binaries compiled for both Go packages without being executed. [Compilation log](validation/0.11.0/cross-compile.log), [binary formats](validation/0.11.0/build-formats.log).
- Linux statement coverage is 83.0% overall; the profile and function report are retained with the [coverage log](validation/0.11.0/linux-amd64/coverage.log). Windows-specific code is excluded from that measurement.

Native Windows/macOS and ARM64 runtime validation still require an accessible host or CI runner; the prepared hosted workflow has not been run. Physical USB/power loss, real disk exhaustion, system snapshot commands on Windows/macOS and application signing remain untested. Older evidence schemas remain readable; checkpoints and review histories remain version-bound. See [RESUME_PREFLIGHT.md](RESUME_PREFLIGHT.md) for exact behavior and compatibility.

# Historical k957 0.10.1 validation

Date: 2026-09-28. Native host: Linux AMD64, Go 1.26.8, Python 3.14.7, GCC available. Windows compatibility environment: Wine 10.0 with Windows Python 3.13.12 and cross-compiled Go test executables. The independent cryptography package is 49.0.0; no third-party Go modules were added.

- Native Linux: all 18 validation steps passed, including formatting, vet, uncached unit tests, race detection, release build, version and all 11 integrations. [Receipt and command logs](validation/0.10.1/linux-amd64/validation.json).
- Windows AMD64 under Wine: both Go test packages, version and all 11 integrations passed. Formatting, vet, race detection and building were explicitly skipped in the prebuilt Windows runner; they ran separately on Linux. [Receipt and command logs](validation/0.10.1/windows-amd64-wine/validation.json).
- Both process-termination/restart integrations passed on each executed environment, using 192 MiB fixtures and independently checking staged/final content. This is process termination, not physical USB or power-loss testing.
- Regression tests cover unchanged Windows files, Unicode/nested/empty paths, temporary checkpoint readers, and persistent Windows replacement conflicts preserving the previous checkpoint and cleaning temporary files. Before the fixes, Windows collection rejected unchanged files and plaintext checkpoint polling caused `Access denied` on replacement.
- All six release executables built. The additional Linux ARM64, Windows ARM64 and macOS Intel/Apple Silicon test executables compiled for both packages; these executables were not run. [Compilation log](validation/0.10.1/cross-compile.log).
- ELF/PE/Mach-O formats were checked. The Linux and Windows AMD64 release executable hashes match their validation receipts; both report version 0.10.1.
- Linux statement coverage: CLI 76.2%, core 83.4%, total 82.7%. [Function coverage](validation/0.10.1/linux-amd64/coverage.txt). Windows-specific code is excluded from this Linux coverage measurement.
- The six-target GitHub Actions workflow passed `actionlint` v1.7.12. [Lint log](validation/0.10.1/workflow-lint.log). The workflow has not been executed on hosted runners.

Native Windows and macOS runtime tests remain unperformed: no accessible unlocked Windows test guest or macOS/CI executor was available. Wine results do not establish native OS, ACL, device or USB behavior. ARM64 runtime, system snapshot commands on Windows/macOS, application signing/notarization, physical interruptions and browser visual checks remain unvalidated. See [PLATFORM_TESTING.md](PLATFORM_TESTING.md) for reproduction and version-bound checkpoint/review compatibility. Older reports below are historical; their platform and feature limitations describe their own versions.

# Historical k957 0.10.0 validation

Date: 2026-09-28. Environment: Linux AMD64, Go 1.26.8, GCC available. No third-party Go modules were added.

- `bash scripts/test.sh`: passed (`go vet ./...` and uncached Go tests).
- `go test -race -coverprofile=/tmp/k957-0.10-coverage.out ./...`: passed; no races reported. Statement coverage: CLI 76.2%, core 83.4%, total 82.7%. Function-level results are in [0.10-coverage.txt](0.10-coverage.txt).
- `gofmt -l` on changed Go files: no output.
- The packaged `legacy-v1.k957` and `demo-resumable.k957` evidence files both passed `verify` with the 0.10.0 binary.
- `bash scripts/build.sh`: all six Linux/Windows/macOS AMD64/ARM64 targets built. ELF/PE/Mach-O formats checked; the native executable reports `k957 0.10.0`.
- All 11 Python integration scripts passed, including the new independent PCAPNG test, classic PCAP regression, encrypted/plain SIGKILL recovery, preflight, analyst reviews, custody, sharing, structured logs and independent cryptographic verification. Command output is in [0.10-integration-output.txt](0.10-integration-output.txt).
- `FuzzPCAPNG`, two workers, 10-second budget: 744,234 executions, passed.
- `FuzzPCAP`, two workers, 10-second budget (about 11 seconds including completion): 410,649 executions, passed.

The new tests cover mixed byte-order sections, per-interface timestamps/offsets, binary timestamp precision, SLL/SLL2 in both containers, distinct interface/section flow groups, source byte offsets, malformed block/option lengths, undefined interfaces, declared section lengths, unsupported packet/metadata handling and resource limits. The Python test checks HTML/CSV/JSON provenance, missing metadata/payload markers in both report types, masked IP/path/time values, and unchanged evidence bytes.

Fuzz campaigns are short smoke tests, not exhaustive validation. Only Linux AMD64 was executed. Windows/macOS/ARM64 device operation, real capture compatibility, visual browser checks and physical USB/power loss were not tested. Older packaged examples and the unprefixed `coverage.out`, `docs/coverage.txt`, `docs/test-output.txt`, `docs/integration-output.txt` and `docs/pcap-fuzz.txt` remain historical 0.9.0 artifacts. Version-bound checkpoints and review ledgers are not migrated; see [PCAPNG.md](PCAPNG.md).

# Historical 0.9.0 test report

Date: 2026-09-28. Environment: restricted Linux AMD64. Compiler: Go 1.26.1. The core at this version used no third-party Go modules.

## Executed checks

- `go test -race -coverprofile=coverage.out ./...` and `go vet ./...`: passed, with no data races reported. Statement coverage: CLI 76.2%, core 82.4%, total 81.7%.
- Native CLI end-to-end flow: passed.
- Classic PCAP: both byte orders, microsecond/nanosecond timestamps, Ethernet/VLAN/raw IP, IPv4/IPv6 TCP/UDP headers: passed. Independent Python checks confirmed record positions, times and byte counts.
- Directional/reverse flows, out-of-order timestamps and reference limits: passed. Complete headers with missing payload and incomplete transport headers produced the expected acceptance/skip results.
- Fragments, malformed records, unsupported protocols and PCAPNG produced verified skip/error reasons. Record/flow/file budgets and malformed lengths respected their limits.
- Shared IPs across network/log evidence, packet references, HTML/JSON/CSV export, shared IP/path/time masking, exclusion of payload markers from findings and unchanged evidence bytes: passed.
- `FuzzPCAP`, two workers, approximately nine seconds: 153,041 executions, no failure.
- Sharing: none of 18 sensitive markers appeared in eight output files. Raw evidence, analysis and signed records retained their byte hashes. Alias/table/reference consistency, preserved counts, cross-field masking, literal/longest matching and HTML/CSV escaping passed.
- Ambiguous policy JSON, unknown categories, policy limits, invalid histories and attempts to review a sharing report were rejected without output.
- Two-key custody registration/transfer/acceptance preserved previous signatures. Holder state during a pending transfer and after acceptance, cancellation, wrong signers and invalid transitions produced the expected results.
- Independent Python verified custody event signatures, domain separation and hashes. Evidence-binding, sequence, payload modification/re-hashing and rollback against an external expected head were rejected. Duplicate JSON fields, timestamp/size bounds and safe HTML/JSON/CSV export passed.
- Preflight combined budgets and per-filesystem reserves passed using controlled capacity values. Insufficient/unknown space produced blocked/unknown status before collection. Existing destinations, overlaps, limits and cancellation passed. Native Linux free-space and metadata-only planning left source content unchanged and created no destination. Collection and package verification after preflight passed.
- Encrypted 192 MiB acquisition recovered after SIGKILL with the same key. Independent Python cryptography verified staged checkpoint/chunk AES-GCM and HMAC. Wrong keys, altered state/chunks and purpose mismatches were rejected. An injected output-write failure returned without blocking the pipe. Synthetic plaintext markers and source paths were absent from encrypted work/output files.
- CSV/JSONL fields, multiline CSV, CRLF and byte positions passed. Invalid IPs, conflicting fields, duplicate JSON keys and malformed CSV produced verified skip/error reports. Three shared entities, distinct evidence counts and CSV export passed.
- Historical `FuzzStructuredLogs` during 0.4.0, approximately six seconds: 74,853 executions, no failure.
- Two signed review revisions and fresh analysis passed. Raw evidence and the previous revision remained unchanged. Altered histories, wrong signing keys and changed rule bases were rejected. Analyst-note HTML/CSV safety passed automated checks.
- Plain 192 MiB acquisition recovered after SIGKILL; 24 chunks were independently verified. Stale-lock rejection, recovery after confirmed process exit, acquisition epochs, v2 chunk hashes, read-only work status and completed-file reuse passed. Same-metadata prefix mutations, corrupt checkpoint chunks and changed sources prevented resume.
- Python standard-library checks independently verified ZIP sizes/hashes and original source bytes. Python cryptography independently verified Ed25519 signatures and decrypted AES-GCM frames.
- Historical 0.1.0 `FuzzEnvelope`: two workers, approximately five seconds, 183,868 executions without failure. Historical 0.1.0 `FuzzRules`: two workers, approximately six seconds, 9,138 executions without failure.
- All six OS/architecture targets cross-compiled. Formats were Linux ELF, Windows PE32+ and macOS Mach-O.

The new 0.9.0 PCAP campaign is recorded in `pcap-fuzz.txt`. Cryptographic/rule fuzz measurements were historical runs against unchanged code; those targets were not fuzzed again for this release. Structured-log fuzzing ran during 0.4.0. These short campaigns are smoke checks, not exhaustive validation. Coverage does not establish correctness. Final test, coverage and ten CLI integration results are in `test-output.txt`, `coverage.txt` and `integration-output.txt`. After the final IPv6 endpoint display change, Go tests, race/vet checks, six builds and PCAP integration all passed again.

Reproduce process recovery with `python3 scripts/resume_integration.py`: a real child process is terminated after its first checkpoint, its exit is confirmed, the test removes its own stale lock, resumes collection and independently compares 24 chunks. This does not establish physical power/USB interruption behavior.

## Tested behavior

- File acquisition, opening signed packages and HTML/JSON/CSV exports.
- Rejection of modified evidence objects, manifests/signatures, wrong trusted keys and trusted-key requirements on unsigned packages.
- Rejection of extra/path-traversal archive records and duplicate manifest objects.
- File-size limits, skipped symlinks and recorded partial collection status.
- Prevention of source/output overlap and overwriting existing outputs; cancelled collection leaves no output.
- Empty, short, complete-frame and multi-frame AES-GCM data; rejection of truncation, modification and appended data; removal of newly decrypted output on failure.
- HTML escaping and CSV formula-prefix protection.
- Invalid rules, bounded binary/text scanning and missing helper commands.
- JSONL/RFC3339 conversion to UTC without guessing a timezone for unqualified log times.
- Rejection of private signing keys inside the source root.
- CLI key generation, collection, verification, analysis, encryption and decryption.

## Platform execution

All six targets built. Only Linux AMD64 executed, in the restricted environment. Linux ARM64, Windows AMD64/ARM64 and macOS AMD64/ARM64 binaries were not executed for this historical release.

## Unperformed or excluded checks

Physical USB/power interruption, real full disks/bad sectors, hardware write blockers, native Windows ACL/enterprise controls, macOS TCC/notarization, real RAM/disk acquisition, multi-terabyte loads, broken network filesystems and independent forensic-laboratory validation were not performed. HTML escaping was tested; browser visual/accessibility checks were not. Real native Windows/macOS helper output was not tested. This was not a production security audit or NIST certification.

- `python3 scripts/review_integration.py`: signed reviews; no GUI, multi-user authorization or physical-device validation was added in this release.
- `python3 scripts/structured_integration.py`: independent structured-log CLI checks; the 74,853-input fuzz campaign was a short smoke check.
- `python3 scripts/encrypted_integration.py`: requires Python cryptography. Absence of known plaintext markers does not establish absence of side-channel, swap or kernel leaks.
- `python3 scripts/preflight_integration.py`: insufficient space was simulated with controlled capacity; real full-disk and native Windows/macOS free-space APIs were not executed.
- `python3 scripts/custody_integration.py`: requires Python cryptography. Two-key event signatures were independently checked; evidence and previous ledger hashes remained unchanged. Physical transfers, civil identity, key-revocation services, trusted timestamps and centralized custody infrastructure were outside its scope.
- `python3 scripts/share_integration.py`: 18 known private markers were checked across eight files with signed review/custody inputs. This does not establish real-world anonymization or complete personal-data recognition. Free text is omitted. Browser visual/accessibility checks were not performed.
- `python3 scripts/pcap_integration.py`: independently calculated synthetic record positions, times and lengths. Broad field-capture compatibility was not tested. At 0.9.0, PCAPNG, live capture, IP fragment reconstruction, TCP session reconstruction, payload and checksum analysis were unsupported. Directional five-tuple groups were not unique connections or people. See `PCAP_TR.md` for the historical baseline and current extensions.
