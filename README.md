# k957 0.12.0

**English** · [Türkçe](README_TR.md)

k957 is an offline command-line application for logical evidence collection, package integrity verification, bounded artifact analysis and reporting. It is written in Go and ships as standalone executables for Linux, Windows and macOS on AMD64 and ARM64. The interactive wizard and HTML report interface are currently in Turkish; an English README does not change the application's interface language.

**Status: developer preview.** This release is a working collection and analysis core, not a complete forensic suite or a production-validated product. The exact release capabilities and platform status are recorded in [RELEASE.json](RELEASE.json).

## Implemented capabilities

- **Collection:** recursively copy selected regular files into a `.k957` package with a manifest, SHA-256 hashes, collection issues and optional Ed25519 signing. Live system information is collected only with `--system`.
- **Preflight and recovery:** inspect inventory and estimated destination capacity; collect in resumable 8 MiB parts; inspect or verify saved work; estimate remaining space before resuming. Acquisition epochs and part provenance are retained.
- **Encryption:** AES-256-GCM transport files, or encrypted checkpoints/parts and directly encrypted final output for resumable logical collection.
- **Analysis:** UTF-8 text, CSV and JSONL/NDJSON; Windows event XML exports; supported PCAP/PCAPNG packet headers and directional TCP/UDP flows. Literal text/SHA-256 rules and shared user/host/IP values retain evidence references.
- **Review and custody:** analyst decisions with optional signed review histories; separately signed custody declarations with an external actor/key trust list and recipient acceptance.
- **Reporting:** offline searchable HTML, JSON and CSV; a separate masked sharing report with explicit disclosure policies.

New in **0.12.0**: Windows event XML analysis accepts UTF-8 and BOM-marked UTF-16 LE/BE, retains provider/event/record identifiers and ordered Data fields, normalizes explicit-zone timestamps, and reports original encoded byte offsets and skipped records. Windows-specific context is omitted from shared reports. This analyzes XML exports, not binary EVTX. See [Windows event XML](docs/WINDOWS_EVENT_XML.md) and the [changelog](CHANGELOG.md).

## Run the application

No Go or Python installation is needed to run the supplied executables. Keep `dist/` beside the launcher scripts and select the executable matching the operating system and architecture:

- Linux: `dist/k957-linux-amd64` or `dist/k957-linux-arm64`.
- Windows: `dist/k957-windows-amd64.exe` or `dist/k957-windows-arm64.exe`.
- macOS: `dist/k957-darwin-amd64` for Intel, or `dist/k957-darwin-arm64` for Apple Silicon.

Run `sh start-unix.sh` on Linux/macOS or open `start-windows.cmd` on Windows to start the Turkish wizard. The wizard offers basic collection and analysis; use the CLI for signing, encryption, resume, review and other advanced options. If Unix executable permissions were lost during copying, restore the execute bit on the chosen binary.

For example, from the project directory:

```sh
./dist/k957-linux-amd64 version
./dist/k957-linux-amd64 help
```

On Windows PowerShell, use `./dist/k957-windows-amd64.exe version`; on Apple Silicon, use `./dist/k957-darwin-arm64 version`. In all examples below, replace **`k957`** with your executable's path, or put it on `PATH`. Commands are written on single lines so shell-specific line continuations are unnecessary.

The `version` command reports **0.12.0**. The current general `help` banner still contains an older `0.9.0` label; use `version` and [RELEASE.json](RELEASE.json) for the actual version.

These binaries are not distributed with platform application signing or macOS notarization. Device mount options such as `noexec` and organizational application controls can prevent execution. Follow the applicable deployment policy.

## Quick start with synthetic evidence

Run these commands from the project directory. `examples/demo-source` contains artificial data. Choose a new `case-output` directory; report directories and output files must not already exist, and their parents must exist.

```sh
mkdir case-output
k957 preflight --root examples/demo-source --out case-output/demo.k957
k957 collect --root examples/demo-source --out case-output/demo.k957 --case DEMO-001 --operator Analyst --scope "Synthetic demonstration" --check-space
k957 verify --in case-output/demo.k957
k957 analyze --in case-output/demo.k957 --out case-output/report --rules examples/rules.json
k957 share --in case-output/demo.k957 --out case-output/shared --rules examples/rules.json
```

Open `case-output/report/report.html` locally. Review the separate `case-output/shared` directory before distributing it. For real work, substitute an authorized source directory and an appropriate protected destination outside the source tree.

`preflight` reports checks and inventory issues without acquiring source contents. It estimates capacity; it neither reserves space nor proves that source and destination are separate physical devices. `--check-space` blocks collection when the result is `blocked` or `unknown`; `warning` and `pass` allow the collector to continue its own checks.

## Collection, recovery and encryption

### Collection defaults

The default limits are **256 MiB per source, 2 GiB total, 10,000 files and 30 minutes**. Change them with `--max-file`, `--max-total`, `--max-files` and `--timeout`. Byte limits take integer bytes; durations accept values such as `1h`. Preflight and `--check-space` use a default **256 MiB reserve per target filesystem**, adjustable with `--reserve`.

Outputs must be outside the source tree. Symlinks and special files are skipped and collection problems are recorded in the manifest. The tool does not automatically elevate privileges.

`collect --system` optionally records platform-specific system/process/session/network information, using local files and commands listed in [system.go](internal/core/system.go). It may be used without `--root`, but cannot be combined with resumable `--work` collection. Snapshot commands can be unavailable or denied; those failures are recorded.

### Resumable acquisition

The following example uses the synthetic source and the `case-output` directory created above:

```sh
k957 collect --root examples/demo-source --work case-output/resume-work --out case-output/resumable.k957 --case DEMO-002 --operator Analyst --scope "Synthetic resumable demonstration" --check-space
k957 work-status --work case-output/resume-work --verify-parts
k957 preflight --resume --root examples/demo-source --work case-output/resume-work --out case-output/resumed.k957
k957 collect --resume --root examples/demo-source --work case-output/resume-work --out case-output/resumed.k957 --case DEMO-002 --operator Analyst --scope "Synthetic resumable demonstration" --check-space
```

If the first collection completed, the last command repackages saved data into a new output; it does not simulate interruption or reacquire completed files. After an actual interruption, resume using the original root, case, operator, scope and limits. The original inventory is frozen: newly created source files are excluded, and completed files are reused from saved parts. The result may span multiple acquisition times.

Resume preflight checks saved metadata and remaining capacity; it does not rehash chunks. `work-status --verify-parts` checks saved parts, not the current source prefix. Actual resume performs its own integrity checks. Never clear a work lock until the collector's exit has been confirmed. See [resume and recovery](docs/RESUME_TR.md) and [remaining-space preflight](docs/RESUME_PREFLIGHT.md).

### Signing

This synthetic example creates a new signing key pair outside the source directory:

```sh
k957 keygen --out case-output/analyst
k957 collect --root examples/demo-source --out case-output/signed.k957 --case DEMO-003 --operator Analyst --scope "Synthetic signed demonstration" --sign-key case-output/analyst.key
k957 verify --in case-output/signed.k957 --trusted-key case-output/analyst.pub
```

`keygen` creates `.key` and `.pub` files. For real cases, protect private keys in a trusted environment outside source/work trees and establish public-key trust independently of the evidence package. Without `--trusted-key`, hashes are checked but a present signature is not authenticated. Hash consistency alone does not establish provenance.

### Encrypted collection and transport

```sh
k957 encryption-key --out case-output/transport.key
k957 collect --root examples/demo-source --work case-output/encrypted-work --out case-output/encrypted.k957.enc --case DEMO-004 --operator Analyst --scope "Synthetic encrypted demonstration" --encryption-key case-output/transport.key --check-space
k957 unseal --in case-output/encrypted.k957.enc --out case-output/decrypted.k957 --key case-output/transport.key
k957 verify --in case-output/decrypted.k957
```

Encrypted collection requires `--work` and supports logical files only. Resume and inspect encrypted work with the original `--encryption-key`; fresh encrypted preflight estimates use `--encrypted`. `verify`, `analyze` and `share` read plaintext `.k957` packages, so first unseal encrypted evidence into a protected location.

An already created package can also be encrypted separately:

```sh
k957 seal --in case-output/demo.k957 --out case-output/demo-transport.k957.enc --key case-output/transport.key
```

`seal` does **not** delete its plaintext input. Use a new random key for each real case and keep it separately from the evidence. There is no password-based or recipient-public-key encryption. File mode `0600` does not configure Windows ACL policy. Details: [encrypted collection](docs/ENCRYPTED_COLLECTION_TR.md).

## Analysis and reports

The analyzer verifies the evidence package before interpreting its contents. Supported analysis includes:

- UTF-8 CSV, JSONL/NDJSON and text with explicit RFC3339 timestamps. Structured aliases include `timestamp`/`time`/`@timestamp`, `user`/`username`, `host`/`hostname`, and source/destination IP fields. Timezones and missing years are not guessed.
- `.xml` Windows event exports in the Windows Event namespace, with a single event, event fragments or an `Events` wrapper. Original time, UTC, source line/byte location, provider metadata and ordered Data fields are retained within parser limits. No external XML resources or provider DLLs are loaded.
- Classic PCAP and bounded PCAPNG Enhanced Packet Blocks, including supported Ethernet, raw IP and Linux SLL/SLL2 encapsulation. TCP/UDP header fields and directional flows are extracted; payloads, reassembly and packet checksum verification are not implemented.
- Case-insensitive literal line matches or exact SHA-256 matches from rule JSON. Rules are not regular expressions, Sigma or YARA. With no `--rules` file, no content/hash rules are loaded.
- Shared user/host/IP values in at least two evidence objects. Equal values do not establish independent sources, identity, causality or malicious activity.

A full analysis always writes:

- `report.html`: offline, searchable report with a Turkish interface.
- `analysis.json`: manifest, rules, findings, events, correlations, parser summaries and limitations.
- `findings.csv`: finding IDs, rule matches and analyst decisions when applied.
- `timeline.csv`: UTC events and available source references.
- `correlations.csv`: cross-evidence entity summaries.

Additional files are conditional: `windows-events.csv` for accepted XML events, `network.csv` for extracted flows, `captures.csv` when capture summaries exist, and `custody.csv` when a verified custody ledger is attached. HTML content is escaped and CSV formula prefixes are protected. Browser printing can produce PDF; native PDF/DOCX generation is not included.

Text/XML reads are bounded to **8 MiB per file and 128 MiB total**; capture reads have a separate **64 MiB per file and 256 MiB total** budget. Log events, counted XML records and capture records share a **50,000** budget, excluding file metadata events. There are at most **100 rules, 10,000 findings and 10,000 network flows**. XML and captures each have a 20,000-record per-file ceiling and additional format-specific limits. Reaching the finding limit stops the remaining analysis. Inspect parser summaries and notes: a report can represent partial coverage.

Format details: [structured logs](docs/STRUCTURED_TR.md), [Windows XML](docs/WINDOWS_EVENT_XML.md), [classic PCAP](docs/PCAP_TR.md), [PCAPNG](docs/PCAPNG.md).

## Analyst review, custody and sharing

Findings start as `unreviewed`. After the quick start and signing examples, replace `FINDING_ID` with an actual ID from `case-output/report/analysis.json`:

```sh
k957 review --analysis case-output/report/analysis.json --finding FINDING_ID --decision needs-review --analyst Analyst --note "Requires source context" --sign-key case-output/analyst.key --out case-output/reviews-1.json
k957 analyze --in case-output/demo.k957 --out case-output/reviewed-report --rules examples/rules.json --reviews case-output/reviews-1.json --review-key case-output/analyst.pub
```

Decisions are `confirmed`, `rejected` or `needs-review`. Append history with `--previous` and a new output; signed previous histories require `--previous-key`. Reanalysis must use the matching evidence, analyzer version and rules. Review decisions annotate findings without changing evidence. See [analyst review](docs/REVIEW_TR.md).

`custody` supports `register`, `transfer`, `accept`, `cancel` and `note` actions. It requires an actor signing key and external trust JSON. `custody-verify` validates the ledger against the evidence and trust list; `--expected-head` can check a separately retained history head. Attach a ledger to `analyze` or `share` with `--custody`, `--custody-trust` and optionally `--custody-head`. Signatures authenticate declarations, not physical handover or trusted time. See the complete [custody workflow](docs/CUSTODY_TR.md).

`share` creates a separate `k957-shared-report/1` projection with `shared.json`, HTML and CSV outputs. Default policies mask sensitive identity/path categories and omit source timestamps, free-text excerpts/notes and Windows-specific context. Counts and relationships remain; anonymity is not guaranteed. To retain timestamps explicitly:

```sh
k957 share --in case-output/demo.k957 --out case-output/shared-with-times --rules examples/rules.json --policy examples/share-policy.json
```

A sharing report is neither an evidence package nor an authoritative review input. Share only the inspected sharing directory, not the surrounding case files. See [sharing policies](docs/SHARING_TR.md).

## Commands and outcomes

- `wizard`: interactive Turkish collection/analysis assistant.
- `preflight`: fresh or resumed acquisition planning.
- `collect`: logical files and optional live system snapshots.
- `work-status`: checkpoint inspection and optional part verification.
- `verify`: package integrity and optional trusted signature verification.
- `analyze`, `share`: full analysis or a separate masked report.
- `review`: a new version of the analyst decision ledger.
- `custody`, `custody-verify`: signed custody declarations and validation.
- `keygen`, `encryption-key`: signing keys or a random AES-256 key.
- `seal`, `unseal`: authenticated streaming encryption/decryption.
- `version`, `help`: release version and command overview.

Run `k957 <command> -h` for flags. The current CLI prints subcommand flag help but returns exit code 1 for that request; `k957 help` returns 0. Invoking the executable without arguments prints general help; use `wizard` or a launcher for the interactive assistant.

Successful commands return 0; errors return 1. A partial `collect` also returns 1 while retaining a completed package marked `partial`; inspect manifest issues. Successful `verify` does not mean collection was complete. Cancellation and hard failures attempt to remove unfinished output in single-pass mode; resumable mode retains saved work. Forced termination can leave an incomplete final file. Never accept that file without verification; use a new output path for recovery.

## Compatibility and limitations

Both `k957-evidence/1` and `/2` remain readable. Checkpoints and review histories are bound to their producing analyzer version. Complete old work with its original binary; do not edit version fields to force migration. Preserve old signed reviews and create a fresh analysis for new-version review work.

Packaged example reports and review histories were generated for **0.9.0** and remain historical. Their old absolute source paths and coverage notes describe those original runs. Read the [example guide](examples/README.md) before reusing them.

Collection is logical, live and bounded: it is not a write blocker or an atomic filesystem snapshot. ACLs, xattrs, alternate data streams, ownership, creation/access timestamps, sparse layout and hardlink semantics are not preserved. Reading a live system can change it, and file-change checks do not catch every race.

RAM acquisition, physical disk imaging, deleted-data recovery, native EVTX/Registry/MFT/browser database parsing, cloud APIs, mobile acquisition, live packet capture and distributed analysis are not implemented. Copying those files does not mean interpreting their contents. The [roadmap](docs/ROADMAP.md) distinguishes existing features from pending work.

## Build and validate

Building requires **Go 1.25 or newer**; the supplied 0.12.0 binaries were built with **Go 1.26.8**. There are no third-party Go modules.

```sh
go test ./...
go vet ./...
go build -trimpath -buildvcs=false -o k957 ./cmd/k957
```

On Windows, choose `-o k957.exe`. To build all six release targets, run `bash scripts/build.sh` on a Bash-equipped host or `powershell -File scripts/build.ps1` on Windows. These scripts replace matching files in `dist/`. `bash scripts/test.sh` runs vet and uncached unit tests with coverage.

For full native validation, use Python 3.11+ in a suitable environment, install the test-only dependency, and choose a new result directory:

```sh
python -m pip install -r scripts/requirements-test.txt
python scripts/validate.py --out validation-results
```

Use `python3` where required. Validation runs formatting, vet, uncached tests, coverage, race detection, a native release build, version and all 12 integration scripts. It rebuilds the native `dist` executable and retains per-command logs plus a `validation.json` receipt. Race detection needs a native C compiler; Windows AMD64 needs GCC/MinGW, macOS needs the Xcode command line tools, and Windows ARM64 race detection is unsupported. See [platform testing](docs/PLATFORM_TESTING.md) for setup and prebuilt Windows/Wine mode.

The retained **0.12.0** results, dated **2026-09-29**, are:

- Native Linux AMD64: all 20 validation steps passed, including race detection and 12 integration scripts; total statement coverage was 84.3%.
- Windows AMD64 under Wine 10.0: both Go test packages, version and 12 integrations passed. Native Windows execution was not performed.
- Linux/Windows/macOS AMD64 and ARM64: all six release targets compiled. macOS and the remaining ARM64 targets have not been runtime-tested.
- The six-target [CI workflow](.github/workflows/platform-tests.yml) is prepared but has not executed. Physical USB/power interruption and real-device acquisition remain unvalidated.

See the [test report and receipts](docs/TEST_REPORT.md). Compilation, Wine execution and native execution are different levels of evidence.

## Project files

- [cmd/k957](cmd/k957): CLI, wizard and command handling.
- [internal/core](internal/core): collection, integrity, encryption, analysis and exports.
- [scripts](scripts): build scripts, integration checks and validation runner.
- [examples](examples/README.md): synthetic evidence, rules and historical reports.
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): formats and trust model.
- [docs/PREFLIGHT_TR.md](docs/PREFLIGHT_TR.md): initial acquisition planning.
- [docs/RESUME_PREFLIGHT.md](docs/RESUME_PREFLIGHT.md): remaining-space planning.
- [CHANGELOG.md](CHANGELOG.md), [RELEASE.json](RELEASE.json): release changes and capabilities.
- [SHA256SUMS.txt](SHA256SUMS.txt): distributed-file hashes; this is not a publisher signature. Documentation-only edits update these hashes without changing the application version.

Specialized documents with `_TR` filenames are primarily Turkish; some historical documents include later English update notes. The two root READMEs describe the same current release in their respective languages.

## License

[MIT](LICENSE). The software is provided without warranty; consult the license for its terms.
