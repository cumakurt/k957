# k957 0.15.0 — practical user guide

**English** · [Turkish user guide](README_TR.md)

k957 helps you collect computer evidence, check whether it has changed, examine supported records and create reports. You run it by typing commands in a terminal. You do not need to write software to use the supplied executables.

For example, you can preserve a folder of logs, find failed sign-in records, inspect a supported browser-history database, compare several collections and give another person a PDF with references to the original evidence. A reported match is something to examine. It is not automatically proof of an attack or a person's responsibility.

**Release status: developer preview.** Native Linux AMD64 and Windows AMD64 checks have been executed for the current source. Six operating-system/processor targets are built. Windows ARM64, native macOS, physical-device tests and valid kernel-memory corpus accuracy remain unvalidated. Read [RELEASE.json](RELEASE.json) and [the test report](docs/TEST_REPORT.md) for exact source/executable bindings and the scope of each run.

This guide explains the current executable. Application messages, wizard prompts and reports are English. The Turkish guide explains the same commands in Turkish; it does not change the application's language. Original evidence can contain any language.

## How to read this guide

1. Start with **Getting ready** and **First exercise**. These use artificial demonstration files.
2. Read **Understanding the results** before treating a report as a conclusion.
3. Choose a **Usage scenario** for your task.
4. Use **Command reference** when you need a particular option. Each command includes purpose, an example, the expected result and every option exposed by its help.
5. Use **Troubleshooting**, **Limits and coverage**, and **Further reading** for questions that affect an examination.

Contents:

- [Getting ready](#getting-ready)
- [Basic concepts](#basic-concepts)
- [First exercise](#first-exercise)
- [Understanding the results](#understanding-the-results)
- [Usage scenarios](#usage-scenarios)
- [Command reference](#command-reference)
- [Rules, indicators and labelled measurements](#rules-indicators-and-labelled-measurements)
- [Reports: choosing, reading and delivering outputs](#reports-choosing-reading-and-delivering-outputs)
- [Memory: acquisition, complete scanning and kernel examination](#memory-acquisition-complete-scanning-and-kernel-examination)
- [Trust, custody and source references](#trust-custody-and-source-references)
- [Limits and coverage](#limits-and-coverage)
- [Troubleshooting](#troubleshooting)
- [Building, validation and release artifacts](#building-validation-and-release-artifacts)
- [Further reading](#further-reading)
- [License and developer](#license-and-developer)

## Getting ready

### Choose the executable

A source checkout does not include compiled binaries. Build them with the instructions under **Building, validation and release artifacts**; the start scripts require an existing `dist/` build. Prepared executables can be distributed separately as release assets. See [repository and release preparation](docs/REPOSITORY.md).

Use the file that matches both your operating system and processor:

- Linux on an Intel/AMD 64-bit computer: `dist/k957-linux-amd64`.
- Linux on a 64-bit ARM computer: `dist/k957-linux-arm64`.
- Windows on an Intel/AMD 64-bit computer: `dist/k957-windows-amd64.exe`.
- Windows on an ARM64 computer: `dist/k957-windows-arm64.exe`.
- macOS on an Intel Mac: `dist/k957-darwin-amd64`.
- macOS on an Apple Silicon Mac: `dist/k957-darwin-arm64`.

AMD64 is also called x64 or x86-64. It includes modern Intel processors; the name does not mean that an AMD processor is required. ARM64 is a different processor family. On Windows, Settings → System → About shows the system type. On a Mac, About This Mac identifies the chip. On Linux, `uname -m` commonly prints `x86_64` or `aarch64`.

The application itself needs no Go, Python, Office or web server installation. You need a browser to read HTML and a PDF reader to read PDF. Optional Volatility, Sleuth Kit and local-model workflows have separate prerequisites explained later. The tools used to independently check reports in the test suite are not ordinary application prerequisites.

### Open a terminal and test the program

On Windows, open PowerShell or Windows Terminal in the project folder:

```powershell
.\dist\k957-windows-amd64.exe version
.\dist\k957-windows-amd64.exe help
```

On Linux:

```sh
chmod +x ./dist/k957-linux-amd64
./dist/k957-linux-amd64 version
./dist/k957-linux-amd64 help
```

On Apple Silicon macOS:

```sh
chmod +x ./dist/k957-darwin-arm64
./dist/k957-darwin-arm64 version
./dist/k957-darwin-arm64 help
```

Replace the file with the appropriate ARM64/Intel variant when necessary. The version output also shows Cuma Kurt's developer contact and project links. If a system blocks an unsigned executable, resolve the operating system's trust policy before running it; the release is not code-signed or notarized.

Throughout the rest of this guide, **`k957` means the path to your executable**. For example, on Windows, replace `k957 analyze ...` with `.\dist\k957-windows-amd64.exe analyze ...`. You can put the executable on your PATH and use its filename instead, but that is optional.

The project also includes `start-unix.sh` and `start-windows.cmd` launchers for the English interactive wizard. Keep the expected `dist/` directory beside the launchers. `wizard` asks whether to collect or analyze, then asks for the required paths and case details. It is not a full graphical investigation application.

### Paths, folders and options

- A **path** is an address for a file or folder. `./evidence` means an `evidence` folder inside the current working folder. `C:\Cases\Evidence` is an absolute Windows path.
- Put quotes around a path containing spaces: `--root "C:\Cases\Example Evidence"`.
- An **option** starts with `--`, such as `--root` or `--case`. An option taking a value needs the value immediately after it: `--case CASE-001`.
- Boolean switches can be enabled without a value, such as `--check-space`. Disable them using an equals sign: `--system=false`. Do not write `--system false`.
- Sizes are integer **bytes**, not `2GB` or `256MiB`. 1 MiB = `1048576`, 256 MiB = `268435456`, 1 GiB = `1073741824`, 2 GiB = `2147483648`, 8 GiB = `8589934592`.
- Durations use values such as `30s`, `5m`, `30m` or `4h`. A duration value is not a date.
- Explicit outputs must be **new paths**. The program does not silently replace an old package, report or ledger. Use a new name for each attempt and create its parent folder when needed.
- Do not put an output package or resumable work folder inside the source folder. A collector must not collect its own growing output.

Examples are independent workflows. Reusing the same output filename from two examples requires choosing a fresh name; do not paste the entire guide as one script.

## Basic concepts

- **Evidence/source:** the original files or image you want to preserve and examine. A log, database, event file or RAM image can be evidence.
- **Collection:** one acquisition run. A full collection is a directory with its record, signatures, hashes and acquired artifacts. A selected-folder collection can be one `.k957` package.
- **Package (`.k957`):** a container holding acquired objects and a manifest describing their source, size and hash. The extension is not an encrypted-file guarantee.
- **Manifest:** the inventory inside the package. It records what was collected and problems encountered.
- **SHA-256/hash:** a long value calculated from bytes. If those bytes change, the expected hash changes. A matching hash establishes byte consistency with that expected value; it does not establish what a file means.
- **Signature:** a cryptographic check using a private/public key pair. The private `.key` signs; the public `.pub` verifies. The public key's identity must be established separately.
- **Fingerprint:** a hash identifying a signing public key. Retain it independently when the program generates a temporary signing key.
- **Trusted key:** a public key you obtained through an independently trusted route. A key stored beside evidence is not an external trust anchor by itself.
- **Encryption:** keeps transported/staged bytes unreadable without an AES key. Encryption and signatures solve different problems. Losing the encryption key can make the encrypted material unusable.
- **Case:** an investigation identifier such as `CASE-001`. A derived case dossier can combine multiple collections.
- **Finding:** a rule/hash/indicator observation for an analyst to review. It is not automatically a confirmed incident.
- **Timeline:** records arranged by time, with source references. Clock errors and missing time zones can affect interpretation.
- **Provenance:** where an observation came from: collection digest, evidence ID, original path, native record or byte offset.
- **Custody:** signed declarations of registration and transfer. They record statements; they do not prove a physical handover or authenticate a person's real-world identity.
- **Scope:** the authorized set of sources being collected or examined. Write a description another person could understand, not merely “all”.
- **Derived report:** an explanation built from evidence. HTML, PDF, DOCX, CSV and a case index are derived outputs. Preserve the original evidence separately.

## First exercise

This exercise uses `examples/demo-source`, which contains artificial data. It does not request full-machine collection or RAM acquisition. Run it from the project folder. Use a fresh `case-output` directory or substitute another fresh name.

### 1. Create a destination folder

```sh
mkdir case-output
```

This command also works in ordinary PowerShell. The folder groups this exercise's outputs. It is outside the demonstration source.

### 2. Estimate the required space

```sh
k957 preflight --root examples/demo-source --out case-output/demo.k957
```

Read the inventory, capacity checks and outcome. `preflight` inspects and estimates; it does not collect evidence or create the package. A “ready” estimate describes the measured situation at that moment. Free space and live files can change afterwards.

### 3. Create a reusable signing key

```sh
k957 keygen --out case-output/examiner
```

This creates `examiner.key` and `examiner.pub`. Keep the private `.key` restricted to its signer. The `.pub` can be distributed to people who must verify that signer's outputs. These example paths are convenient for learning; a real examination needs independent key management.

### 4. Collect the demonstration folder

```sh
k957 collect --root examples/demo-source --out case-output/demo.k957 --case DEMO-001 --operator Analyst --scope "Synthetic demonstration folder" --sign-key case-output/examiner.key --check-space
```

`--root` selects the source. `--out` chooses the new package. `--case`, `--operator` and `--scope` describe this acquisition. `--sign-key` signs it with the key from step 3. `--check-space` repeats a capacity check before acquisition. Because this command supplies `--root` and `--out`, it uses selected-folder logical collection, not zero-argument full collection.

### 5. Verify the package

```sh
k957 verify --in case-output/demo.k957 --trusted-key case-output/examiner.pub
```

The verifier checks the package structure, recorded object hashes and signature against the supplied key. A successful verification does not say the logs are benign or that a particular person created them. It says the acquired bytes and signature satisfy the verification checks.

### 6. Create the examination report

```sh
k957 analyze --in case-output/demo.k957 --out case-output/report --trusted-key case-output/examiner.pub --rules examples/rules.json
```

Open `case-output/report/report.html` in a browser and `case-output/report/report.pdf` in a PDF reader. PDF is produced by default; you do not need to install a PDF printer. Keep `analysis.json`, CSV exports and coverage records with the reading editions. They contain machine-readable details and disclosed omissions that the visual report may summarize.

### 7. Create an explicit DOCX/PDF document bundle

```sh
k957 report-documents --analysis case-output/report/analysis.json --out case-output/documents --format both
k957 report-seal --report case-output/documents --key case-output/examiner.key
k957 report-verify --report case-output/documents --trusted-key case-output/examiner.pub
```

`report-documents` produces both PDF and DOCX. `report-seal` signs the derived bundle and its source bindings. `report-verify` checks the seal and included files. Editing the DOCX afterwards changes its bytes and invalidates the old seal for that edited file; make a separately identified new edition if an examiner edits it.

### 8. Make a masked sharing copy

```sh
k957 share --in case-output/demo.k957 --out case-output/shared --trusted-key case-output/examiner.pub --rules examples/rules.json
```

Open and review `case-output/shared/report.html` and `report.pdf` before sharing that new directory. The default policy masks supported identity/path categories and omits sensitive context. It is not a guarantee of anonymity. Preserve the unmasked examination directory privately; the sharing copy does not replace it.

## Understanding the results

### Collection and verification status

- `complete`: the collection completed under its configured scope. Check notes and metadata omissions as well; this is not a claim that every artifact on the machine was acquired.
- `partial`: some acquisition or interpretation work could not finish. Read `issues`, the collection record and the package manifest. Partial data can still have valid hashes/signatures.
- `verified`: the integrity checks succeeded. Distinguish verification against an independently supplied key from verification using an embedded key.
- `failed`: an operation could not satisfy its checks. The summary or retained diagnostic explains why. Do not treat it as a successfully examined collection.
- `absent`: a selected profile path did not exist. Absence of a path does not establish absence of an attack. An unavailable command, optional Registry location or event channel may be recorded separately as an issue.
- `skipped`, `unsupported`, `limited` or `truncated`: coverage is incomplete for that input or method. A zero count from such a method is not proof that no matching records exist.

### Reading a finding

Start with the rule/indicator name, then examine its evidence ID, source path, event/native record, timestamp and excerpt. Open the original verified object or the full machine-readable projection before deciding. A phrase such as `failed password` can be a normal login mistake, an automated test or malicious activity; the phrase alone cannot distinguish them.

Review decisions have separate meanings: `confirmed`, `rejected` and `needs-review`. A signed decision records the analyst's declared assessment and reason. It does not make the underlying inference infallible.

### Progress, read workload and interruption

The live display shows phases such as preparation, memory, files, packaging, verification and analysis. Percentages appear when the total work is known. “Estimating” means the program cannot yet give a meaningful percentage. An estimated remaining time is approximate.

`read workload` can exceed the source's size because integrity checking, hashing and parsing can read the same bytes more than once. For example, a 31 GiB image can lead to a much larger displayed read workload without becoming a larger evidence image.

Progress goes to stderr. Machine-readable results go to stdout when redirected/piped; some terminal commands show a grouped human summary instead. To retain JSON separately:

```sh
k957 verify --in case-output/demo.k957 --trusted-key case-output/examiner.pub > case-output/verification.json 2> case-output/verification-progress.log
```

Ctrl+C requests immediate process termination with exit code `130`. It does not finish the current object, sign an interrupted full collection or wait for a child tool to complete. An unfinished directory may remain. Restart is supported only for the explicit resumable logical workflow with `--work`; full-machine collection is not a resumable RAM-acquisition workflow.

Other reported failures use a nonzero exit status, normally `1`. A collection status must still be read: a logical command's exit status alone is not a complete acquisition-quality assessment.

Disable color on Linux/macOS with `NO_COLOR=1 k957 ...`. In PowerShell, set `$env:NO_COLOR="1"` before the command and remove it with `Remove-Item Env:NO_COLOR` afterwards. `TERM=dumb` selects plain progress. Redirected output stays line-oriented. Supported Windows consoles enable VT processing before ANSI redraw/color output; if that setup fails, the program uses plain output.

## Usage scenarios

### A. Preserve a folder of logs

Use the selected-folder exercise above when you have already copied the relevant logs into one directory. `collect` walks that directory recursively and records acquired file bytes, hashes and available metadata. It is a logical acquisition: it does not image unused disk space, recover deleted files or freeze several live files at the same instant. Keep the package outside the source directory. Record why the directory was selected in `--scope`.

### B. Triage the computer you are currently using

`k957 collect` creates `output/<host>/<UTC timestamp>/`, attempts memory first, then live system state and the OS artifact profile. It operates on the current computer. To change full-mode settings, include the literal `--full` flag:

```sh
k957 collect --full --output-dir case-output/collections --case CASE-001 --operator Examiner --scope "Approved triage of this computer" --sign-key case-output/examiner.key
k957 verify --store case-output/collections --trusted-key case-output/examiner.pub
k957 analyze --store case-output/collections --trusted-key case-output/examiner.pub --rules examples/rules.json
```

Create the parent `case-output` first. Windows usually needs an elevated terminal and a compatible memory acquisition tool; Linux needs access to exposed physical ranges and `/proc/kcore`. macOS requires an external memory acquisition tool. A missing optional log is recorded as absent; a failed memory attempt is a different condition and can make a collection partial. Confirm the acquisition record before saying that RAM was captured.

For a deliberately smaller exercise on synthetic files, turn the three machine-wide sources off explicitly:

```sh
k957 collect --full --root examples/demo-source --output-dir case-output/demo-collections --system=false --artifacts=false --memory=false --case DEMO --operator Analyst --scope "Synthetic folder only"
```

This is an intentional reduced collection. It cannot answer questions about the host's RAM or omitted OS artifacts. File limits in full mode apply to filesystem sources; the default `--memory-limit 0` stores the mapped physical RAM without a configured byte cap.

### C. Resume a long selected-folder acquisition

Use `--work` from the first run. A checkpoint stores acquisition state and verified parts outside the source and package. After interruption, use the same root, case, scope, limits, signer and work directory, adding `--resume`. Do not edit checkpoint files. This is not a snapshot: resumed segments have separate acquisition epochs.

```sh
k957 preflight --root examples/demo-source --out case-output/resumed.k957 --work case-output/checkpoint
k957 collect --root examples/demo-source --out case-output/resumed.k957 --work case-output/checkpoint --case DEMO --operator Analyst --scope "Synthetic resume exercise" --sign-key case-output/examiner.key --check-space
k957 work-status --work case-output/checkpoint --verify-parts
```

Only if that collection was interrupted before successful completion, repeat the exact `collect` command with `--resume`. A successfully created output must not be overwritten. Full-machine collection and memory acquisition do not use this resumable logical-file workflow.

### D. Encrypt transport and resumable staging

`encryption-key` creates an AES-256 key file. In logical collection, `--encryption-key` requires `--work` and encrypts staged parts and the final package. Keep the key separately from the transported package; loss of the key prevents recovery. Decrypt into a new plaintext package before ordinary package verification and analysis.

```sh
k957 encryption-key --out case-output/transport.key
k957 collect --root examples/demo-source --out case-output/encrypted.k957 --work case-output/encrypted-work --encryption-key case-output/transport.key --case DEMO --operator Analyst --scope "Synthetic encrypted exercise" --sign-key case-output/examiner.key
k957 unseal --in case-output/encrypted.k957 --out case-output/decrypted.k957 --key case-output/transport.key
k957 verify --in case-output/decrypted.k957 --trusted-key case-output/examiner.pub
```

Transport encryption and Ed25519 signing solve different tasks: encryption restricts reading; signatures authenticate recorded bytes against a trusted public key. A plaintext report generated later is not automatically encrypted.

### E. Examine supported browser, event and persistence records

Collect the actual files first. Analysis recognizes selected SQLite browser history schemas, EVTX records, clean Registry hives, supported launchd plists and selected text/XML persistence records. It preserves native record references where available. Recognizing a file type does not mean every structure in that type can be interpreted.

```sh
k957 analyze --in case-output/demo.k957 --out case-output/event-report --trusted-key case-output/examiner.pub --rules examples/event-rules.json
```

For a live SQLite database, use `sqlite-acquire` for a separate transaction-consistent logical backup. Collect original main/WAL/journal files separately if you also need raw source bytes. The backup is a derived database and is labeled accordingly.

### F. Examine already exported cloud records

Put only the selected CloudTrail JSON or JSON.gz exports in a directory. `source-import` packages them with provenance. It does not sign in to a cloud account or download records. Record the account/time/region selection and the export method in your examination notes; the exported bytes alone do not prove that every cloud event was exported.

```sh
k957 source-import --kind cloudtrail --in cloud-exports --out case-output/cloud.k957 --case CASE-001 --operator Analyst --scope "Selected offline CloudTrail exports" --sign-key case-output/examiner.key
```

### G. Compare several collected computers

`case` creates a derived dossier from a collection store, not from an arbitrary folder of `.k957` files. Each full collection has its signed `collection.json` and associated files. Failed verification is reported and that collection is excluded from examination.

```sh
k957 case --store case-output/collections --out case-output/dossier --trusted-key case-output/examiner.pub --rules examples/event-rules.json
k957 case-query --case case-output/dossier --kind event --text "failed" --limit 50
k957 case-serve --case case-output/dossier
```

Use the printed local URL, including its token, to open the read-only viewer on the same computer. Keep `case-serve` running while browsing; Ctrl+C stops it. Filter by collection digest and evidence ID when a record needs an exact source scope. Identical file hashes indicate equal acquired bytes, not a common attacker or a copying direction.

### H. Review a finding and save a selection

Read the referenced original record first. Copy the stable finding ID from `analysis.json`; do not use the row number or description as the identifier. `review` records an analyst decision separately from the analysis. A rejected match remains part of the original analysis history.

```sh
k957 review --analysis case-output/report/analysis.json --finding FINDING_ID --analyst Analyst --decision needs-review --note "Confirm this record against the original source" --out case-output/review-01.json --sign-key case-output/examiner.key
k957 analyze --in case-output/demo.k957 --out case-output/reviewed-report --rules examples/rules.json --reviews case-output/review-01.json --review-key case-output/examiner.pub --trusted-key case-output/examiner.pub
```

Replace `FINDING_ID` with a real ID from that analysis. For a case selection, `case-bookmark` creates a signed note with the selected query page, source bindings and HTML/PDF. It records that page, not every matching record beyond it.

### I. Hand over a report with less personal information

`share` creates a separate masked report. The original package remains the evidence. Use the default policy first and review the resulting files before distribution. Explicit policy choices can retain sensitive fields; visible RAM strings and recovered tool files require particular care.

```sh
k957 share --in case-output/demo.k957 --out case-output/shared --rules examples/rules.json --trusted-key case-output/examiner.pub
k957 report-seal --report case-output/shared --key case-output/examiner.key
k957 report-verify --report case-output/shared --trusted-key case-output/examiner.pub
```

A masked report is a sharing projection, not an assertion that the case contains no personal data. Seal it after the final content is ready. Adding or changing a bundle file later causes report verification to fail.

### J. Examine an existing RAM or raw disk image

Use `memory-examine` with a trusted Volatility executable and matching offline symbols, or `disk-examine`/`disk-recover` with Sleuth Kit. These commands preserve external-tool provenance and source hashes. They do not acquire a physical disk. Replace `IMAGE_SHA256`, tool paths and selectors with actual trusted values before running the examples in the command reference. A failed plugin or unsupported filesystem is a reported limitation, not an empty computer.

### K. Use an optional local assistant

Build a case first. `case-assistant` retrieves an explicitly selected page and asks an already installed, cached local Ollama model to propose cited observations. The model is not bundled and is not downloaded automatically. Its answer can be wrong even when citations are formatted correctly. A person must examine the sources; `assistant-review` records acceptance or rejection as a separate signed decision. The `--question` text does not replace the `--text` retrieval filter.

### L. Record custody and compare clocks

Custody records describe declared possession and transfers; they do not physically move evidence. Use actor-specific signing keys, an external actor/public-key trust list and independent retention of ledger heads. Temporal correlation uses explicit clock and identity estimates to propose candidates. It cannot establish causality or silently assume that matching user names on different hosts identify one person.

## Command reference

Examples below are templates, not one long script. Create parent folders first; use a new output name for each run. Uppercase placeholders must be replaced. `k957 help` lists commands; `k957 <command> -h` shows flag help for flag-based commands. The wizard is interactive, and version/build-info should be run without flags. The option lists below are derived from the current executable. When help shares a parser, read the command-specific notes before using its flags.

### `wizard`

Start an interactive collection/analysis assistant.

```sh
k957 wizard
```

Answer the English prompts. No flags are supported; wizard -h is not a help screen.

No command-specific flags.

### `preflight`

Estimate selected-folder acquisition capacity before writing evidence.

```sh
k957 preflight --root examples/demo-source --out case-output/planned.k957
```

Returns counts, planned sizes and filesystem capacity. This is an estimate, not a reservation or a guarantee that live sources remain unchanged.

Options (a missing printed default means no explicit default is shown by help):

- `--encrypted` — estimate encrypted resumable mode; does not read a key.
- `--encryption-key string` — original key for an encrypted --resume checkpoint.
- `--max-file int` — maximum bytes per source (default 268435456).
- `--max-files int` — maximum source count (default 10000).
- `--max-total int` — maximum acquired bytes (default 2147483648).
- `--out string` — planned new output package.
- `--reserve int` — additional free-space reserve per target filesystem (default 268435456).
- `--resume` — estimate remaining space from an existing checkpoint; use original root and limits.
- `--root string` — source directory.
- `--work string` — staging directory (new, or existing with --resume).

### `collect`

Create a signed logical package from a selected directory.

```sh
k957 collect --root examples/demo-source --out case-output/selected.k957 --case DEMO --operator Analyst --scope "Synthetic files" --sign-key case-output/examiner.key
```

Creates a new package and acquisition record. With no arguments this command instead selects full-machine mode; see the next entry.

Options (a missing printed default means no explicit default is shown by help):

- `--case string` — case identifier.
- `--check-space` — run preflight before a fresh or resumed logical acquisition.
- `--encryption-key string` — encrypt staging and final output; requires --work.
- `--max-file int` — maximum bytes per source (default 268435456).
- `--max-files int` — maximum source count (default 10000).
- `--max-total int` — maximum acquired bytes (default 2147483648).
- `--operator string` — operator name.
- `--out string` — new .k957 package outside source tree.
- `--reserve int` — space reserve used by --check-space (default 268435456).
- `--resume` — resume an existing --work with identical scope and limits.
- `--root string` — directory to collect recursively.
- `--scope string` — authorized collection scope.
- `--sign-key string` — optional Ed25519 private key file.
- `--system` — opt-in live system snapshots.
- `--timeout duration` — collection deadline (default 30m0s).
- `--work string` — resumable staging directory outside source/output (logical files only).

### `collect --full`

Collect physical memory, live state and the OS artifact profile.

```sh
k957 collect --full --output-dir case-output/collections --case CASE-001 --operator Analyst --sign-key case-output/examiner.key
```

Creates host/timestamp directories containing signed collection records, evidence and available memory. Explicit --full selects this parser; do not spell the mode selector as --full=true.

Options (a missing printed default means no explicit default is shown by help):

- `--artifacts` — collect the built-in OS artifact profile (default true).
- `--case string` — case identifier; default AUTO-<host>-<timestamp>.
- `--full` — collect memory, live system state and the OS artifact profile (default true).
- `--max-file int` — maximum bytes per source file (default 268435456).
- `--max-files int` — maximum source file count (default 100000).
- `--max-total int` — maximum acquired filesystem bytes (default 8589934592).
- `--memory` — acquire a physical memory image (default true).
- `--memory-limit int` — maximum stored physical bytes; 0 means the mapped RAM.
- `--memory-tool string` — external acquisition tool; {output} is required in --memory-tool-arg.
- `--memory-tool-arg value` — one argument for --memory-tool; repeat the flag and include {output}.
- `--operator string` — operator; default is the current user.
- `--output-dir string` — collection root; host and timestamp directories are created inside it (default "output").
- `--reserve int` — free-space reserve kept on the destination filesystem (default 268435456).
- `--root string` — additional directory to collect.
- `--scope string` — scope; default describes a full triage of this host.
- `--sign-key string` — Ed25519 private key; omit to generate and discard a per-run key.
- `--system` — collect live system snapshots (default true).
- `--timeout duration` — collection deadline (default 4h0m0s).

### `source-import`

Package selected offline CloudTrail exports with provenance.

```sh
k957 source-import --kind cloudtrail --in cloud-exports --out case-output/imported.k957 --case CASE-001 --operator Analyst --scope "Selected exports"
```

Only selected JSON/gzip exports are supported; no remote cloud acquisition is performed.

Options (a missing printed default means no explicit default is shown by help):

- `--case string` — case identifier.
- `--in string` — directory containing only selected JSON/JSON.gz exports.
- `--kind string` — authorized offline export kind (default "cloudtrail").
- `--operator string` — examiner.
- `--out string` — new evidence package.
- `--scope string` — authorized exported scope.
- `--sign-key string` — optional package signer.

### `sqlite-acquire`

Create a separate transaction-consistent SQLite logical backup.

```sh
k957 sqlite-acquire --in browser-source/History --out case-output/history.k957 --case CASE-001 --operator Analyst --scope "Selected browser database" --sign-key case-output/examiner.key
```

Outputs a package of the derived backup and provenance. It does not substitute the original main/WAL bytes.

Options (a missing printed default means no explicit default is shown by help):

- `--case string` — case identifier.
- `--in string` — live SQLite main file; original/WAL bytes are not substituted.
- `--operator string` — examiner.
- `--out string` — new evidence package of a logical backup and provenance.
- `--scope string` — authorized source scope.
- `--sign-key string` — optional package signing key.

### `work-status`

Inspect an existing resumable checkpoint.

```sh
k957 work-status --work case-output/checkpoint --verify-parts
```

Reports acquisition state; verifying parts reads retained bytes and checks their hashes.

Options (a missing printed default means no explicit default is shown by help):

- `--encryption-key string` — key for encrypted staging.
- `--verify-parts` — rehash saved parts (does not inspect source).
- `--work string` — staging directory.

### `verify`

Verify one plaintext package or all full collections in a store.

```sh
k957 verify --in case-output/demo.k957 --trusted-key case-output/examiner.pub
```

No --in means a store scan, default ./output. The shared parser exposes analysis/share flags; --rules, --out, --reviews and --review-key do not produce an analysis here. --hash-set and --iocs are rejected; --policy belongs to share. Use --in/--store and --trusted-key for verification.

Options (a missing printed default means no explicit default is shown by help):

- `--custody string` — signed custody ledger (analyze).
- `--custody-head string` — independently retained custody head (analyze).
- `--custody-trust string` — external actor/key trust JSON (analyze).
- `--hash-set string` — examiner SHA-256 set (analyze/share).
- `--in string` — package path.
- `--iocs string` — offline k957-indicators/1 exact SHA-256, IP and domain list.
- `--out string` — new report directory (analyze/share).
- `--policy string` — share policy JSON; default masks all categories.
- `--review-key string` — trusted public key for review ledger.
- `--reviews string` — review ledger to apply after recomputing analysis.
- `--rules string` — literal/hash rule JSON (analyze).
- `--store string` — collection root; default ./output when --in is omitted.
- `--trusted-key string` — trusted signing public key.

### `analyze`

Verify evidence, run supported examinations and generate reports.

```sh
k957 analyze --in case-output/demo.k957 --out case-output/analysis-02 --rules examples/rules.json --trusted-key case-output/examiner.pub
```

One package uses --in; store mode uses --store or default ./output. HTML and PDF are default outputs. --policy is reserved for share. Review/custody inputs require the corresponding single-package scope.

Options (a missing printed default means no explicit default is shown by help):

- `--custody string` — signed custody ledger (analyze).
- `--custody-head string` — independently retained custody head (analyze).
- `--custody-trust string` — external actor/key trust JSON (analyze).
- `--hash-set string` — examiner SHA-256 set (analyze/share).
- `--in string` — package path.
- `--iocs string` — offline k957-indicators/1 exact SHA-256, IP and domain list.
- `--out string` — new report directory (analyze/share).
- `--policy string` — share policy JSON; default masks all categories.
- `--review-key string` — trusted public key for review ledger.
- `--reviews string` — review ledger to apply after recomputing analysis.
- `--rules string` — literal/hash rule JSON (analyze).
- `--store string` — collection root; default ./output when --in is omitted.
- `--trusted-key string` — trusted signing public key.

### `case`

Build a derived cross-collection examination dossier.

```sh
k957 case --store case-output/collections --out case-output/dossier --rules examples/event-rules.json
```

Produces a queryable SQLite index, inventories, timelines and HTML/PDF. Default output is case/<UTC timestamp>, outside the evidence store.

Options (a missing printed default means no explicit default is shown by help):

- `--hash-set string` — examiner SHA-256 set.
- `--iocs string` — offline k957-indicators/1 exact indicator list.
- `--out string` — new dossier directory; default ./case/<UTC timestamp>.
- `--review value` — review ledger for an examined collection; repeatable.
- `--review-key string` — trusted review public key.
- `--rules string` — literal or structured rule JSON; default built-in rules.
- `--store string` — collection root; default ./output.
- `--trusted-key string` — trusted collection public key.

### `case-query`

Search a bounded page of scoped indexed records.

```sh
k957 case-query --case case-output/dossier --kind event --text "failed" --limit 50 --offset 0
```

Outputs a JSON page and coverage. Filters combine; text search is a literal substring. --port is exposed by the shared viewer parser but only affects case-serve.

Options (a missing printed default means no explicit default is shown by help):

- `--after string` — inclusive RFC3339 lower time bound.
- `--before string` — inclusive RFC3339 upper time bound.
- `--case string` — derived case directory.
- `--digest string` — exact signed collection SHA-256.
- `--evidence string` — exact evidence ID, scoped by --digest.
- `--host string` — exact collection host.
- `--kind string` — event, finding, review, inventory, activity, indicator_match, memory_observation or boundary.
- `--limit int` — page size, 1..200 (default 100).
- `--native-parser string` — exact native parser name; event rows only.
- `--native-record string` — exact native record ID; event rows only.
- `--offset int` — row offset.
- `--port int` — loopback viewer port; 0 selects an available port.
- `--text string` — literal substring search.
- `--usn-file-id string` — exact USN file ID in raw little-endian hex; event rows only.

### `case-assistant`

Ask an explicit cached local model about selected cited records.

```sh
k957 case-assistant --case case-output/dossier --model MODEL_NAME:TAG --kind event --text "failed" --limit 20 --question "Summarize these selected records with citations" --out case-output/proposal.json
```

Replace MODEL_NAME:TAG with an already cached Ollama model. Retains the selected inputs and proposal; no automatic finding decision is made.

Options (a missing printed default means no explicit default is shown by help):

- `--case string` — derived case directory.
- `--digest string` — scope retrieval to exact collection digest.
- `--endpoint string` — explicit loopback Ollama runtime (default "http://127.0.0.1:11434").
- `--evidence string` — scope retrieval to evidence ID.
- `--kind string` — event, finding, activity or other indexed kind (default "event").
- `--limit int` — selected source rows, 1..20 (default 20).
- `--model string` — already cached local model tag, including :tag.
- `--model-digest string` — optional required cached model digest.
- `--offset int` — selected query page offset.
- `--out string` — new assistant JSON, or signed review directory.
- `--question string` — bounded examiner question.
- `--text string` — literal retrieval filter, independent of question.

### `assistant-review`

Record a separate signed examiner decision on an assistant proposal.

```sh
k957 assistant-review --case case-output/dossier --in case-output/proposal.json --decision reject --analyst Analyst --note "Source context does not support the proposal" --sign-key case-output/examiner.key --out case-output/proposal-review
```

Accept/reject refers to the proposal. It does not authenticate the model or transform its claims into original evidence.

Options (a missing printed default means no explicit default is shown by help):

- `--analyst string` — examiner identifier.
- `--case string` — derived case directory.
- `--decision string` — accept or reject proposal.
- `--in string` — assistant JSON proposal.
- `--note string` — required review reason.
- `--out string` — new assistant JSON, or signed review directory.
- `--sign-key string` — Ed25519 review signer.

### `case-correlate`

Derive temporal candidates using explicit clock and identity estimates.

```sh
k957 case-correlate --case case-output/dossier --field user --window 5m --out case-output/candidates.json
```

An optional --policy supplies estimates; without sufficient estimates uncertainty remains visible. Candidates are not causality findings.

Options (a missing printed default means no explicit default is shown by help):

- `--case string` — derived case directory.
- `--field string` — user, host, source_ip or destination_ip (default "user").
- `--out string` — new derived result JSON; default stdout.
- `--policy string` — clock and explicit identity estimates JSON.
- `--window duration` — candidate time window, at most 24h (default 5m0s).

### `case-bookmark`

Save a signed examiner note and selected query page.

```sh
k957 case-bookmark --case case-output/dossier --kind event --text "failed" --limit 50 --title "Authentication review" --analyst Analyst --note "Selected for source verification" --sign-key case-output/examiner.key --out case-output/bookmark
```

Creates selection metadata, source-bound rows and HTML/PDF. Pagination limits are part of the declared selection.

Options (a missing printed default means no explicit default is shown by help):

- `--after string` — inclusive RFC3339 time.
- `--analyst string` — examiner identifier.
- `--before string` — inclusive RFC3339 time.
- `--case string` — derived case directory.
- `--digest string` — collection SHA-256 scope.
- `--evidence string` — evidence ID scope.
- `--host string` — collection host.
- `--kind string` — indexed record kind.
- `--limit int` — selected page size, 1..200 (default 100).
- `--native-parser string` — exact native parser name; event rows only.
- `--native-record string` — exact native record ID; event rows only.
- `--note string` — required selection reason.
- `--offset int` — selected page offset.
- `--out string` — new signed bookmark/subset directory.
- `--sign-key string` — Ed25519 bookmark signer.
- `--text string` — literal search filter.
- `--title string` — investigation bookmark title.
- `--usn-file-id string` — exact USN file ID in raw little-endian hex; event rows only.

### `case-serve`

Serve a token-protected read-only viewer on the same computer.

```sh
k957 case-serve --case case-output/dossier --port 0
```

Port 0 chooses a free local port. Open the printed URL and keep the process running. This is not a remote multi-user service.

Options (a missing printed default means no explicit default is shown by help):

- `--after string` — inclusive RFC3339 lower time bound.
- `--before string` — inclusive RFC3339 upper time bound.
- `--case string` — derived case directory.
- `--digest string` — exact signed collection SHA-256.
- `--evidence string` — exact evidence ID, scoped by --digest.
- `--host string` — exact collection host.
- `--kind string` — event, finding, review, inventory, activity, indicator_match, memory_observation or boundary.
- `--limit int` — page size, 1..200 (default 100).
- `--native-parser string` — exact native parser name; event rows only.
- `--native-record string` — exact native record ID; event rows only.
- `--offset int` — row offset.
- `--port int` — loopback viewer port; 0 selects an available port.
- `--text string` — literal substring search.
- `--usn-file-id string` — exact USN file ID in raw little-endian hex; event rows only.

### `rules-evaluate`

Measure rule results against an explicitly labelled corpus.

```sh
k957 rules-evaluate --rules examples/event-rules.json --corpus labelled-corpus.json --out case-output/rule-measurements.json
```

Requires a real labelled corpus in the documented schema. Reports true/false positives/negatives; measurements only describe that corpus.

Options (a missing printed default means no explicit default is shown by help):

- `--corpus string` — labelled event corpus JSON.
- `--out string` — new evaluation JSON; default stdout.
- `--rules string` — structured rules JSON.

### `report-seal`

Sign every file in a finished derived report bundle.

```sh
k957 report-seal --report case-output/report --key case-output/examiner.key
```

Creates a manifest and Ed25519 seal; later file additions or edits invalidate verification. Only --report and --key operate for this command; document-generation/trust flags in shared help are for the other report commands.

Options (a missing printed default means no explicit default is shown by help):

- `--analysis string` — derived analysis JSON for report-documents.
- `--format string` — pdf, docx or both (default "both").
- `--key string` — Ed25519 report signing key (report-seal).
- `--out string` — new document directory.
- `--report string` — report directory.
- `--trusted-key string` — external trusted report public key (report-verify).

### `report-verify`

Verify a report bundle against its retained seal.

```sh
k957 report-verify --report case-output/report --trusted-key case-output/examiner.pub
```

Use --report and optionally independent --trusted-key. It checks bundle bytes and source bindings, not factual correctness or trusted time. Other shared report flags do not generate documents here.

Options (a missing printed default means no explicit default is shown by help):

- `--analysis string` — derived analysis JSON for report-documents.
- `--format string` — pdf, docx or both (default "both").
- `--key string` — Ed25519 report signing key (report-seal).
- `--out string` — new document directory.
- `--report string` — report directory.
- `--trusted-key string` — external trusted report public key (report-verify).

### `report-documents`

Generate native PDF and/or DOCX from an existing analysis JSON.

```sh
k957 report-documents --analysis case-output/report/analysis.json --out case-output/documents --format both
```

Use --analysis, --out and --format. Keeps analysis.json and documents.json with declared projection omissions. Shared --report/--key/--trusted-key belong to sealing or verification.

Options (a missing printed default means no explicit default is shown by help):

- `--analysis string` — derived analysis JSON for report-documents.
- `--format string` — pdf, docx or both (default "both").
- `--key string` — Ed25519 report signing key (report-seal).
- `--out string` — new document directory.
- `--report string` — report directory.
- `--trusted-key string` — external trusted report public key (report-verify).

### `disk-examine`

Enumerate an existing raw filesystem/disk image with Sleuth Kit fls.

```sh
k957 disk-examine --image images/disk.raw --sha256 IMAGE_SHA256 --tool tools/fls --out case-output/disk-list
```

Record the image-scoped inode references. --offset is sectors, not bytes. --inode in shared help is for disk-recover; this is enumeration, not imaging.

Options (a missing printed default means no explicit default is shown by help):

- `--image string` — raw disk/filesystem image.
- `--inode string` — image-scoped inode reference (disk-recover).
- `--offset int` — filesystem offset in sectors.
- `--out string` — new examination/recovery directory.
- `--sector-size int` — sector bytes, 512..4096 power of two (default 512).
- `--sha256 string` — expected image digest; required for recovery.
- `--tool string` — examiner-selected fls/icat executable.

### `disk-recover`

Recover one explicitly selected image-scoped inode using icat.

```sh
k957 disk-recover --image images/disk.raw --sha256 IMAGE_SHA256 --inode INODE_REFERENCE --tool tools/icat --out case-output/recovered
```

Replace both placeholders with the trusted hash and an inode from this image. Recovery does not prove the original path or an execution history.

Options (a missing printed default means no explicit default is shown by help):

- `--image string` — raw disk/filesystem image.
- `--inode string` — image-scoped inode reference (disk-recover).
- `--offset int` — filesystem offset in sectors.
- `--out string` — new examination/recovery directory.
- `--sector-size int` — sector bytes, 512..4096 power of two (default 512).
- `--sha256 string` — expected image digest; required for recovery.
- `--tool string` — examiner-selected fls/icat executable.

### `memory-examine`

Attempt installed Volatility methods against a verified RAM image.

```sh
k957 memory-examine --image images/memory.lime --sha256 IMAGE_SHA256 --tool tools/vol --symbols offline-symbols --platform windows --plugin all --out case-output/kernel-results
```

Use the platform of the image, not necessarily this computer. All installed applicable plugins are attempted; missing parameters/modules/symbols and failures are recorded separately.

Options (a missing printed default means no explicit default is shown by help):

- `--image string` — raw/LiME memory image.
- `--out string` — new external examination directory.
- `--platform string` — image platform: linux, windows or mac (default: runtime host OS; select explicitly for a different image platform).
- `--plugin string` — all installed platform plugins, or one plugin name (default "all").
- `--sha256 string` — expected acquired image SHA-256.
- `--symbols string` — offline JSON/compressed symbol directory; no plugin code.
- `--tool string` — trusted installed Volatility 3 executable.
- `--work-dir string` — private staging directory; defaults to temporary/output filesystem with sufficient free space.

### `share`

Export a separate masked report from verified evidence.

```sh
k957 share --in case-output/demo.k957 --out case-output/shared-02 --rules examples/rules.json --trusted-key case-output/examiner.pub
```

Requires one package --in; it is not a store operation. --policy is a sharing policy, not a temporal-correlation policy. Review the complete output before distribution.

Options (a missing printed default means no explicit default is shown by help):

- `--custody string` — signed custody ledger (analyze).
- `--custody-head string` — independently retained custody head (analyze).
- `--custody-trust string` — external actor/key trust JSON (analyze).
- `--hash-set string` — examiner SHA-256 set (analyze/share).
- `--in string` — package path.
- `--iocs string` — offline k957-indicators/1 exact SHA-256, IP and domain list.
- `--out string` — new report directory (analyze/share).
- `--policy string` — share policy JSON; default masks all categories.
- `--review-key string` — trusted public key for review ledger.
- `--reviews string` — review ledger to apply after recomputing analysis.
- `--rules string` — literal/hash rule JSON (analyze).
- `--store string` — collection root; default ./output when --in is omitted.
- `--trusted-key string` — trusted signing public key.

### `review`

Append an analyst decision to a new independent review ledger.

```sh
k957 review --analysis case-output/report/analysis.json --finding FINDING_ID --analyst Analyst --decision needs-review --note "Verify source context" --out case-output/review-02.json --sign-key case-output/examiner.key
```

Decisions are confirmed, rejected or needs-review. Append using --previous, writing a new output; --previous-key verifies an independently trusted previous signed ledger.

Options (a missing printed default means no explicit default is shown by help):

- `--analysis string` — original analysis.json from current version.
- `--analyst string` — analyst name.
- `--decision string` — confirmed, rejected or needs-review.
- `--finding string` — stable finding ID.
- `--note string` — required reason.
- `--out string` — new review ledger JSON.
- `--previous string` — previous review ledger, if any.
- `--previous-key string` — trusted public key for previous signed ledger.
- `--sign-key string` — optional signing private key.

### `custody`

Append a signed custody declaration for a verified package.

```sh
k957 custody --in case-output/demo.k957 --trusted-key case-output/examiner.pub --trust actor-trust.json --action register --actor Analyst --sign-key case-output/examiner.key --location "Evidence storage" --note "Initial registration" --out case-output/custody-01.json
```

Create actor-trust.json first with the actual actor public key. Transfer proposes a recipient; accept is signed by that recipient. --anchor/--anchor-key in shared help apply to custody-verify.

Options (a missing printed default means no explicit default is shown by help):

- `--action string` — register, transfer, accept, cancel or note.
- `--actor string` — exact actor identifier in trust list.
- `--anchor string` — externally retained signed custody head; custody-verify.
- `--anchor-key string` — required external witness public key for --anchor.
- `--at string` — declared RFC3339 event time; defaults to now.
- `--expected-head string` — independently retained previous/current custody head.
- `--in string` — verified plaintext .k957 evidence package.
- `--location string` — declared storage/handover location.
- `--note string` — required reason or observation.
- `--out string` — new custody ledger JSON.
- `--previous string` — previous custody ledger; omitted for register.
- `--sign-key string` — required actor Ed25519 private key.
- `--to string` — recipient for transfer only.
- `--trust string` — required external actor/public-key trust JSON.
- `--trusted-key string` — trusted evidence package signing key.

### `custody-anchor`

Sign a custody head for independent external retention.

```sh
k957 custody-anchor --ledger case-output/custody-01.json --trust actor-trust.json --sign-key witness.key --witness Witness --reference "Separate retention record" --out case-output/head-anchor.json
```

Use an independent witness key and retain the anchor outside the evidence/ledger location. Keeping both together alone does not detect rollback of both.

Options (a missing printed default means no explicit default is shown by help):

- `--ledger string` — custody ledger.
- `--out string` — new signed anchor JSON; retain separately from evidence.
- `--reference string` — external retention reference.
- `--sign-key string` — independent witness Ed25519 key.
- `--trust string` — external actor/key policy.
- `--witness string` — declared witness identifier.

### `custody-verify`

Verify signatures, actor policy, transfer state and retained head.

```sh
k957 custody-verify --in case-output/demo.k957 --trusted-key case-output/examiner.pub --ledger case-output/custody-01.json --trust actor-trust.json --anchor case-output/head-anchor.json --anchor-key witness.pub
```

Alternatively use an independently retained --expected-head. Declared custody and time are not a physical handover proof or trusted timestamp.

Options (a missing printed default means no explicit default is shown by help):

- `--anchor string` — externally retained signed custody head; custody-verify.
- `--anchor-key string` — required external witness public key for --anchor.
- `--expected-head string` — independently retained previous/current custody head.
- `--in string` — verified plaintext .k957 evidence package.
- `--ledger string` — custody ledger JSON to verify.
- `--trust string` — required external actor/public-key trust JSON.
- `--trusted-key string` — trusted evidence package signing key.

### `keygen`

Create an Ed25519 signing key pair.

```sh
k957 keygen --out case-output/examiner-02
```

Creates examiner-02.key and examiner-02.pub; keep the private .key secret and retain/distribute the .pub independently.

Options (a missing printed default means no explicit default is shown by help):

- `--out string` — new signing key prefix.

### `encryption-key`

Create a random AES-256 transport key.

```sh
k957 encryption-key --out case-output/transport-02.key
```

Creates a new symmetric key file. This is not a public/private key pair and must not be shared with the encrypted package.

Options (a missing printed default means no explicit default is shown by help):

- `--out string` — new encryption key path.

### `seal`

Encrypt an existing file in authenticated streaming frames.

```sh
k957 seal --in case-output/demo.k957 --out case-output/demo.encrypted --key case-output/transport.key
```

Writes a new encrypted file. It does not create an evidence signature; use the signing workflow separately.

Options (a missing printed default means no explicit default is shown by help):

- `--in string` — input file.
- `--key string` — AES-256 hex key file.
- `--out string` — new output file.

### `unseal`

Decrypt a transport file into a new plaintext file.

```sh
k957 unseal --in case-output/demo.encrypted --out case-output/demo-restored.k957 --key case-output/transport.key
```

Wrong keys or modified authenticated frames fail. Verify the restored evidence package before analyzing it.

Options (a missing printed default means no explicit default is shown by help):

- `--in string` — input file.
- `--key string` — AES-256 hex key file.
- `--out string` — new output file.

### `version`

Show release version and public developer contacts.

```sh
k957 version
```

Version labels alone do not identify the executable bytes.

No command-specific flags.

### `build-info`

Show compiler, target, modules, source identity and developer metadata.

```sh
k957 build-info
```

Retain this output together with the executable SHA-256 for reproducibility. Source identity is distinct from executable hash.

No command-specific flags.

## Rules, indicators and labelled measurements

### Text rules: start with a phrase you can explain

Save the following as `my-rules.json` in a text editor using UTF-8. It is a JSON array; commas separate objects and JSON does not accept comments. The `id` is your stable rule name, `description` explains why a match deserves review, and `contains` is the literal phrase. This example is a triage aid, not a malware detector:

```json
[
  {"id":"LOGIN-FAILED","description":"Review a failed authentication reference","contains":"failed password"},
  {"id":"SCRIPT-REFERENCE","description":"Review a script interpreter reference","contains":"powershell"}
]
```

```sh
k957 analyze --in case-output/demo.k957 --out case-output/custom-report --rules my-rules.json --trusted-key case-output/examiner.pub
```

Search supported text records and RAM strings with a meaningful phrase. A phrase inside a document, an administrator's script or a copied log can match without malicious activity. A missing match can mean the source was not acquired, the parser does not cover it, or the content did not match; it does not prove the action never occurred. See [structured rule documentation](docs/STRUCTURED_TR.md) for supported fields/operators and [example rules](examples/event-rules.json).

### Structured event rules: combine conditions

This rule uses `all`: both conditions must be true. `type` identifies a projected Windows event; the event ID narrows it. It does not search arbitrary bytes for the number 1102.

```json
[
  {
    "id":"LOG-CLEARED",
    "description":"Review whether log clearing was authorized",
    "event":{"all":[
      {"field":"type","op":"equals","value":"windows_event"},
      {"field":"windows.event_id","op":"equals","value":"1102"}
    ]}
  }
]
```

Supported structured conditions include selected equality/substring and IP CIDR predicates. Use documented event fields; a misspelled or absent field does not magically extract new evidence. `any` means at least one listed alternative must match when alternatives are supplied. Optional `techniques` contain examiner-supplied ATT&CK IDs; the application does not infer a technique from a matching word.

### Offline indicators: exact observed values

Save this as `indicators.json`. `example.test` and `192.0.2.1` are demonstration values, not claims about a real threat:

```json
{
  "schema":"k957-indicators/1",
  "name":"Demonstration indicators",
  "source":"Examiner-supplied synthetic list",
  "indicators":[
    {"id":"DOMAIN-001","kind":"domain","value":"example.test"},
    {"id":"IP-001","kind":"ip","value":"192.0.2.1"}
  ]
}
```

```sh
k957 analyze --in case-output/demo.k957 --out case-output/indicator-report --iocs indicators.json --trusted-key case-output/examiner.pub
```

Allowed kinds are `domain`, `ip` and `sha256`. Domains use ASCII/punycode, are case-folded and have a trailing dot removed; subdomains do not implicitly match. Supported projected browser hosts, DNS questions, HTTP Host, TLS server names, event IPs and acquired object/image hashes supply observations. There is no online reputation lookup, active DNS request or arbitrary prose search for these indicators. The original list and match references are retained. An IOC match is not an automatic compromise verdict.

### Hash sets: equal bytes, examiner-supplied meaning

Save actual 64-character SHA-256 values in a text file. A bare hash means `known-bad`; explicit labels are clearer:

```text
# Replace the placeholders with actual SHA-256 values before use.
known-good TRUSTED_REFERENCE_SHA256 Approved reference file
known-bad SELECTED_CANDIDATE_SHA256 Candidate requiring examination
```

```sh
k957 analyze --in case-output/demo.k957 --out case-output/hash-report --hash-set my-hashes.txt --trusted-key case-output/examiner.pub
```

The placeholder text above is not a valid hash set. Obtain hashes from trusted reference files or recorded evidence; do not invent a malicious label because a file is unfamiliar. The parser rejects conflicting labels/verdicts. `known-good` is recorded without a finding; `known-bad` creates an unreviewed candidate. Limits: 32 MiB input and 500,000 hashes. [Hash set details](docs/CASE.md#hash-sets).

### Measure a structured rule with known labels

Save the structured rule above as `log-rule.json` and this corpus as `labelled-corpus.json`:

```json
{
  "schema":"k957-rule-corpus/1",
  "name":"Two synthetic Windows events",
  "events":[
    {"type":"windows_event","windows":{"event_id":1102}},
    {"type":"windows_event","windows":{"event_id":4624}}
  ],
  "positive":[{"rule":"LOG-CLEARED","event_index":0}]
}
```

```sh
k957 rules-evaluate --rules log-rule.json --corpus labelled-corpus.json --out case-output/log-rule-measurements.json
```

Event indexes start at zero. Unlisted event/rule pairs are labelled negative; forgetting a positive label changes the measurement. True positive means expected and matched; false positive means matched but labelled negative; false negative means expected but missed; true negative means negative and unmatched. Precision describes the proportion of matches labelled positive; recall describes the proportion of positives found. Undefined ratios are omitted. Two synthetic rows demonstrate the mechanism, not real detection accuracy. This runner supports structured event rules only, at most 100 rules, 10,000 events and 100,000 labels.

## Reports: choosing, reading and delivering outputs

### Which format should I open?

- **`report.html`**: open locally in a browser for the visual report, filtering and navigation. Some report types offer more interaction than others. It is a derived reading view; retain the source bundle.
- **`report.pdf`**: generated by default with analysis, sharing, case and bookmarked records. Use it for an easy-to-open reading copy or printing. No browser, AI model or online PDF service is needed to produce it.
- **`analysis.json`**: machine-readable single-analysis record, useful for checking precise source fields and later document generation.
- **`case.json` / `case-index.sqlite`**: dossier summary and rebuildable cross-collection examination index. The index is not a signed original source database.
- **CSV files**: spreadsheet-friendly timelines, findings, inventory, file types, indicators and other applicable projections. Output files vary with report type and available evidence. CSV formula protection changes spreadsheet presentation of risky strings; original evidence remains separately retained.
- **`documents.json`**: document-generation receipt. Check included formats, source projection binding, page count, omitted content and PDF glyph substitutions.
- **`report.docx`**: explicitly request through `report-documents --format docx` or `both` when a Word-compatible reading copy is needed. Editing it changes a sealed bundle's bytes.
- **`timeline.jsonl`, `attack-navigator.json`, value lists and `review-queue.json`**: portable analysis projections. The JSONL timeline contains only events with absolute timestamps; ATT&CK mappings are examiner-supplied and are not validated against every technique release. See [reporting details](docs/REPORTING.md).

### Read method status before conclusions

Start with collection/verification status and coverage. Then inspect method notes, acquisition issues, source references and omissions. A file modification timestamp is not proof that a person executed the file. Registry last-write time is not value creation time. A TLS server name is not decrypted HTTPS content. Zero extracted rows from an unavailable parser is not a clean-system verdict.

For each material observation, retain: collection digest, evidence ID, original/native record or byte/address reference, relevant raw timestamp/encoding, method and limitations, and your decision. The application's `Software developer` credit identifies the software author; it does not identify the person who conducted or approved the examination.

### A PDF is a reading edition

PDF/DOCX deliberately have readable projections: generally up to 500 findings/events/inventory/IOC/review rows, 200 notes/coverage rows and 400 acquisition issues, with report-specific memory/case previews. Paragraphs are limited to 16 KiB and total document text to 1 MiB. Case PDFs sample up to 200 rows of each included index kind. Inspect `documents.json` for exact omissions rather than assuming every row appears on paper.

These document limits do not truncate complete RAM JSONL or kernel output. HTML/JSON can also carry bounded previews; use the complete sidecar files when completeness matters. `report-documents` does not reconstruct or copy missing RAM sidecars from an analysis JSON alone. Unsupported PDF characters appear as visible `[U+XXXX]` escapes and are recorded; original Unicode text stays in JSON/HTML and DOCX. Native PDF layout uses embedded fonts, sections, source references and page numbering; it is a deterministic document generator, not AI-authored prose.

### Masking policy example

The default `share` projection is conservative. For an explicit policy, save this as `share-policy.json`:

```json
{"schema":"k957-share-policy/1","keep":["timestamps"],"literals":[]}
```

```sh
k957 share --in case-output/demo.k957 --out case-output/shared-policy --policy share-policy.json --trusted-key case-output/examiner.pub
```

This choice retains timestamps. Other keep/literal choices are documented in [sharing](docs/SHARING_TR.md); review them before use. Shared reports have a separate disclosure binding and exclude private complete RAM strings/kernel dump files. Do not manually copy those private files into a shared bundle. Masking is not a guarantee against re-identification from context.

### Seal only the final bundle

```sh
k957 report-seal --report case-output/report --key case-output/examiner.key
k957 report-verify --report case-output/report --trusted-key case-output/examiner.pub
```

The seal enumerates every included regular file's path, size and SHA-256 and binds the report's declared sources. Verification rejects unexpected/missing/modified files and unsafe paths. Retain the public key independently. Internal consistency using the embedded key is weaker than verifying with a public key obtained through a separate trusted channel. A report seal does not certify the analysis's conclusions or provide independently trusted time. Keep original signed evidence, analysis sidecars, final report and verification record together in your retention plan.

## Memory: acquisition, complete scanning and kernel examination

### Three different tasks

1. **Acquisition** saves a RAM image. Full mode tries memory first; successful capture records its method, byte count, hash, gaps and read errors. Live RAM changes during acquisition; the image is not an atomic view of every page.
2. **Default analysis** authenticates and streams supported raw/LiME images. It extracts complete applicable strings, literal-rule hits, URLs and selected structural observations. It does not reconstruct a full process list from operating-system kernel structures.
3. **Kernel examination** uses a trusted external Volatility installation and exact matching offline symbols. It can attempt processes, sockets and other methods supported by that installed tool. Whether a method can run depends on the image/platform/symbols/modules/required selectors. It cannot promise every possible forensic result from every image.

### Capturing RAM

Linux reads exposed `System RAM` ranges against `/proc/kcore` mappings and writes LiME. Hidden ranges, lockdown, unavailable mappings and permissions can prevent or reduce acquisition. Read failures can be represented by zero pages and recorded; a zero page is not automatically evidence that the original memory was zero.

Windows discovers exactly one matching `winpmem*.exe` next to the executable or in its `tools` directory, or accepts an explicit tool. WinPmem is an external driver/tool requiring compatibility and privileges. For an explicitly selected tool whose documented syntax is `-o <file>`:

```sh
k957 collect --full --memory-tool tools/winpmem.exe --memory-tool-arg=-o --memory-tool-arg="{output}" --output-dir case-output/collections
```

Verify that your selected tool actually uses this syntax. Each `--memory-tool-arg` is one argument; one must contain `{output}`, replaced with the chosen destination. macOS has no built-in physical-memory acquisition method. An external tool's hash is retained, but this alone does not validate its driver or all interpreter dependencies.

### No automatic RAM image, result or tool-runtime cap

Default in-process scanning reads one verified descriptor and hashes exactly the consumed stream. It does not load the entire image into RAM or require an image-sized `/tmp` copy. There is no configured image-size, LiME range-count or complete result-count ceiling. Complete private JSONL retains ASCII/UTF-16LE printable strings in reconstructable segments, literal hits, full URL tokens and supported observations, with addresses/encodings. CSV exports stream applicable complete hit/observation rows. Previews in analysis/HTML/PDF are separately bounded and declared.

External examination still needs a full private image/symbol copy. It checks available capacity, considers the temporary filesystem then the output filesystem, and accepts an explicit `--work-dir`. There is no automatic 8 GiB image cap, fixed 64 MiB RAM staging reserve, two-minute plugin deadline, 32 MiB output cap, 64 KiB stderr cap or 100,000-row kernel cap. Disk exhaustion, cancellation, malformed output, changed input and incompatible symbols are real failures. Keep enough space for both staging and unpredictable recovered dumps/results; free space is not reserved against other programs.

### Configure automatic kernel examination

Linux/macOS shell example (replace paths with existing trusted files/directories):

```sh
export K957_VOLATILITY=/opt/forensics/vol
export K957_MEMORY_SYMBOLS=/data/offline-symbols
export K957_MEMORY_WORK_DIR=/data/memory-work
k957 analyze --store case-output/collections
```

PowerShell equivalent:

```powershell
$env:K957_VOLATILITY="C:\Forensics\vol.exe"
$env:K957_MEMORY_SYMBOLS="D:\offline-symbols"
$env:K957_MEMORY_WORK_DIR="D:\memory-work"
.\k957-windows-amd64.exe analyze --store case-output/collections
```

The work directory is optional and must be an existing suitable destination. Automatic platform selection uses the acquisition record or package manifest. For imported RAM from another platform, use explicit `memory-examine --platform` instead of relying on the collector OS.

### Read the whole memory result

Check image hash, method states and complete sidecar references/counts in `memory.csv` and the analysis. Basic previews show at most 500 hits, 500 observations and 50 URL previews per image; complete JSONL preserves the rest. Kernel suite receipts retain attempted/unavailable/failed methods, tool/symbol hashes, JSON output, help/stderr and recovered files. `all` discovers applicable installed platform/global methods; it does not invent PIDs, YARA rules or addresses for methods that require them. A missing method is explicitly reported.

Printable memory strings can include passwords, tokens, personal messages and unrelated data. Keep full results private and review disclosure separately. The current synthetic >8 GiB Windows check proves orchestration and retention, not kernel recovery accuracy on a valid real image. Positive kernel reference-image accuracy remains unvalidated. [Full memory documentation](docs/MEMORY.md).

## Trust, custody and source references

### Why independently retained keys matter

A fingerprint/hash changes when bytes change, but an attacker able to replace both evidence and its hash can supply a new matching pair. A signature checked against a public key you retained independently ties bytes to that key. A freshly generated embedded key only establishes self-consistency. If full collection discards its generated private key, record the displayed fingerprint independently at acquisition time; later you cannot use the discarded key to sign more data.

Private signing keys end in `.key`; public verification keys end in `.pub`. AES transport keys are separate symmetric secrets. Do not email private keys inside report bundles or overwrite a lost key with a new one while claiming the same signer. Protect keys through your own retention/access procedures.

### Minimal actor trust file

Create an actor-specific key with `keygen`, read its `.pub` file and replace the placeholder below with its actual 64-character hexadecimal public key. Save `actor-trust.json`:

```json
{
  "schema":"k957-custody-trust/1",
  "keys":[{"actor":"Analyst","public_key":"ACTUAL_PUBLIC_KEY_HEX"}]
}
```

The placeholder is invalid until replaced. The string must be the key bytes, not a path to a `.pub` file. Add each distinct actor/key deliberately. Retain this trust file independently; it is a policy you supply, not something the evidence should choose for you.

### Transfer sequence

Register the initial holder, then let that holder propose `transfer --to Recipient`. The recipient signs `accept` using their own trusted key. The holder may cancel a pending transfer. A holder's note is permitted only under valid state rules. Each step references the previous ledger and writes a new ledger. Retain the displayed head outside that location and check `--expected-head` or an independent witness anchor on later verification. Rotation/revocation policies are supported by the trust schema; retaining historical keys matters. [Custody examples and lifecycle](docs/CUSTODY_TR.md).

### Clock estimates and identity

Use RFC3339 times with explicit timezone; `Z` means UTC, not your local wall clock. The original raw timestamp/encoding remains important. A positive source clock offset means the source clock is ahead and is subtracted to estimate UTC. Unknown drift/identity stays uncertain. A matching username or IP does not by itself establish a person across collections. Clock/identity policy files use their own schema; a sharing policy cannot be used as a correlation policy. [Examination workflows](docs/EXAMINATION_WORKFLOWS.md).

## Limits and coverage

### What collection does and does not preserve

Logical collection preserves acquired file contents and supported descriptor/handle metadata. It is not full physical-device imaging, VSS/snapshot acquisition, deleted-space recovery or an atomic multi-file snapshot. Linux supports selected ownership/timestamps/xattrs/raw ACL attributes; Windows selected handle metadata and owner/group/DACL SDDL; macOS selected timestamps/ownership/xattrs. Windows alternate-stream contents/SACL and native macOS ACL coverage are not claimed. Bounded metadata projections and unreadable sources are disclosed.

Full profiles select known OS artifact locations; they are not a guarantee that every user-created log, application database or persistence mechanism on every OS version was acquired. Use an additional `--root` or a separate scoped acquisition when needed. Offline CloudTrail is the selected cloud adapter; cloud account acquisition is not implemented.

### Supported interpretations

- Selected browser SQLite schemas and sidecar handling; a logical backup is separate from original file bytes.
- EVTX record/header/CRC/BinXML projections; provider message DLLs are not loaded.
- Clean Registry REGF 1.3–1.6 selected keys/values; dirty-hive replay, deleted cells and all segmented data are not covered.
- Selected launchd/task/systemd and Prefetch header information; this is not complete execution reconstruction.
- Selected USN v2/v3 offline journal records and source-scoped file group exports; not MFT reconstruction, live journal acquisition or USN v4 interpretation.
- PCAP/PCAPNG selected IPv4/IPv6/TCP/UDP and DNS/HTTP Host/TLS ClientHello projections. No TLS decryption, QUIC interpretation, live capture, full application payload interpretation or fragment reassembly.
- File signature inventory recognizes more formats than the native parsers semantically interpret.
- RAM streaming observations and separately configured external kernel examination.

### Independent capacities

File collection defaults were listed in the command reference; changing them changes acquisition scope. Native complex artifact workers accept up to 128 MiB input, 32 MiB projected output and 30 seconds per worker. PCAP projections have 64 MiB per-file/256 MiB aggregate, 20,000 packets per file, 10,000 flows and 20 references per flow limits. General analysis finding/review projections and case outputs have their own capacities: legacy inventory up to 100,000 objects; examination index up to one million rows/2 GiB; query pages up to 200 rows, offset up to one million and five-second execution.

These are distinct from uncapped complete RAM results. Look at the actual coverage/omissions in each output. “Supported” means the implemented method can handle a defined projection; it does not mean every OS release or malformed/hostile input has been positively validated. External tools are trusted host code, not a complete OS sandbox. Linux native workers add security restrictions; other platforms do not claim an equivalent sandbox. [Architecture](docs/ARCHITECTURE.md), [artifact coverage](docs/ARTIFACTS.md), [known gaps](docs/PRODUCT_GAPS.md).

### Tested platforms and release status

Current source has retained native Linux AMD64 and Windows AMD64 validation, Windows console/API checks and external-tool integrations. All six binaries undergo build/static-link checks. Native Windows ARM64/macOS, broad physical-device coverage and valid kernel accuracy remain open. The 100,000-object Windows source-scale pass belongs to the separately recorded source/run described in the test report; do not treat it as every test passing for every build. Synthetic negative-image Volatility checks are not positive kernel enumeration tests.

The executable is a developer preview, not a claim of courtroom certification, broad malware-detection accuracy. [Development plan](docs/DEVELOPMENT_PLAN.md) describes the recorded scope. [Release metadata](RELEASE.json), [test report](docs/TEST_REPORT.md) and [platform matrix](docs/PLATFORM_TESTING.md) identify exact runs and limitations.

## Troubleshooting

### “Command not found” or Windows cannot locate the executable

Use the actual platform filename. PowerShell requires `.\k957-windows-amd64.exe` for an executable in the current folder. Linux/macOS use `./k957-linux-amd64` or their corresponding target. Commands in this guide use `k957` as shorthand; substitute your executable or add its directory to PATH deliberately.

### “Exec format error” or wrong processor

Choose AMD64 for Intel/AMD x86-64, ARM64 for an ARM64 operating system. A CPU supporting an instruction set does not guarantee the installed OS uses it. An ELF Linux binary does not run natively on Windows or macOS. Check `build-info` after selecting the binary.

### Unknown option, unexpected positional argument or a boolean not disabled

Check that the command supports the option, use two hyphens and quote paths with spaces. Use `--memory=false`, not `--memory false`. Full collection options need the literal `--full`. Use integer bytes for size flags and Go-style durations such as `30m`, not `30 minutes`. Verify and report commands can show shared flags that do not operate for that command; read the notes above.

### Output already exists

Choose a new filename/directory, for example `report-02`, and retain the previous result. An explicit output must be new; deleting an existing result is not required to proceed. Parent directories must exist. Output/work paths must not overlap the acquired source.

### Missing files or “partial” collection

Read `collection.json` and the acquisition record. Absent optional paths can be normal on another OS/version. Permission failures, read errors, skipped limits and memory failures require separate assessment. Run with appropriate authorized privileges or adjust the documented scope/limits; do not call a partial acquisition complete merely because the program ended.

### Memory staging says there is insufficient space

Confirm `version`/`build-info`: an older binary may still require the former image-sized default temporary staging behavior. The current basic scanner streams external images without that copy. External Volatility needs a private image/symbol copy, and packaged images/archive workers also need staging. Select `--work-dir` or `K957_MEMORY_WORK_DIR` on a filesystem with enough capacity. `/tmp` can be a small RAM-backed filesystem even when another disk is free. Space is needed for outputs/dumps in addition to the source and staging. Do not remove the acquired image to make room; choose another destination.

### Verification fails

Keep the failing package and error record for investigation. Check that you selected the correct independently retained public key and all required collection files are present. Do not regenerate hashes/signatures over changed bytes to “fix” verification. A wrong public key and modified evidence are different causes. A store operation exits nonzero if any collection fails; successful siblings are still listed separately.

### Analysis found nothing

Check the source type, acquired bytes, parser coverage, rule file, time/filter scope and omitted rows. Try a known synthetic example to confirm the workflow. An unsupported database or missing symbol table cannot establish that no suspicious activity occurred.

### Volatility methods fail or are unavailable

Read each method's retained diagnostics and help. Verify tool/platform/symbol compatibility and optional modules. Some methods need PIDs, addresses or YARA rules and cannot run from `all` alone. Retry a specific supported method with the required external tool setup; k957 does not invent selectors. A working Volatility installation without matching symbols may still fail to interpret the image.

### Windows shows escape characters or repeated progress blocks

Current builds enable VT processing on supported real console handles before ANSI redraw; unsupported environments fall back to line output. Confirm the current binary rather than an older copied executable. `TERM=dumb` requests plain progress and `NO_COLOR` disables color. Redirected output is line-oriented. Unicode display also depends on the terminal/font; original source text remains separately preserved.

### PDF does not show every row or displays [U+XXXX]

Read `documents.json`; a PDF is a bounded reading edition. Open the referenced JSON/CSV/complete memory sidecars for remaining rows. `[U+XXXX]` records an unsupported font character, not lost evidence bytes; use HTML/JSON/DOCX for the original text. Do not claim that the PDF alone contains every complete result.

### Viewer cannot open or stops responding

Keep `case-serve` running and use the entire printed loopback URL/token on the same computer. Port 0 avoids a conflicting fixed port. Do not expose the viewer to the network by treating it as a server product. Large queries have page/time limits; narrow the collection/evidence/native reference instead of assuming an empty page means no source record.

### Interrupted acquisition

Ctrl+C requests immediate exit 130. Inspect the work status before any supported resume, preserve the original parameters and signing/encryption keys, and use the same checkpoint. A completed package is not resumable into the same existing output. Full-machine/RAM collection must be rerun as a new collection if needed; its partial directory is not a logical resume checkpoint.

## Building, validation and release artifacts

### Running binaries versus compiling source

To use supplied binaries you do not need Go or Python. To compile, install the Go version specified by [go.mod](go.mod), Go 1.26.0 or newer; retained current builds used Go 1.26.8, and use the repository's build script. Initial dependency download may need network access. The build creates six static-target executables and checks platform-library dependencies; compilation alone is not a native runtime test.

```sh
scripts/build.sh
```

On Windows PowerShell:

```powershell
.\scripts\build.ps1
```

Read each target's success/failure summary. Plain output is used for noninteractive logs; color can be disabled through `NO_COLOR`. Binaries go to `dist/`. `SOURCE.json` records compile-input identity; `SHA256SUMS.txt` lists artifact bytes; `RELEASE.json` records validation scope and does not claim untested runtime targets passed.

### Developer checks

Do not run validation against original evidence. The harness creates synthetic/temporary fixtures. Python test dependencies are for independent validation, not ordinary CLI use:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r scripts/requirements-test.txt
.venv/bin/python scripts/validate.py --help
GOCACHE=/tmp/k957-go-cache go test ./...
GOCACHE=/tmp/k957-go-cache go vet ./...
python3 scripts/check_language.py
```

On Windows use `.venv\Scripts\python.exe` and the corresponding environment syntax instead of Unix paths. Read the validation help before selecting platform/dependency/scale options. Optional tool/model tests can be skipped when unconfigured; skips do not mean the capability was positively tested. [Platform testing instructions](docs/PLATFORM_TESTING.md) and [source-scale workflow](docs/SOURCE_SCALE.md) explain reproducible runs.

### Retain the right identities

Record the tool version, source identity, executable SHA-256, OS/processor, external tool and symbol identities, input hashes, command/settings and output verification records. Verify published artifact checksums using your platform's SHA-256 tool; a checksum file itself needs a trusted delivery/retention channel. A locally rebuilt executable can have different bytes while using the same source identity.

## Further reading

- [Examples](examples/README.md): supplied synthetic workflows and fixtures.
- [Examination workflows](docs/EXAMINATION_WORKFLOWS.md): native parsers, case queries, assistant, bookmarks, tool examinations and custody.
- [Artifacts](docs/ARTIFACTS.md), [Windows event XML](docs/WINDOWS_EVENT_XML.md), [USN journals](docs/USN_JOURNAL.md): exact source projections.
- [Memory](docs/MEMORY.md), [case index](docs/CASE.md), [reporting](docs/REPORTING.md): full output and scope details.
- [Preflight](docs/PREFLIGHT_TR.md), [resume](docs/RESUME_TR.md), [encrypted collection](docs/ENCRYPTED_COLLECTION_TR.md): acquisition operations.
- [Analyst review](docs/REVIEW_TR.md), [custody](docs/CUSTODY_TR.md), [sharing](docs/SHARING_TR.md): independent decisions and disclosure.
- [Architecture](docs/ARCHITECTURE.md), [test report](docs/TEST_REPORT.md), [platform testing](docs/PLATFORM_TESTING.md): implementation and evidence of checks.
- [Development plan](docs/DEVELOPMENT_PLAN.md), [gaps](docs/PRODUCT_GAPS.md), [implementation progress](docs/IMPLEMENTATION_PROGRESS.md), [change log](CHANGELOG.md): current scope and development history.

Historical `_TR` filenames under docs are retained for compatibility; the root `README_TR.md` is the Turkish user guide. Other application/documentation text is English.

## License and developer

Developer: **Cuma Kurt**. These are software-author contacts, not examination or incident-response credentials:

- Email: [cumakurt@gmail.com](mailto:cumakurt@gmail.com)
- Source repository: [github.com/cumakurt/k957](https://github.com/cumakurt/k957)
- LinkedIn: [Cuma Kurt](https://www.linkedin.com/in/cuma-kurt-34414917/)

See [LICENSE](LICENSE), [third-party notices](THIRD_PARTY_NOTICES.md) and [retained dependency/font licenses](licenses). External tools and optional models have their own installation, compatibility and licensing requirements. Include relevant source identity, version, sanitized command and error when reporting a problem; use synthetic reproductions instead of sending private evidence or secrets.
