# Synthetic examples

[Application README](../README.md)

## Start here if you are new

This directory is a practice kit. It lets you learn collection, verification, analysis and sharing without collecting your own computer. A **source** is the original artificial input; a **package** is the signed acquired copy; a **report** is an interpretation of that copy. They serve different purposes.

1. Read the [first exercise](../README.md#first-exercise) or its [Turkish explanation](../README_TR.md#ilk-uygulama).
2. Open `demo-source/` in your file browser and inspect the small text files. These are inputs, not conclusions.
3. Run commands from the project root. Replace `k957` with your actual executable, such as `./dist/k957-linux-amd64` or `.\dist\k957-windows-amd64.exe`.
4. Open the generated HTML/PDF and compare a finding's referenced text with its source. A match is a candidate to review, not proof of an incident.
5. Keep newly generated outputs separate from the included examples. An explicit output path must be new.

For every command and option, use the main guide. Do not use demonstration identities, public keys or synthetic indicators as a real case policy.

All evidence and identities in this directory are artificial. Analysis/sharing reports and signed review/custody histories were regenerated in English with **0.15.0**. The network demonstration package was recollected with an English scope declaration; its synthetic source files are unchanged. Other acquisition packages remain unchanged. Acquisition version fields and source paths describe each collection. Current functionality is documented in the [application README](../README.md) and [release metadata](../RELEASE.json).

## Included files

- `demo-source/`, `demo.k957` and `demo-report/`: artificial text logs, a single-pass package collected with 0.2.0, and its current English analysis report.
- `legacy-v1.k957`: an evidence-schema v1 compatibility fixture collected with 0.1.0.
- `demo-resumable.k957` and `demo-resumable-report/`: an evidence-schema v2 package collected with 0.2.0 and a report showing two acquisition epochs. The second invocation reuses completed parts without reading their sources again. This fixture does not simulate forced termination; the actual process-kill recovery test is [resume_integration.py](../scripts/resume_integration.py).
- `rules.json`: two demonstration literal rules for failed-authentication text and a PowerShell reference. Neither match is a malware verdict.
- `reviews-v1.json`, `reviews-v2.json`, `demo-review.pub` and `demo-reviewed-report/`: two signed review-history versions, their example public key and a reviewed report. Review histories bind to the current 0.15.0 analysis basis and the included rules. Regenerate them if the analysis basis changes.
- `structured-source/`, `structured.k957`, `structured-report/`: synthetic CSV/JSONL input, its 0.4.0 acquisition package, and a current report with three shared entities (user/host/IP) plus skipped records. Shared values do not establish identity or causality.
- `custody-001.json`, `custody-002.json`, `custody-003.json`, `custody-trust.json`, `custody-head.txt` and `demo-custody-report/`: Alice registers evidence, requests transfer to Bob, and Bob accepts. The trust list contains demonstration public keys; the head stored beside the ledger is not an independently trusted history checkpoint.
- `demo-shared-report/`: a separately masked copy of the review/custody example. `structured-shared-report/` uses `share-policy.json` to retain only source timestamps among the configurable disclosure categories.
- `network-source/`, `network.k957`, `network-report/` and `network-shared-report/`: a synthetic 0.15.0 network acquisition and current reports, described below.

Example public keys and trust lists must not be reused for real cases. Private signing keys are not included. A sharing report is a derivative presentation, not evidence or an authoritative review input. The repository also includes unmasked reports and synthetic sources; for real work, distribute only the reviewed sharing directory.

## Network example and PCAPNG compatibility

`network-source/traffic.pcap` contains Ethernet/VLAN, IPv4 UDP, IPv6 TCP and truncated-payload examples. Of its nine records, five are parsed and four are skipped with reasons, producing four directional flows. `big-nano.bin` adds a big-endian, nanosecond-resolution raw IPv4 capture and one more flow; its non-PCAP extension demonstrates magic-byte detection. `observer.jsonl` supplies a shared IP value for cross-evidence correlation.

`network-source/unsupported.pcapng` is only a **four-byte PCAPNG magic prefix**, not a complete capture. The original 0.9.0 parser did not support PCAPNG. In the current release, valid supported PCAPNG structures are parsed, while this deliberately truncated fixture still reports a structural error. Its failure does not mean current PCAPNG support is absent. See [PCAPNG support](../docs/PCAPNG.md).

The default shared network report masks or omits IPs, source paths and source times while retaining ports, counts and packet references.

## Generate a current report

Run from the **project root**, not this directory. Replace `k957` with the correct executable path as described in the [application README](../README.md). Choose a new output directory; these commands read the existing package without replacing the included reports:

```sh
k957 verify --in examples/demo.k957
k957 analyze --in examples/demo.k957 --out fresh-demo-report --rules examples/rules.json
k957 analyze --in examples/network.k957 --out fresh-network-report
```

To review a current analysis, create a new review history against that analysis and the same rules. Signed review files remain bound to their analyzer version and rules. Evidence schemas v1/v2 remain readable by 0.15.0.

## Generate and validate fresh fixtures

### Practice collecting your own new demonstration package

Create a fresh destination and signing key, then acquire only the artificial source folder:

```sh
mkdir example-practice
k957 keygen --out example-practice/examiner
k957 preflight --root examples/demo-source --out example-practice/demo.k957
k957 collect --root examples/demo-source --out example-practice/demo.k957 --case PRACTICE --operator Analyst --scope "Synthetic examples only" --sign-key example-practice/examiner.key --check-space
k957 verify --in example-practice/demo.k957 --trusted-key example-practice/examiner.pub
k957 analyze --in example-practice/demo.k957 --out example-practice/report --rules examples/rules.json --trusted-key example-practice/examiner.pub
```

The explicit `--root` and `--out` select logical folder collection. Running `k957 collect` without arguments instead tries full-machine collection, including RAM; it is a different exercise. The new private `.key` belongs to this practice run; the `.pub` verifies its signatures. Independently retain public keys in real work rather than trusting a key supplied together with unfamiliar evidence.

Expected outputs include the new package and `report/report.html`, `report/report.pdf`, `report/analysis.json`, CSV projections and `report/documents.json`. Check the collection status and report coverage before interpreting counts. The older included packages retain their historical acquisition versions; new reports describe the current analyzer.

### Practice sharing and authenticating a report

```sh
k957 share --in example-practice/demo.k957 --out example-practice/shared --rules examples/rules.json --trusted-key example-practice/examiner.pub
k957 report-seal --report example-practice/shared --key example-practice/examiner.key
k957 report-verify --report example-practice/shared --trusted-key example-practice/examiner.pub
k957 report-documents --analysis example-practice/report/analysis.json --out example-practice/documents --format both
```

Open and review the shared HTML/PDF before sending the `shared` directory. Do not send the entire practice directory: it also contains the private key and unmasked outputs. The seal detects later edits/additions/removals; it does not certify the examiner's conclusions. `report-documents` creates explicit DOCX/PDF reading copies; consult `documents.json` for omissions. Complete data is retained in the applicable machine-readable projections, not necessarily on every PDF page.

### Choose the next example

- **Text matching:** `demo-source` with `rules.json`; inspect a phrase and its original line.
- **Structured records:** `structured-source`; compare a source row, UTC time and correlation references. Equal entities do not prove a shared identity.
- **Packets:** `network-source`; inspect valid/skipped packet counts and flow references. The truncated PCAPNG prefix is intentionally malformed.
- **Human decisions:** the reviewed report and signed review histories; compare the original candidate with confirmed/rejected/needs-review states. Existing history binds its recorded analysis basis.
- **Declared handover:** custody ledgers; follow register, proposed transfer and acceptance. The included head is colocated and is not an independent anti-rollback anchor.
- **Disclosure:** compare full and shared reports; fields omitted by a sharing policy cannot be recovered from the masked presentation.

### Independent integration checks

These scripts use the executable matching the host platform in `dist/` (or `K957_TEST_BINARY` if set). They create temporary synthetic cases and check the current CLI:

```sh
python scripts/pcapng_integration.py
python scripts/windows_xml_integration.py
```

Use `python3` where needed. To retain a newly generated classic-PCAP source directory as well as run its integration checks, choose a new destination:

```sh
python scripts/pcap_integration.py --examples fresh-network-source
```

The last command saves synthetic source files. To regenerate all packaged English reports and fresh signed review/custody histories while preserving the existing evidence packages, run `python scripts/generate_examples.py`. This replaces the demonstration reports, ledgers and public keys; temporary private keys are removed after generation. Do not use demonstration keys or histories for real cases. These three scripts use Python's standard library; the complete validation suite additionally needs [requirements-test.txt](../scripts/requirements-test.txt). See [platform testing](../docs/PLATFORM_TESTING.md) and the [retained test results](../docs/TEST_REPORT.md).

All regenerated report directories include a default native `report.pdf` and `documents.json` omission/source receipt alongside HTML. The example evidence packages retain their original hashes. These synthetic reports demonstrate rendering and provenance; they are not real incident conclusions or positive kernel-memory validation. See [reporting](../docs/REPORTING.md).
