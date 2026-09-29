# Synthetic examples

**English** · [Türkçe](README_TR.md) · [Application README](../README.md)

All evidence and identities in this directory are artificial. Packaged analysis/sharing reports and review histories are historical **0.9.0** examples; they have not been regenerated for **0.12.0**. Their version fields, absolute source paths and limitations describe the original run, not the current parser. Current functionality is documented in the [application README](../README.md) and [release metadata](../RELEASE.json).

## Included files

- `demo-source/`, `demo.k957` and `demo-report/`: artificial text logs, a single-pass package collected with 0.2.0, and its historical analysis report.
- `legacy-v1.k957`: an evidence-schema v1 compatibility fixture collected with 0.1.0.
- `demo-resumable.k957` and `demo-resumable-report/`: an evidence-schema v2 package collected with 0.2.0 and a report showing two acquisition epochs. The second invocation reuses completed parts without reading their sources again. This fixture does not simulate forced termination; the actual process-kill recovery test is [resume_integration.py](../scripts/resume_integration.py).
- `rules.json`: two demonstration literal rules for failed-authentication text and a PowerShell reference. Neither match is a malware verdict.
- `reviews-v1.json`, `reviews-v2.json`, `demo-review.pub` and `demo-reviewed-report/`: two signed review-history versions, their example public key and a reviewed report. Review histories bind to their original analysis basis; do not apply these 0.9.0 histories to a newly generated 0.12.0 analysis.
- `structured-source/`, `structured.k957`, `structured-report/`: synthetic CSV/JSONL input, its 0.4.0 acquisition package, and a 0.9.0 report with three shared entities (user/host/IP) plus skipped records. Shared values do not establish identity or causality.
- `custody-001.json`, `custody-002.json`, `custody-003.json`, `custody-trust.json`, `custody-head.txt` and `demo-custody-report/`: Alice registers evidence, requests transfer to Bob, and Bob accepts. The trust list contains demonstration public keys; the head stored beside the ledger is not an independently trusted history checkpoint.
- `demo-shared-report/`: a separately masked copy of the review/custody example. `structured-shared-report/` uses `share-policy.json` to retain only source timestamps among the configurable disclosure categories.
- `network-source/`, `network.k957`, `network-report/` and `network-shared-report/`: synthetic 0.9.0 network acquisition and reports, described below.

Example public keys and trust lists must not be reused for real cases. Private signing keys are not included. A sharing report is a derivative presentation, not evidence or an authoritative review input. The repository also includes unmasked reports and synthetic sources; for real work, distribute only the reviewed sharing directory.

## Network example and PCAPNG compatibility

`network-source/traffic.pcap` contains Ethernet/VLAN, IPv4 UDP, IPv6 TCP and truncated-payload examples. Of its nine records, five are parsed and four are skipped with reasons, producing four directional flows. `big-nano.bin` adds a big-endian, nanosecond-resolution raw IPv4 capture and one more flow; its non-PCAP extension demonstrates magic-byte detection. `observer.jsonl` supplies a shared IP value for cross-evidence correlation.

`network-source/unsupported.pcapng` is only a **four-byte PCAPNG magic prefix**, not a complete capture. The historical 0.9.0 report says PCAPNG was unsupported. In 0.12.0, valid supported PCAPNG structures are parsed, while this deliberately truncated fixture still reports a structural error. Its failure does not mean current PCAPNG support is absent. See [PCAPNG support](../docs/PCAPNG.md).

The default shared network report masks or omits IPs, source paths and source times while retaining ports, counts and packet references.

## Generate a current report

Run from the **project root**, not this directory. Replace `k957` with the correct executable path as described in the [application README](../README.md). Choose a new output directory; these commands read the existing package without rewriting the historical reports:

```sh
k957 verify --in examples/demo.k957
k957 analyze --in examples/demo.k957 --out fresh-demo-report --rules examples/rules.json
k957 analyze --in examples/network.k957 --out fresh-network-report
```

To review a current analysis, create a new review history against that analysis and the same rules. Preserve the historical signed review files with their original reports; their original analyzer is required to reuse that review basis. Evidence schemas v1/v2 themselves remain readable by 0.12.0.

## Generate and validate fresh fixtures

These scripts use the executable matching the host platform in `dist/` (or `K957_TEST_BINARY` if set). They create temporary synthetic cases and check the current CLI:

```sh
python scripts/pcapng_integration.py
python scripts/windows_xml_integration.py
```

Use `python3` where needed. To retain a newly generated classic-PCAP source directory as well as run its integration checks, choose a new destination:

```sh
python scripts/pcap_integration.py --examples fresh-network-source
```

The last command saves synthetic source files; it does not regenerate the packaged historical reports. These three scripts use Python's standard library; the complete validation suite additionally needs [requirements-test.txt](../scripts/requirements-test.txt). See [platform testing](../docs/PLATFORM_TESTING.md) and the [retained test results](../docs/TEST_REPORT.md).
