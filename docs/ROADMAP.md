# Product plan traceability and remaining development

## Current implementation status (0.15.0)

The historical 0.13.0 matrix below is retained as a baseline. Current capabilities, verification and remaining acceptance work are recorded in [IMPLEMENTATION_PROGRESS.md](IMPLEMENTATION_PROGRESS.md), with commands and limits in [EXAMINATION_WORKFLOWS.md](EXAMINATION_WORKFLOWS.md). Native artifact workers, unified case search, temporal estimates, evaluated structured rules, network metadata, PDF/DOCX/report seals, key lifecycle, external disk/RAM tools, offline CloudTrail and cited local assistant increments are implemented. Actual local inference was exercised on three synthetic quotation tasks; an earlier task miss is retained. Native device/platform, wider reference corpus, snapshot, full streaming, mobile/VM/container, hardware/TSA and forensic model quality validation remain pending.


This release does not claim completion of the earlier plan. The following historical 0.13.0 matrix records its implemented scope; empty adapters/examples are not completed capabilities. Current English-only UI replaces the earlier localized interface.

| Plan area | Historical 0.13.0 status | Next acceptance condition |
|---|---|---|
| Go, USB, OS/architecture binaries | Six targets built | Native devices, signing |
| Collection/analysis separation | Separate commands/core workflows | Independent deployment/version compatibility |
| User workflow | CLI wizard/reports | Accessible desktop/web case UI |
| Logical collection | Implemented | Metadata identity/ACL/xattr/ADS/snapshots |
| Preflight | Fresh/frozen inventory, remaining space/reserves | Physical-device separation/native validation |
| Live triage | Selected OS commands | Broader validated artifact/device matrix |
| Physical disk/RAM | Linux LiME, external RAM helpers; no disk imaging | Signed helpers/reference images/native capture |
| Windows artifacts | Bounded event XML; native binary formats pending | Native parsers/OS-version reference corpus |
| Linux/macOS logs | Generic text exports | Native formats/version tests |
| Browser/email/messages | No native databases | WAL consistency/application corpus |
| Cloud/SaaS | Pending | Authorized APIs/pagination/rate limits |
| Mobile/NAS/IoT | Pending | Documented authorized export adapters |
| Container/VM/network | Logical copies, PCAP/PCAPNG headers/flows | Sessions/runtime APIs/snapshots |
| SHA-256/signatures | Implemented | External key operations/hardware signer |
| Encryption | Encrypted staging/final stream/seal | Recipient keys/hardware/audit |
| Custody | Per-actor signatures/acceptance/trust/current head | Trusted time/immutable retention/lifecycle |
| Resume | Chunks/checkpoints/prefix verification/epochs | USB/power/native tests |
| Metadata/timeline | RFC3339/JSONL | Clock uncertainty/native time semantics |
| Rules | Literals/SHA-256 | Sigma/YARA semantics/labels/licenses |
| Correlation | Shared structured users/hosts/IPs with references | Identity/time windows/graph |
| RAM analysis | Literal streams/banner/tool guidance | Isolated Volatility/offline symbols |
| Deleted data/carving | Pending | Reference images/false-positive evaluation |
| Examiner review | CLI reasons/versioned signed history | Roles/UI/second approval |
| Reports | HTML/JSON/CSV/shared policy/browser PDF | Native PDF/DOCX/projection completeness |
| Assistant | Pending | Source citations/local model/disclosure policy |
| Parser isolation | Resource bounds only | Separate low-privilege workers/sandbox |
| Organizational scale | Pending | Index/storage/RBAC/concurrency/queue |

## 0.14.0 examination progress

The license is AGPL-3.0-or-later. Full-mode records bind the collector binary hash. Analysis adds magic-byte types, examiner hash sets and a Sleuth Kit body file. `k957 case` writes one derived dossier for every verified collection, including duplicate hashes across hosts. Native EVTX/registry/MFT parsing, physical disk imaging and in-process kernel reconstruction remain pending. See [CASE.md](CASE.md).

## 0.13.0 acquisition progress

Zero-argument `collect`, `verify` and `analyze` operate on `output/<hostname>/<timestamp>/`. Linux physical memory is a LiME v1 image with an acquisition record, three hashes and a collection signature. Analysis scans the image literally and names the Volatility 3 commands that need matching symbols. See [MEMORY.md](MEMORY.md). Native macOS capture, physical disk imaging and in-process kernel reconstruction remain pending.

## 0.12.0 analysis progress

Windows event XML exports retain System metadata, timestamps, ordered Data fields and original encoded byte positions. Full reports expose parse skips and unsupported payloads; shared reports exclude Windows-specific context. See [WINDOWS_EVENT_XML.md](WINDOWS_EVENT_XML.md). Native EVTX parsing and native Windows export validation remain pending.

## 0.11.0 acquisition progress

Read-only resume preflight and gated plain/encrypted recovery are implemented and validated with partial and completed frozen inventories. Capacity boundaries, unchanged checkpoints, lock/option/source/chunk failures and process-termination recovery are covered. See [RESUME_PREFLIGHT.md](RESUME_PREFLIGHT.md).

## 0.10.1 platform progress

Windows collection identity and checkpoint reader conflicts are fixed. All unit tests and 11 integration scripts pass on native Linux AMD64 and under Wine 10.0 for Windows AMD64. Six-target CI and reusable validation receipts are implemented. Native Windows/macOS and ARM64 execution remain pending; see [PLATFORM_TESTING.md](PLATFORM_TESTING.md).

## Next milestones

1. **Platform validation:** native Windows/macOS devices, application signing, USB controls, permissions and changing-source/read-error scenarios.
2. **Acquisition durability:** chunks, checkpoints, estimates, filesystem identity, encrypted writes and remaining resume space exist. Physical-device identity and power/USB interruption behavior still require validation.
3. **Artifact versions:** broaden native EVTX/Registry, browser SQLite, journal/unified-log parsers with corrupt-input fuzzing and independent reference comparisons.
4. **Examination experience:** case investigation, examiner notes, explainable temporal relationships, search and complete document projections.
5. **Specialized sources:** RAM/disk tools, cloud APIs and VM/container/mobile exports with explicit authorization/license/reference requirements.
6. **Organizational scope:** hardware keys, roles, immutable retention and bounded workers; assistant quality must be measured against evidence references.

Earlier estimates of 6–8 months for an initial product and 12–18+ months for broad platform scope were planning estimates, not a claim of completion in one session. Preview development does not replace those acceptance requirements.
