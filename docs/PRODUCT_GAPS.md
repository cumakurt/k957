# Product gaps and proposed development plan

Assessment date: 2026-09-30. Basis: the current k957 0.14.0 working tree, the [product review](PRODUCT_REVIEW.md), the retained [latest validation receipt](validation/product-recheck-linux-amd64.json), and direct inspection of collection, analysis, case, correlation and reporting code. This plan is the historical 0.14.0 gap baseline. Current implementations, tests and remaining acceptance work are recorded in [IMPLEMENTATION_PROGRESS.md](IMPLEMENTATION_PROGRESS.md); do not read the historical gaps below as current capability claims.

The product already provides logical acquisition, evidence hashes and signatures, resumable encrypted staging, selected text/XML/network interpretation, analyst decisions, custody declarations and masked sharing. The outstanding work concerns fidelity, completeness, scale, examination workflow and platform assurance. Priorities below are an engineering recommendation for the existing offline examination product, rather than severity scores for newly discovered bugs.

## First: establish a dependable examination baseline

### 1. Release freshness and native platform assurance

**Gap:** The reviewed source differs from the distributed binaries and their checksum manifest. The latest executed validation is native Linux AMD64; Windows/macOS and ARM64 runtime assurance is incomplete. Existing CI configuration is not evidence of a successful run. `RELEASE.json` still identifies a developer preview and contains historical coverage data.

**Proposal:** Produce an immutable release candidate from one source revision; generate binaries, checksums, source identity and release metadata together. Exercise the existing platform workflow on native hosts, then add permission, locked-file, Unicode-path, USB disconnect and power interruption scenarios. Introduce platform signing/notarization where applicable, with explicit unsigned states until credentials and validation are available.

**Acceptance:** Each supported target has a retained runtime receipt or is explicitly labelled unvalidated. Published files match the release manifest and tested source identity. Real device scenarios have documented results. Effort: medium engineering work plus access to native runners and devices.

Evidence: [RELEASE.json](../RELEASE.json), [platform testing](PLATFORM_TESTING.md), [latest extra checks](validation/product-recheck-extra.json).

### 2. Consistent acquisition and native metadata

**Gap:** Source-change detection does not create a consistent snapshot. Logical collection lacks comprehensive ACL/xattr/alternate-stream capture and physical-device separation assurance. A live SQLite file can be acquired without a matching transaction state.

**Proposal:** Add explicit acquisition methods and guarantees to the record. Use platform snapshot adapters where available; VSS is a candidate for Windows. Retain raw database and sidecar files from a consistent snapshot before parsing. If an online SQLite backup is offered, record it as a separate logical acquisition with its own provenance, rather than substituting it for original files. Collect native metadata through bounded platform adapters.

**Acceptance:** Concurrent writers cannot silently produce a supposedly consistent acquisition. Missing permissions, sidecars and unsupported snapshot methods have explicit outcomes. Metadata round trips and source/destination device checks pass native fixtures. Effort: high and platform dependent.

Evidence: [collection implementation](../internal/core/collect.go), [artifact discovery](../internal/core/artifacts.go). Design references: [Microsoft VSS overview](https://learn.microsoft.com/en-us/windows/win32/vss/volume-shadow-copy-service-overview), [SQLite WAL](https://sqlite.org/wal.html), [SQLite backup API](https://sqlite.org/backup.html).

### 3. Complete, structured coverage reporting

**Gap:** Finding truncation and several parser omissions are now exposed, but completeness is not described uniformly. Case duplicate groups and extension mismatches stop at 2,000 rows; hash matches stop at 10,000. Case inventory stops at 100,000 objects. Not every limit has retained eligible/emitted/omitted counters in every output.

**Proposal:** Add a versioned coverage record for every analysis stage, including support status, attempted inputs, emitted rows, omissions, reason, limit and whether an exact total is known. Record case selection and partial acquisition separately from successful byte verification. Project only safe counters and enums into shared reports.

**Acceptance:** Boundary and over-boundary fixtures identify every omitted class in JSON and HTML. Exact counters are not fabricated for stages that stopped before counting remaining inputs. Full and masked outputs agree on safe aggregate counts. Effort: low to medium.

Evidence: [analysis](../internal/core/analyze.go), [case](../internal/core/case.go), [sharing](../internal/core/share.go).

### 4. Parser isolation and immutable examination inputs

**Gap:** Parsers run in the main process. Verification and later parsing can reopen paths; immutability against concurrent directory modification is not guaranteed. Resource limits help, but do not provide a process sandbox.

**Proposal:** Introduce a versioned worker protocol with read-only evidence handles, bounded output, cancellation, CPU/memory/time limits and disabled network access. Reuse verified immutable objects or validate each immutable copy before dispatch. Begin with complex native formats and retain the existing simple parsers until migration is justified.

**Acceptance:** A worker crash, runaway input, parent-path change or timeout cannot modify original evidence or publish ordinary completed output. Failed stages preserve explicit partial coverage. Effort: medium to high; prerequisite for native parsing and richer RAM analysis.

Evidence: [store analysis](../internal/core/store.go), [verification](../internal/core/verify.go), [product review limitations](PRODUCT_REVIEW.md).

### 5. Native artifact interpretation

**Gap:** EVTX, Registry, MFT/USN, SQLite/WAL, binary journal and native macOS log parsing are absent. Collecting browser history files does not produce browser history events. Prefetch interpretation extracts only selected executable names; systemd drop-in merging and binary plist semantics are incomplete.

**Proposal:** First implement bounded SQLite/WAL browser-history workers and EVTX interpretation or an explicitly documented native export path. Expand to Registry, MFT/USN and platform logs in separate increments. Define a supported application/OS/version matrix, preserve raw timestamps, and retain evidence/record/page/byte references.

**Acceptance:** Each supported format agrees with independent reference results on valid, corrupt, truncated and version-specific fixtures. Unsupported variants are explicit. Source bytes stay unchanged. Effort: high; depends on acquisition consistency, worker isolation and reference fixtures.

Evidence: [analysis support notes](../internal/core/analyze.go), [platform parsing](../internal/core/platform_parse.go), [file type identification](../internal/core/identify.go), [artifact inventory](ARTIFACTS.md).

### 6. Reference accuracy and maintainable core boundaries

**Gap:** The latest 86.5% statement coverage and passing synthetic tests do not establish forensic accuracy across real artifacts. `internal/core` combines acquisition, parsing, case aggregation and reporting; shared limits and outcome semantics need coordinated maintenance.

**Proposal:** Maintain a supported-format corpus with independent expected outputs, known unsupported examples and recorded false positives/negatives. Expand fuzz campaigns and compatibility tests. Extract focused interfaces for verified evidence, acquisition adapters, parser workers and report projections while preserving current CLI and schemas through documented adapters.

**Acceptance:** Each claimed capability names its corpus and oracle. Critical interpretation changes have comparison evidence and compatibility tests. Refactoring preserves evidence bytes, identifiers and public behavior unless a migration is explicitly documented. Effort: medium and ongoing.

Evidence: [core architecture](ARCHITECTURE.md), [regression suite](../internal/core/recheck_test.go), [validation receipts](validation/product-recheck-extra.json).

## Next: improve analysis depth and examiner workflow

### 7. A unified case examination

**Gap:** `case` joins inventory, duplicate hashes and acquisition/file timestamps. It does not merge the parsed events, findings, activity and review decisions from all collection analyses into a shared case investigation.

**Proposal:** Build a versioned case index from verified collections and validated analysis records. Identify objects with collection digest plus evidence ID; retain analyzer/rule/review identities. Offer a common timeline and cross-collection searches with explicit duplicate-source handling.

**Acceptance:** Two collections with the same local `E1` identifier cannot collide. Every event links to its collection and exact evidence record. Missing, stale and partial analyses are visible. Effort: medium to high; depends on complete coverage and case storage.

Evidence: [case dossier](../internal/core/case.go), [analysis model](../internal/core/analyze.go), [case documentation](CASE.md).

### 8. Bounded storage, search and large-case performance

**Gap:** Analysis/case rows accumulate in memory; several exports serialize full arrays; verified archives can be reread. No durable case search index or complete browser pagination exists. Existing caps avoid unbounded output by omitting data.

**Proposal:** Measure peak memory, bytes reread and latency first. Add a rebuildable local derived index, bounded streaming exports, stable pagination and sorting. Keep the signed evidence separate from the derived database. Choose a storage implementation after considering the current CGO-free, six-target build contract.

**Acceptance:** An agreed reference case, initially 100,000 objects and 1,000,000 derived events, meets a documented memory and latency budget. Indexed searches retain source links; index loss permits deterministic rebuilding. These are proposed test targets, not measured current capacity. Effort: high.

Evidence: [analysis export](../internal/core/analyze.go), [case CSV accumulation](../internal/core/case.go), [HTML report](../internal/core/report_html.go).

### 9. Time uncertainty and identity-aware correlation

**Gap:** Correlation groups shared user/host/IP values across evidence objects. It does not account for host clock offsets, resolve identities, distinguish repeated sessions or establish causal relationships.

**Proposal:** Preserve raw time and time semantics alongside UTC projections. Support examiner-supplied clock corrections with provenance and uncertainty intervals. Add bounded temporal joins and scoped user/host/session identities; explain the rule and references behind each relationship.

**Acceptance:** Same-named accounts, NAT addresses, duplicate logs and events outside a time window do not become unsupported identity conclusions. Corrections never rewrite original timestamps. Effort: medium; depends on a unified case event model.

Evidence: [correlation](../internal/core/correlate.go), [analysis notes](../internal/core/analyze.go).

### 10. Richer, evaluated detection rules

**Gap:** Rules mainly use literal strings and exact SHA-256 matches. There is no field-based condition language, bounded event-sequence engine or corpus-backed quality measurement for detection packs.

**Proposal:** Define a versioned rule schema with explicit field types, boolean operators and bounded temporal conditions. Store rule-pack identity in analysis and require evidence references for each match. Add a runner that reports known true/false positives and negatives per corpus and rule version. Consider rule-language importers only after semantics and resource budgets are defined.

**Acceptance:** Repeated analysis with the same evidence and rule pack produces the same addressed matches. Invalid rules fail clearly; sequence limits and omissions are reported. Evaluation results are retained and reviewed. Effort: medium; depends on structured native events and time semantics.

Evidence: [rule matching](../internal/core/analyze.go), [exact hash sets](../internal/core/hashset.go).

### 11. RAM acquisition assurance and kernel object analysis

**Gap:** Linux acquisition and external-tool integration exist, but memory examination is literal scanning and symbol-free observations. It does not reconstruct process lists, sockets, injected regions or kernel objects. Windows/macOS acquisition relies on an external tool.

**Proposal:** Integrate an isolated Volatility 3 worker with pinned tool identity, explicit plugin scope and offline symbol bundles matched to the image. Require provenance for external acquisition helpers. Report missing/mismatched symbols as unsupported analysis and retain the existing lightweight observations separately.

**Acceptance:** Known reference images yield independently compared processes/sockets with memory references. Missing symbols, unreadable pages and unsupported kernels are visible; no automatic network download occurs in offline mode. Effort: high and requires image/symbol access.

Evidence: [memory scanner](../internal/core/memory_scan.go), [acquisition](../internal/core/memory.go). Design reference: [Volatility symbol tables](https://volatility3.readthedocs.io/en/latest/symbol-tables.html).

### 12. Network session and application interpretation

**Gap:** PCAP/PCAPNG support is bounded TCP/UDP header and directional-flow interpretation. IP fragment/TCP reassembly, DNS/application parsing, packet checksum validation and session separation are absent.

**Proposal:** Introduce bounded fragment and TCP reconstruction with explicit retransmission, overlap and capture-gap policies; then add selected DNS/HTTP/TLS metadata parsers. Keep file/section/interface/packet provenance and make encrypted payload limitations explicit.

**Acceptance:** Known captures with reused tuples, packet loss, overlaps and truncation retain correct session distinctions and omissions. Reported metadata links to packets. Effort: high; depends on worker/resource and coverage policies.

Evidence: [PCAP semantics](PCAP_TR.md), [PCAPNG semantics](PCAPNG.md), [analysis scope](../internal/core/analyze.go).

### 13. Report documents and derived-output authentication

**Gap:** HTML/JSON/CSV and masked sharing exist. Native PDF/DOCX, complete large-section navigation and signatures over the exported report bundle do not. A signed acquisition does not authenticate a later report.

**Proposal:** Generate every format from one report projection with source references and coverage. Add report-bundle hashes, a versioned report manifest, optional analyst signatures and a verifier. Implement PDF/DOCX only after provenance, masking and omission semantics remain consistent across outputs.

**Acceptance:** Changing an exported report invalidates its signature verification. Full and shared reports use distinct manifests and disclosure policies. All formats preserve the same covered counts and source links. Effort: medium.

Evidence: [HTML view](../internal/core/report_html.go), [sharing projection](../internal/core/share.go), [architecture](ARCHITECTURE.md).

### 14. Searchable and accessible examiner interface

**Gap:** The product has CLI commands, an English wizard and static reports, rather than an interactive case workspace. Analyst decisions exist, but a filtered evidence browser, persistent investigation bookmarks and multi-user roles/second approval are absent.

**Proposal:** Start with a local case viewer backed by the derived index: filters, evidence preview, source navigation, timeline, notes and signed-review integration. Support keyboard access and clear partial/unsupported states. Introduce authentication, roles, audit events and bounded job queues only if a multi-user service becomes part of the product scope.

**Acceptance:** An examiner can trace a finding to bytes, record a decision and export a covered subset without losing review provenance. Accessibility checks pass the chosen UI standard. A service deployment has explicit permissions and concurrent-update tests. Effort: medium to high; depends on case storage.

Evidence: [CLI](../cmd/k957/main.go), [report template](../internal/core/report_template.go), [review ledger](../internal/core/review.go), [roadmap](ROADMAP.md).

### 15. Operational trust and key lifecycle

**Gap:** Signed custody events, external actor trust and recipient acceptance exist. Trusted timestamping, key revocation/rotation policy, hardware-backed signing and independently anchored immutable custody history are incomplete.

**Proposal:** Define key-validity intervals and historical revocation semantics before implementing rotation. Add an optional hardware signing adapter and timestamp service. Preserve an offline workflow, recording whether time and ledger-head anchoring are independently verified. Keep trust configuration outside acquired evidence.

**Acceptance:** A key change/revocation does not silently rewrite history. Valid historical events, forbidden new events and rollback to a valid old ledger prefix have documented decisions and tests. Offline use clearly reports unavailable external assurance. Effort: medium to high; requires organizational trust decisions.

Evidence: [custody workflow](CUSTODY_TR.md), [custody implementation](../internal/core/custody.go), [release status](../RELEASE.json).

## Optional: expand beyond the current offline triage scope

### 16. Physical disk imaging and deleted-data recovery

**Gap:** Full physical disk imaging, deleted-file reconstruction and carving are absent.

**Proposal:** Prefer a bounded read-only import/adaptor workflow for independently acquired reference images first. Add image identity, unreadable-sector maps, resume records and then format-specific filesystem/deleted-data workers. Native imaging needs a separate acquisition and device-validation project.

**Acceptance:** Reference images reproduce expected file and deleted-data results, hashes and address mappings. Recovery uncertainty and false positives are reported. Real device interruption and write-protection scenarios are documented. Effort: high; requires devices and reference images.

Evidence: [case scope](CASE.md), [release flags](../RELEASE.json).

### 17. Cloud, mobile, container, VM and remote sources

**Gap:** Provider-specific cloud/SaaS and mobile/NAS/IoT acquisition adapters are absent. Logical copies and packet files do not provide runtime/API-level container or VM examination.

**Proposal:** Choose one concrete source from actual demand and define its authorized export/import contract. Add bounded pagination, rate-limit recovery, stable identities, export completeness and provider/version coverage before adding more connectors. Keep offline import available.

**Acceptance:** Pagination, expired credentials, retry duplication and unavailable fields produce explicit scope and partial states; credentials are excluded from evidence/report output. Effort: high per source and requires provider/device access.

Evidence: [roadmap](ROADMAP.md), [artifact profiles](../internal/core/artifacts.go).

### 18. Evidence-grounded AI assistance

**Gap:** There is no integrated AI examiner assistant. This is optional for the existing deterministic CLI.

**Proposal:** After indexed source references and coverage are stable, offer local/offline summarization and suggested investigation questions. Require references for every factual claim, separate suggestions from findings and retain analyst approval. Define model/tool identity and a policy for any external data transfer.

**Acceptance:** An evaluation corpus measures unsupported claims, missed evidence, prompt injection and disclosure. The assistant cannot silently change signed evidence, analyst decisions or rule results. Effort: medium to high; depends on the case interface and evaluation corpus.

Evidence: [roadmap](ROADMAP.md), [current analysis model](../internal/core/analyze.go).

## Suggested delivery order

1. Release/source alignment, coverage records and a reference corpus. Run native platform/device validation in parallel when infrastructure is available.
2. Acquisition consistency and immutable worker inputs; first SQLite/WAL and EVTX increments.
3. A rebuildable case index, merged timeline and paginated reports; then a local examiner interface.
4. Evaluated structured rules, temporal correlation, deeper RAM/network interpretation and authenticated report bundles.
5. Key-lifecycle extensions and demand-driven physical/cloud/mobile/AI scope.

Effort labels are relative engineering estimates, not calendar commitments. Team size, native platform access, trusted sample data, signing credentials and target-case sizes must be established before committing dates or capacity guarantees.
