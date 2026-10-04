# k957 architecture and evidence format v1

## Modules

One statically built Go CLI exposes separate Collect and Analyze workflows. No service, telemetry, auto-update or persistence agent is installed. An explicitly requested read-only case viewer binds to loopback; the optional assistant uses an explicitly supplied loopback model runtime. OS helpers run only when --system is explicitly requested. A local HTML report requires no server. The source is a modular monolith with pinned CGO-free SQLite, EVTX, plist and PDF modules. Third-party notices are retained. Current boundaries and limits are documented in EXAMINATION_WORKFLOWS.md.

Collect: explicit directory -> bounded regular-file traversal -> ZIP object writer + SHA-256 -> manifest -> optional Ed25519 signature -> fsync/close.
Analyze: archive structural checks -> manifest validation -> every object's SHA-256 -> optional trusted-key signature -> bounded text/log decoding -> literal/hash rules -> provenance-bearing results -> HTML/JSON/CSV.

## Container

A `.k957` file is a standard ZIP with `manifest.json`, optional raw 64-byte `manifest.sig`, and `objects/E000001` entries. Payload paths never derive from hostile source paths. Simple readers stream owned/verified bytes; native workers extract only verified inputs into private read-only staging. Each manifest object records original path, bytes, hash, kind, modification time, collection time, mode string, and detected change flag. Manifest includes collector version, host, OS/architecture, case, scope, operator, start/end, complete/partial status, and issues.

Ed25519 signs the exact stored manifest bytes including trailing newline. Private key file is hex encoding of a 64-byte Go Ed25519 private key. Public key file is 32-byte hex. No embedded public key is implicitly trusted. Verification rejects duplicate archive names, unlisted entries, missing entries, duplicate IDs, wrong hashes/sizes, invalid signatures, unknown schema, unknown manifest fields, and trailing JSON. Current ceilings: 100002 archive entries, 128 MiB manifest, 64 GiB per object, 1 TiB cumulative object bytes. These are resource ceilings; the synthetic source load check covers small regular files, not production acquisition diversity.

Manifest encoding writes inventory entries individually into one bounded signing buffer, preserving the previous exact JSON indentation, field order, escaping, nil/empty arrays and trailing newline. Ed25519 signing and strict verification still retain the complete manifest bytes in memory. Both single-pass and resumable packages use the same 128 MiB ceiling. Plaintext checkpoint bytes are bounded at 256 MiB before staging encryption. Preflight includes 128 MiB for a manifest and two 256 MiB checkpoint generations during replacement; these allowances are planning estimates. Schemas v1/v2 remain unchanged. Older readers with the 16 MiB ceiling reject larger new packages; preserve a compatible current binary with such evidence. Smaller existing packages and current-version checkpoints remain readable without editing their bytes/version.

SHA-256 is over bytes actually acquired. Metadata and data can change during acquisition. Before/open identity checks and after-copy size/mtime checks detect some races, not all. Ancestor-path replacement, hostile kernel behavior, unchanged-size/mtime manipulation, or remote filesystem inconsistency are not prevented. A read from a blocking network filesystem might not promptly honor cancellation. Select stable, trusted input or independently acquired images. The output must be outside the logical source tree; source/output physical volume separation is not enforced.

## Encryption envelope

Magic `K957ENC1` (8 bytes), random 8-byte prefix, frames of big-endian uint32 ciphertext length + ciphertext. AES-256-GCM nonce = prefix || uint32 frame index. AAD = full 16-byte header. Plaintext per frame <= 1 MiB. Final empty plaintext frame is mandatory, authenticated, and must be followed by EOF. Frames cannot be modified, removed, reordered or appended without rejection, subject to cryptographic assumptions. An index overflow is rejected. Use a fresh random key per case; there is no password KDF. Decryption failures remove the newly created destination on a best-effort basis. The format is versioned but has not undergone independent cryptographic audit.

## Trust and disclosure

Tool-produced signatures attest possession of the signing key, not authenticity of a compromised host. Separate trust anchor distribution is required. Live commands resolve through the local executable environment (absolute paths on macOS where defined); a compromised PATH or substituted OS helper may falsify data. No kernel bypass is attempted. Key files are not automatically zeroized or backed by hardware. Command outputs may include personal information and command-line secrets within the explicitly selected system snapshot scope.

HTML uses html/template contextual escaping; CSV formula prefixes are escaped. The report's own search JavaScript is static and executes only locally. No evidence scripts are executed. Selected complex native parsers run in separate processes with verified private inputs, bounded output/time and Linux seccomp/CPU controls. Simple readers check SHA-256 again before publishing interpretation; file classification uses header bytes captured during verification. Default external RAM scanning hashes the exact consumed stream against its signed image hash without temporary copying. Collection archives and inputs for separate tool processes are staged against signed artifact hashes. Store/case metadata and signer bindings use the retained verified record rather than mutable paths. These controls are not a full filesystem/hard-memory sandbox. Keep source storage trusted. Derived reports have optional separately verified report-bundle seals.

## Source provenance

Finding -> evidence ID -> manifest item -> exact original source and hash. A text finding also includes the original line number. Log events preserve the original timestamp string and parsed UTC. Native records retain applicable table/row/record/cell/byte references and raw time semantics. Run ID and creation time vary between analyses; substantive results are deterministic for fixed source, rules and implementation, apart from documented size limits.


## v0.2 resumable acquisition extension

Resumable mode uses `k957-evidence/2`; legacy collection still emits v1. Both are accepted by the current verifier. The manifest adds `inventory_frozen` and `epochs`; each item adds ordered `parts` (offset, size, SHA-256, epoch, acquired timestamp). Empty files have no parts and use the SHA-256 of empty input. Final verification validates offsets, lengths, epoch references, each part hash and the full object hash.

Staging uses a bounded `state.json` replaced via temporary-file/fsync/rename and hash-addressed immutable 8 MiB chunks. Exclusive-create `active.lock` prevents cooperative concurrent writers. It is deliberately not auto-stolen after a crash. Staging is trusted plaintext storage, not an authenticated evidence package. Cache symlinks, source path escapes, malformed state, mismatched options and hash failures are rejected. Intermediate files may remain after uncatchable process death; only state-referenced chunks are resumed.

A completed file is historical evidence and is reused without consulting the current source. An unfinished file must retain metadata and byte-for-byte matching previously acquired prefix. Later chunks record the new epoch. Inventory is frozen at initialization. This is not snapshot consistency, automatic source update synchronization or live-command replay. Host/OS/architecture are recorded per epoch. Detailed operational limits and recovery are in RESUME_TR.md.


## v0.3 review ledger

`k957-review/1` binds ordered analyst events to a digest of analyzer version, original manifest SHA-256, full rule definitions and normalized automatic findings. Finding IDs exclude analysis run IDs and timestamps. Decisions are derived overlays; no evidence object is edited. Each event hashes its sequence, finding, analyst, decision, reason, local timestamp, previous event hash and analysis basis. Optional Ed25519 signs canonical JSON of the entire ledger with its signature field omitted. Stored signatures are hexadecimal. Canonicalization is Go's indent-2 JSON encoding plus newline using declaration field order.

`analyze --reviews` always reopens/verifies the original evidence and recomputes automatic findings before accepting the ledger. Different bases are rejected. Review signature trust and evidence signature trust are separate inputs. New ledger files use exclusive creation; prior file contents remain untouched. This is not WORM storage, centralized version enforcement, rollback prevention, authenticated user identity, or trusted timestamping. The latest signature attests the full current ledger; it does not preserve earlier signatures inside that ledger. Keep all prior signed revisions externally. See REVIEW_TR.md.


## v0.4 structured event analysis

Bounded UTF-8 records use explicit flat field aliases for RFC3339 time, message, user, host, source IP and destination IP. CSV uses encoding/csv with byte/physical-line provenance and multiline-field support; JSONL rejects duplicate keys and conflicting aliases. Invalid nonempty IPs or oversized recognized fields cause the event to be skipped. CSV syntax errors stop that file with a recorded error. No timezone, year, delimiter or provider-specific schema is guessed.

A bounded deterministic entity index groups canonical IPs, lowercased hosts and case-sensitive user names across different evidence object IDs. It does not resolve real identities, deduplicate copied logs or infer causality. Up to 20,000 entity keys and 200 references per result are stored; full processed event counts remain visible. Reports include parser summaries and limitations. Structured events and correlations are derived data; review commands still apply to rule findings, not correlation rows. No network lookup or enrichment occurs.


## v0.5 encrypted acquisition

Optional --encryption-key is restricted to resumable logical-file collection. WorkState metadata is serialized in RAM, then encrypted before any temporary-file write to state.enc. Each 8 MiB chunk is encrypted before staging. Purpose-separated HMAC-SHA256-derived keys protect AES-256-GCM blobs and HMAC filenames. Blob format and AAD are specified in ENCRYPTED_COLLECTION_TR.md. The master key is never written into the work state. State encryption uses fresh random 96-bit nonces; chunk encryption is immutable under its authenticated plaintext-hash identity.

The ZIP exporter writes through an io.Pipe into the existing authenticated transport encryptor; both producer and consumer errors close the pipe and propagate. No application-level plaintext ZIP temporary is created. Filesystem metadata and active.lock remain visible. Key material and plaintext exist in process memory; swap, dumps and hostile kernels are outside this protection. Prior valid checkpoint rollback is not prevented. Default plaintext staging remains available, and in-place mode conversion is refused. Readers validate a checkpoint's mode after authenticated decryption. The final unsealed evidence format remains v2.

## v0.6 acquisition preflight

`preflight.go` uses `planWork` metadata inventory to count selected files/bytes without reading contents. Platform-specific `probeVolume` uses Linux/macOS statfs/device identity or Windows caller-available bytes/volume GUID. Output/work requirements are grouped by filesystem identity and compared with the lowest available-capacity sample plus one reserve. Inventory omissions produce warning, unavailable identity/capacity unknown, and overlap/insufficient estimates blocked. Precedence is blocked > unknown > warning > pass.

This layer does not reserve space, persist inventory, validate keys/permissions or prove physical-device separation. Estimates are planning allowances rather than proven bounds. `collect --check-space` refuses unknown/blocked plans. Original v0.6 gated fresh logical acquisition; current resume planning is documented in [RESUME_PREFLIGHT.md](RESUME_PREFLIGHT.md). System snapshots are outside preflight. See [PREFLIGHT_TR.md](PREFLIGHT_TR.md).

## v0.7 signed custody declarations

`custody.go` keeps separate history bound to case, package ID and exact manifest-byte hash. Each event retains its own signature when history is extended. Exact signed JSON bytes are stored as Base64, avoiding a cryptographic JSON-canonicalization assumption. Signature/head hashes use separate domains. Claims include sequence, previous head, signer fingerprint, parties, action and declared/recorded times.

External trust maps one public key to one actor; all history is checked against it. Register establishes custody; transfer names a pending recipient; acceptance changes the holder using that recipient's signature. Cancel/note require the current holder. Backward times are rejected without claiming trusted time. An independently retained current head is needed to reject an older valid prefix.

Signatures do not establish physical handover or real identity. Evidence binding covers manifest/object hashes rather than complete ZIP transport bytes. Trust, sequence, hash and signature checks are distinct. JSON size/depth, duplicate/unknown keys and encodings are validated. CLI verifies the package before applying custody. See [CUSTODY_TR.md](CUSTODY_TR.md).

## v0.8 sharing projection

`share.go` constructs a separate `k957-shared-report/1` projection from fresh verified analysis. Original Analysis/Manifest values are not edited and reserialized; permitted fields are copied explicitly. Free text, original IDs/hashes/signatures and reverse mappings are excluded. Enums are allowlisted; unsupported values become other. Nullable source times are omitted by default while derived-report creation time remains separate.

Aliases are consistent by category/exact value within one report. Retained text is replaced in one regexp pass using known masked-category values and supplied literals. Metacharacters are escaped; case-insensitive longer matches win. Pattern count/complexity limits fail closed. Fully masked defaults do not require this matcher. HTML/CSV/JSON receive only the sharing model.

`share` verifies evidence, reviews and custody before projection. Shared JSON is not accepted by `LoadAnalysis`. Keep original files separately for source identity/signature/reverse mapping checks. Counts, order and relationships remain; anonymity is not guaranteed. See [SHARING_TR.md](SHARING_TR.md).

## v0.9 classic PCAP

`pcap.go` selects archive objects by name or magic bytes under separate 64 MiB/file and 256 MiB total bounds. Complete record header/body checks precede counting. PCAP byte order/timestamp scale are independent of network-order IP/transport fields. Malformed tails are not resynchronized heuristically.

Header parsing supports Ethernet/raw IP, two VLAN tags, IPv4 and bounded IPv6 extensions. Fragments/unsupported protocols are skipped. Directional five-tuples are scoped to evidence; MAC/VLAN identity and session state are not flow keys. At most 10,000 flows and 20 references per flow are retained, with omitted new-flow packets counted separately. Current bounded session/protocol/checksum extensions are documented in [EXAMINATION_WORKFLOWS.md](EXAMINATION_WORKFLOWS.md).

Packet events retain protocol/ports/lengths/flags and source positions. Capture records share a 50,000-unit budget with parsed logs. Correlations preserve packet references. `pcap_share.go` projects allowlisted fields while omitting original errors/unsupported enums. JSON/CSV expose counts; HTML adds coverage/flow tables. See [PCAP_TR.md](PCAP_TR.md) for semantics and format references.


## v0.10 PCAPNG and cooked links

`pcapng.go` walks bounded blocks, resets interface state at section boundaries, validates duplicated lengths and options, and passes Enhanced Packet Block data to the existing IP/transport decoder. Timestamps use per-interface integer scales and signed offsets; unsupported ranges are recorded as skips. Untimed/obsolete packet blocks are validated and counted without events. Uninterpreted metadata blocks are counted without exporting their contents.

`CaptureContext` adds section/interface provenance to events, flows and references. The shared flow accumulator groups by that context and directional tuple; classic PCAP keeps its previous grouping. SLL/SLL2 only change the link-header decoder. Shared models explicitly retain numeric context and aggregate counts while excluding interface metadata. New CSV columns are appended. Resource limits, format sources and compatibility are documented in `PCAPNG.md`.

## Platform triage artifacts (0.14.0)

`artifacts.go` lists Linux, Windows and macOS collection targets. Browser history discovery adds Chrome, Chromium, Edge and Firefox history files that exist and skips credential databases. `platform_parse.go` extracts Task Scheduler commands, XML launchd agents, systemd `ExecStart` lines and Prefetch executable names. Those events use timeline types `scheduled_task`, `launch_agent`, `systemd_exec` and `prefetch`. `activity.go` then interprets SSH, sudo, cron, shell history and selected Windows event IDs into `activity.csv`. Shared reports do not copy activity rows. Shared reports keep the type as `other` and omit the command text. See [ARTIFACTS.md](ARTIFACTS.md).

## Case examination (0.14.0)

`case.go` verifies every discovered collection and writes `k957-case/1`. The dossier lists duplicate SHA-256 groups, examiner hash-set matches, magic-byte extension mismatches and collection boundaries. Inventory, timeline and a Sleuth Kit body file are separate CSV/text outputs. The dossier is derived and unsigned; the collection signature remains the evidence binding. `collector_sha256` on `k957-collection/1` is the SHA-256 of the executable and is covered by `collection.sig`. Records produced by 0.13.0 remain acceptable. Resume checkpoints still require the producing version.

Analysis classifies the first 560 bytes of each object (`filetypes.csv`) and can apply a `k957-hashset/1` or line-oriented SHA-256 set. `known-bad` adds an unreviewed finding. `known-good` does not. `bodyfile.txt` exports mtime only. See [CASE.md](CASE.md).

## Full-mode store and physical memory (0.13.0)

`k957 collect` with no arguments writes `output/<hostname>/<UTC timestamp>/`. `collection.json` (`k957-collection/1`) binds the signed evidence package, the optional LiME image and `memory.json` (`k957-memory/1`). `collection.sig` is a raw 64-byte Ed25519 signature over the exact record bytes. `SHA256SUMS` covers every file except itself and the later `reports/` directory. A generated private key is discarded; the printed fingerprint is the external note. Embedded `signing.pub` shows internal consistency, not an independent trust anchor.

Linux memory acquisition reads `/proc/kcore` through `/proc/iomem` `System RAM` ranges and writes LiME v1 (magic `0x4C694D45`). Unreadable pages are zero-filled and counted. The image is hashed while written and is not modified. Analysis streams LiME or raw images for literal rules, a kernel banner and URL indicators, and prints Volatility 3 commands. It does not reconstruct kernel objects. See [MEMORY.md](MEMORY.md).

## Windows event XML exports (0.12.0)

`windows_xml.go` decodes UTF-8/BOM-marked UTF-16 with sparse original-byte offset anchors, then uses a strict bounded token stream and one bounded per-event tree. Only direct namespace-qualified System/EventData/rendering fields are projected. Semantic record failures are counted and skipped; malformed structure stops the file while retaining completed events. No provider code, external XML resources or native EVTX parsing is involved. `windows_xml_export.go` adds a formula-safe CSV and the full HTML report exposes metadata, ordered values and omission flags. The separately typed shared projection carries only existing event fields and parser counts; Windows context is never copied. Exact semantics, limits and primary format references are in [WINDOWS_EVENT_XML.md](WINDOWS_EVENT_XML.md).
