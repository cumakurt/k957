# k957 architecture and evidence format v1

## Modules

One statically built Go CLI exposes separate Collect and Analyze workflows. No network service, telemetry, auto-update, persistence agent, or inbound listener is installed. OS helpers run only when --system is explicitly requested. A local HTML report requires no server. The source is a modular monolith using Go standard packages only.

Collect: explicit directory -> bounded regular-file traversal -> ZIP object writer + SHA-256 -> manifest -> optional Ed25519 signature -> fsync/close.
Analyze: archive structural checks -> manifest validation -> every object's SHA-256 -> optional trusted-key signature -> bounded text/log decoding -> literal/hash rules -> provenance-bearing results -> HTML/JSON/CSV.

## Container

A `.k957` file is a standard ZIP with `manifest.json`, optional raw 64-byte `manifest.sig`, and `objects/E000001` entries. Payload paths never derive from hostile source paths. Analyze does not extract the archive. Each manifest object records original path, bytes, hash, kind, modification time, collection time, mode string, and detected change flag. Manifest includes collector version, host, OS/architecture, case, scope, operator, start/end, complete/partial status, and issues.

Ed25519 signs the exact stored manifest bytes including trailing newline. Private key file is hex encoding of a 64-byte Go Ed25519 private key. Public key file is 32-byte hex. No embedded public key is implicitly trusted. Verification rejects duplicate archive names, unlisted entries, missing entries, duplicate IDs, wrong hashes/sizes, invalid signatures, unknown schema, unknown manifest fields, and trailing JSON. Current ceilings: 100002 archive entries, 16 MiB manifest, 64 GiB per object, 1 TiB cumulative object bytes. These are resource ceilings, not validated production acquisition sizes.

SHA-256 is over bytes actually acquired. Metadata and data can change during acquisition. Before/open identity checks and after-copy size/mtime checks detect some races, not all. Ancestor-path replacement, hostile kernel behavior, unchanged-size/mtime manipulation, or remote filesystem inconsistency are not prevented. A read from a blocking network filesystem might not promptly honor cancellation. Select stable, trusted input or independently acquired images. The output must be outside the logical source tree; source/output physical volume separation is not enforced.

## Encryption envelope

Magic `K957ENC1` (8 bytes), random 8-byte prefix, frames of big-endian uint32 ciphertext length + ciphertext. AES-256-GCM nonce = prefix || uint32 frame index. AAD = full 16-byte header. Plaintext per frame <= 1 MiB. Final empty plaintext frame is mandatory, authenticated, and must be followed by EOF. Frames cannot be modified, removed, reordered or appended without rejection, subject to cryptographic assumptions. An index overflow is rejected. Use a fresh random key per case; there is no password KDF. Decryption failures remove the newly created destination on a best-effort basis. The format is versioned but has not undergone independent cryptographic audit.

## Trust and disclosure

Tool-produced signatures attest possession of the signing key, not authenticity of a compromised host. Separate trust anchor distribution is required. Live commands resolve through the local executable environment (absolute paths on macOS where defined); a compromised PATH or substituted OS helper may falsify data. No kernel bypass is attempted. Key files are not automatically zeroized or backed by hardware. Command outputs may include personal information and command-line secrets within the explicitly selected system snapshot scope.

HTML uses html/template contextual escaping; CSV formula prefixes are escaped. The report's own search JavaScript is static and executes only locally. No evidence scripts are executed. Parsers are bounded but currently run in-process, not an OS sandbox. Analyze reopens object streams after verification; concurrent mutation of the underlying package is outside the trust model. Keep input on read-only/trusted storage during analysis. Reports are derived outputs, not signed evidence packages.

## Source provenance

Finding -> evidence ID -> manifest item -> exact original source and hash. A text finding also includes the original line number. Log events preserve the original timestamp string and parsed UTC. There is no source byte offset for structured binary artifacts because those parsers are not implemented. Run ID and creation time vary between analyses; substantive results are deterministic for fixed source, rules and implementation, apart from documented size limits.


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

## v0.6 edinim ön kontrolü

`preflight.go`, `planWork` metadata envanterini kullanarak içerik okumadan aday sayısını/boyutunu hesaplar. OS'e özel `probeVolume` uygulanır (Linux/macOS statfs+device, Windows caller-available bytes+volume GUID). Çıktı/çalışma talepleri dosya sistemi kimliğine göre gruplanır, en düşük boş alan örneği ve bir rezervle karşılaştırılır. Envanter sorunları warning, ölçülemeyen kimlik/kapasite unknown, çakışma veya yetersiz tahmini kapasite blocked üretir. Sonuç üstünlük sırası blocked > unknown > warning > pass.

Bu katman yer ayırmaz, envanteri kalıcılaştırmaz, anahtar/izin kontrolü yapmaz ve fiziksel disk ayrımını ispatlamaz. Kapasite tahmini bir planlama payıdır, üst sınır değildir. `collect --check-space` unknown/blocked durumunda yazmaya başlamaz; yalnızca yeni, sistem snapshot içermeyen mantıksal edinimler desteklenir. Ayrıntılar `PREFLIGHT_TR.md`.

## v0.7 imzalı muhafaza beyanları

`custody.go`, delil manifestinin tam byte hash'ine, vaka ve paket kimliğine bağlı ayrı bir kayıt tutar. Her olay ayrı imzalıdır; yeni olay eklemek eski imzaları değiştirmez. Tam imzalanan byte dizisi Base64 ile saklanır; kripto için JSON kanonikleştirme varsayımı yoktur. İmza ve olay hash'i farklı domain önekleri kullanır. Payload; sıra, önceki hash, imzacı parmak izi, taraflar, işlem ve beyan/kayıt zamanlarını içerir.

Harici güven listesi her açık anahtarı tek actor adına bağlar. Tüm geçmiş listeye göre doğrulanır. Register mevcut sorumluyu başlatır; transfer bekleyen alıcıyı belirler; accept alıcının imzasıyla sorumluyu değiştirir. Cancel ve note mevcut sorumlu tarafından kullanılabilir. Zamanların geriye gitmesi reddedilir; güvenilir zaman kaynağı yoktur. Beklenen bağımsız head olmadan geçerli bir geçmiş önekinin eski sürüm olduğu tespit edilemez.

İmzalar fiziksel teslimi veya gerçek kişi kimliğini kanıtlamaz. Delil bağı ZIP taşıyıcısının tamamına değil, doğrulanmış manifest ve onun nesne özetlerine aittir. Güven listesi/rakam/sıra/imza doğrulaması ayrı katmanlardır. JSON boyut/derinlik sınırları, yinelenen anahtar ve bilinmeyen alan reddi uygulanır. CLI önce paketi `Open` ile doğrular, sonra kaydı uygular. Ayrıntılı format ve sınırlar `CUSTODY_TR.md` içindedir.

## v0.8 paylaşım görünümü

`share.go`, taze doğrulanmış analizden ayrı `k957-shared-report/1` veri modeli üretir. Özgün Analysis/Manifest değiştirilip serileştirilmez; izin verilen alanlar tek tek kopyalanır. Serbest metin, özgün ID/hash/imza ve kimlik eşleme sözlüğü çıkış şemasında yoktur. Enum alanları izin listesine göre aktarılır; bilinmeyen değerler other olur. Kaynak zamanları nullable alanlara dönüştürülür ve varsayılan çıkarılır. Rapor oluşturma zamanı ayrı bir alan olarak korunur.

Takma adlar kategori ve tam değer temelinde rapor içinde tutarlıdır. Açık bırakılan kaynak metinleri, bilinen kapalı kategori değerleri ve kullanıcı literalleriyle Go regexp üzerinden tek geçişte değiştirilir; özel karakterler quote edilir, harf duyarsız uzun eşleşme seçilir. Sayı/kalıp karmaşıklığı limitinde kapalı hata verilir. Varsayılan tam maskeleme bu eşleştiriciyi gerektirmez. HTML/CSV/JSON yalnızca paylaşım modelini alır.

`share` CLI paket, review ve custody kontrollerini normal analiz akışıyla tamamlayıp projeksiyonu uygular. Paylaşım JSON'u normal `LoadAnalysis` tarafından kabul edilmez. Geri eşleme, kaynak kimliği ve dijital imza doğrulaması için özgün dosyalar ayrı tutulur. Sayılar/sıralama/ilişkiler kalır; anonimlik garantisi yoktur. Ayrıntılar `SHARING_TR.md`.

## v0.9 klasik PCAP

`pcap.go`, ZIP nesnesi üzerinde isim veya dört magic byte ile aday tespiti yapar. Ayrı 64 MiB dosya / 256 MiB toplam okuma sınırı uygulanır. Record başlığı/gövdesi sınırları doğrulandıktan sonra paket sayacı artar. PCAP endian ve zaman ölçeği ayrı seçilir; IP/taşıma alanları network byte order ile okunur. Yanlış uzunlukta kalan dosya tahmin edilerek taranmaz.

Header walker Ethernet/raw IP, en fazla iki VLAN, IPv4 ve sınırlı IPv6 uzantılarını destekler. Fragment ve bilinmeyen protokol atlanır. Payload referansı/içeriği dışa aktarılmaz. Akış anahtarı yönlü beşlidir ve delil nesnesi bazındadır; MAC/VLAN kimliği veya oturum durumu anahtar değildir. 10.000 akış ve 20 örnek referans sınırı vardır; fazla yeni akış paketleri ayrıca sayılır.

Paket olayları ayrı packet/protocol/port/length/flag alanları taşır. PCAP kayıtları log olaylarıyla ortak 50.000 bütçeyi tüketir. IP korelasyonu paket referansını da korur. `pcap_share.go` yeni alanları ayrı paylaşım tiplerine projekte eder; hata metinleri ve bilinmeyen enum değerleri kopyalanmaz. JSON ve CSV temel sayaçları, HTML kapsam/akış tablosunu gösterir. Ayrıntılı semantik ve birincil biçim kaynakları `PCAP_TR.md`.


## v0.10 PCAPNG and cooked links

`pcapng.go` walks bounded blocks, resets interface state at section boundaries, validates duplicated lengths and options, and passes Enhanced Packet Block data to the existing IP/transport decoder. Timestamps use per-interface integer scales and signed offsets; unsupported ranges are recorded as skips. Untimed/obsolete packet blocks are validated and counted without events. Uninterpreted metadata blocks are counted without exporting their contents.

`CaptureContext` adds section/interface provenance to events, flows and references. The shared flow accumulator groups by that context and directional tuple; classic PCAP keeps its previous grouping. SLL/SLL2 only change the link-header decoder. Shared models explicitly retain numeric context and aggregate counts while excluding interface metadata. New CSV columns are appended. Resource limits, format sources and compatibility are documented in `PCAPNG.md`.

## Windows event XML exports (0.12.0)

`windows_xml.go` decodes UTF-8/BOM-marked UTF-16 with sparse original-byte offset anchors, then uses a strict bounded token stream and one bounded per-event tree. Only direct namespace-qualified System/EventData/rendering fields are projected. Semantic record failures are counted and skipped; malformed structure stops the file while retaining completed events. No provider code, external XML resources or native EVTX parsing is involved. `windows_xml_export.go` adds a formula-safe CSV and the full HTML report exposes metadata, ordered values and omission flags. The separately typed shared projection carries only existing event fields and parser counts; Windows context is never copied. Exact semantics, limits and primary format references are in [WINDOWS_EVENT_XML.md](WINDOWS_EVENT_XML.md).
