# Değişiklikler

## 0.12.0

- Added bounded Windows event XML export analysis for UTF-8 and BOM-marked UTF-16 LE/BE, including event fragments and Events wrappers.
- Retained provider/event/record identifiers, explicit-zone timestamps, host/SID fields, ordered EventData values and original encoded byte provenance.
- Added per-record skip reasons, partial-prefix recovery, strict numeric/time validation and XML resource bounds; external resources and DTDs are rejected.
- Added Windows event JSON/CSV/HTML reporting with escaping, omission flags and existing host/SID correlations.
- Kept Windows-specific metadata/messages/data out of shared reports, including explicit keep policies.
- Added independent XML/CLI integration, malformed-input fuzzing and regression coverage. Binary EVTX parsing remains unimplemented; see `docs/WINDOWS_EVENT_XML.md`.
- Evidence schemas remain readable; older checkpoints/reviews still require their producing version.

## 0.11.0

- Added read-only `preflight --resume` planning from a frozen checkpoint, including authenticated encrypted checkpoints with the original key.
- Added `collect --resume --check-space`, retaining the collector's source-prefix and chunk integrity verification.
- Reported saved logical bytes, remaining bytes/parts and completed files; staging estimates exclude already recorded bytes while budgeting the final package in full.
- Accounted separately for existing work/chunk mount points, combining shared filesystem needs and applying one reserve per target filesystem.
- Blocked locked work, mismatched options, unavailable/wrong-size chunks, changed incomplete source metadata and exhausted acquisition epochs.
- Extended independent plain/encrypted process-termination tests and completed-work reuse checks; corrected test capacity probes for symlinked temporary directory roots.
- Checkpoint/review version binding remains unchanged. Finish older work with its original binary; earlier evidence schemas remain readable. See `docs/RESUME_PREFLIGHT.md`.

## 0.10.1

- Fixed unchanged Windows source files being skipped: source identity checks now use `os.Lstat` metadata instead of directory enumeration metadata.
- Windows checkpoint replacement retries brief sharing/access conflicts for up to one second. Persistent failures return an error and preserve the previous checkpoint.
- Added collection coverage for Unicode/nested/empty files and checkpoint reader conflicts, including preservation after failed replacement.
- All 11 independent integration scripts select the native executable, use explicit UTF-8 and support Windows process termination and capacity checks.
- Added one validation command with per-step logs, environment identification and a JSON receipt, plus a six-target GitHub Actions workflow.
- Evidence v1/v2 remains readable. Existing checkpoints and signed reviews remain version-bound; use the original producing binary for earlier work directories. See `docs/PLATFORM_TESTING.md` for compatibility and actual execution status.

## 0.10.0

- Bounded PCAPNG section/interface/enhanced-packet parsing with mixed byte orders.
- Per-interface decimal/binary timestamps, signed offsets and nanosecond flooring.
- Linux SLL/SLL2 headers in classic PCAP and PCAPNG.
- Separate flow groups and source references for each PCAPNG section/interface.
- Strict framing checks, packet skip reasons and ignored metadata block counts.
- Section/interface provenance and counters in full and masked HTML/JSON/CSV reports.
- Independent Python CLI integration and a dedicated malformed-input fuzz target.
- Evidence v1/v2 compatibility is preserved. Version-bound 0.9.0 checkpoints and review ledgers require the original binary; no migration is performed. See `docs/PCAPNG.md`.

## 0.9.0

- Klasik PCAP v2.4 dört endian/zaman varyantı; Ethernet/raw IPv4/IPv6 TCP/UDP.
- İki VLAN etiketi ve sınırlı IPv6 uzantı yürüyüşü; fragmentleri gerekçeyle atlama.
- Paket sıra/byte referansları, nanosaniye zamanları, portlar ve TCP bayrakları.
- Dosya bazında yönlü beşli akış özetleri, boyut/sayaç/limit raporu.
- PCAP ve log IP ortaklıkları; normal ve maskelenmiş HTML/JSON/CSV desteği.
- PCAPNG ve desteklenmeyen link metadata için açık hata; payload çözümleme yok.
- Bağımsız Python fixture/kayıt doğrulaması ve 153.041 girdilik kısa fuzz testi.

## 0.8.0

- `share`: ayrı ve daraltılmış şemadan HTML/JSON/CSV paylaşım raporu.
- Varsayılan vaka/kişi/cihaz/IP/yol/konum takma değerleri; kaynak zamanlarını çıkarma.
- Serbest metinleri, özgün kimlik/hash/imzaları ve geri eşlemeyi paylaşım çıktısından çıkarma.
- keep kategorileri ve literal ifadeleri için katı politika dosyası.
- Açık bırakılan alanlarda bilinen kapalı değerleri de maskeleme; uzun eşleşme önceliği.
- Doğrulanmış analist/devir geçmişinin maskelenmiş özeti; tüm çıktı dosyalarında sızıntı testleri.
- Güncel altı binary, örnek paylaşım raporları ve kapsamlı Türkçe kullanım belgesi.

## 0.7.0

- Her olayı ayrı Ed25519 imzasıyla koruyan `custody` ve `custody-verify`.
- register/transfer/accept/cancel/note; teslim alan onayına kadar bekleyen devir.
- Harici kişi/anahtar güven listesi ve kimlik eşleşmesi kontrolü.
- Manifest/vaka/paket kimliği bağı; önceki olay özeti, sıra ve zaman tutarlılığı.
- Bağımsız son kayıt özetiyle eski sürüme dönüş kontrolü.
- HTML/JSON devir geçmişi ve `custody.csv`; önceki imzaları koruyan yeni dosyalar.
- Yinelenen JSON anahtarları ve belirsiz alan adları reddi; bağımsız Python imza/hash doğrulaması.

## 0.6.0

- Salt metadata envanteri ve JSON raporuyla `preflight`.
- Kaynak/çıktı/çalışma yolu çakışmaları, var olan hedef ve dosya limitleri kontrolü.
- OS boş alan sorgusu; aynı dosya sistemindeki çalışma + çıktı için birleşik bütçe.
- Şifreli mod ek yükü, dosya sistemi başına rezerv ve pass/warning/unknown/blocked sonuçları.
- Yeni mantıksal edinimde `collect --check-space`; bilinmeyen/yetersiz kapasitede durdurma.
- Denetimli kapasite testleri, Linux native entegrasyon testi ve güncellenmiş altı binary.

## 0.5.0

- `collect --work --encryption-key`: AES-256-GCM checkpoint ve parça deposu.
- Amaç ayrımlı anahtarlar, HMAC parça adları, her blob için rastgele nonce.
- Final ZIP verisini düz ara dosya oluşturmadan taşıma zarfına şifreleme.
- Şifreli work-status, aynı anahtarla resume, yanlış anahtar/mod ve bozuk ciphertext reddi.
- Şifreli modda özet stdout; tam manifest yalnızca paket içinde.
- 192 MiB SIGKILL/yeniden başlatma, bağımsız kripto doğrulama ve çıktı hatası testleri.

## 0.4.0

- UTF-8 CSV/JSONL için açık şemalı olay ayrıştırma; çok satırlı CSV ve saat dilimi dönüşümü.
- Kaynak fiziksel satırı ve byte konumu; okunan/ayrıştırılan/atlanan kayıt özetleri.
- Kullanıcı, cihaz ve IP alanları; en az iki delilde ortak değerlerin kaynak bağlantılı listesi.
- Sınırlı varlık indeksi, referans listesi ve `correlations.csv`.
- Çelişen/tekrarlanan alanları, yanlış IP ve bozuk kayıtları gizlemeden reddetme.
- Parser fuzz ve bağımsız CLI entegrasyon testleri.

## 0.3.0

- Tekrarlanabilir bulgu kimlikleri ve sürüm/delil/kural/sonuç dayanağına bağlı analist değerlendirmeleri.
- `review`: confirmed/rejected/needs-review, zorunlu analist/gerekçe, yeni dosyada önceki kararları koruma.
- Opsiyonel Ed25519 imzası; imzalı geçmişe eklemede önceki imza doğrulaması.
- `analyze --reviews --review-key`: delili yeniden doğrulayıp analizi tekrar üreterek kararları uygulama.
- HTML/JSON karar geçmişi ve `findings.csv`.
- Değiştirilmiş geçmiş, yanlış dayanak, yanlış anahtar ve rapor enjeksiyonu testleri.

## 0.2.0

- `collect --work` ile 8 MiB parçalara dayanan, checkpoint saklayan mantıksal toplama.
- `--resume` ile aynı vaka/kapsam/envanter/limitler üzerinde devam.
- Tamamlanan parçaların ve dosyaların hash kontrolü; yarım dosyanın kaynaktaki ön bölümünün yeniden hash kontrolü.
- İşlem kilidi, kaynak/çalışma/çıktı ağacı ayrımı, çalışma dosyalarında symlink ve path kaçışı reddi.
- `work-status --verify-parts` ile salt okunur ilerleme ve bütünlük kontrolü.
- v2 pakette parça aralıkları ve edinim dönemleri; v1 okuma desteği korunur.
- HTML/JSON raporlarda edinim dönemleri ve sabit envanter sınırları.
- SIGKILL kurtarma dahil otomatik testler; altı OS/mimari için yeni binary.

Edinim sırasında şifreleme, fiziksel disk/RAM ve bulut bağlantıları bu sürümün parçası değildir.

## 0.1.0

İlk Go çekirdeği: mantıksal toplama, opsiyonel sistem anlık görüntüleri, SHA-256/Ed25519, şifreli taşıma, temel log/kurallar ve HTML/JSON/CSV raporlama.
