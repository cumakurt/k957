# Ürün planı izlenebilirliği ve kalan geliştirme

Bu sürüm önceki planı bütünüyle tamamladığı iddiasında değildir. Aşağıdaki tablo mevcut kodun gerçek kapsamını gösterir; boş adaptörler veya örnekler tamamlanmış özellik sayılmaz.

| Plan alanı | 0.12.0 durumu | Sonraki kabul koşulu |
|---|---|---|
| Go, USB, OS/mimari binary | Uygulandı; 6 hedef derlendi | Her OS/mimaride gerçek cihaz testi, imzalama |
| Collect/Analyze ayrımı | Ayrı komutlar ve çekirdek iş akışları | Bağımsız modül dağıtımı, sürüm uyumluluğu |
| Türkçe kullanıcı akışı | CLI sihirbaz ve rapor | Erişilebilir masaüstü/web vaka arayüzü |
| Mantıksal dosya toplama | Uygulandı | ACL/xattr/ADS, dosya kimliği, snapshot tutarlılığı |
| Edinim ön kontrolü | Fresh/frozen resume inventory, remaining staging space, full output and per-filesystem reserves | Physical device separation and native OS/device validation |
| Canlı triyaj | Sınırlı OS yardımcı komutları | 25–40 doğrulanmış artefakt ve cihaz matrisi |
| Fiziksel disk/RAM | Uygulanmadı | İmzalı platform edinim yardımcıları, referans imaj karşılaştırmaları |
| Windows event exports / EVTX / Registry / MFT / USN | Bounded Windows event XML analysis; native binary formats pending | Native format parsers, real exports and OS/version reference tests |
| Linux journal/audit, macOS Unified Logs | Metin dışa aktarımları yalnızca genel log parserıyla | Yerel format ve sürüm testleri |
| Tarayıcı, e-posta, mesajlaşma | Native veritabanı ayrıştırma yok | SQLite WAL tutarlılığı, uygulama sürüm matrisi |
| Bulut/SaaS | Uygulanmadı | Sağlayıcı API, yetki kapsamı, pagination/rate limit testleri |
| Mobil/NAS/IoT | Uygulanmadı | Belgelenmiş yetkili edinim/dışa aktarım adaptörleri |
| Container/VM/ağ | Logical copies; PCAP/PCAPNG TCP/UDP headers and flows; Linux SLL/SLL2 | Session/payload analysis, runtime/API and snapshot analysis |
| SHA-256 ve imza | Uygulandı | Dış anahtar yönetimi, donanım imza desteği |
| Şifreleme | Şifreli checkpoint/parçalar, akış halinde şifreli final çıktı ve sonradan seal | Alıcı açık anahtarı, donanım anahtarı, bağımsız kripto denetimi |
| Muhafaza zinciri | Kişi başına imzalı olaylar, teslim alma onayı, harici güven listesi, bağımsız son kayıt özeti kontrolü | Güvenilir zaman damgası, merkezi değişmez kayıt, anahtar iptal/yetki politikası |
| Kesinti ve sürdürme | 8 MiB parçalar, checkpoint, prefix doğrulama, edinim dönemleri uygulandı | Fiziksel USB/güç kesintisi ve diğer OS testleri |
| Metadata/zaman çizelgesi | Uygulandı; RFC3339 ve JSONL | Clock skew belirsizliği, binary artefakt zaman semantiği |
| Kurallar | Düz metin/SHA-256 | Sigma/YARA eşleme, test kümesi ve lisans kontrolleri |
| Korelasyon/varlık grafiği | Yapılandırılmış kayıtlarda ortak kullanıcı/cihaz/IP; kaynak referansları | Kimlik çözümleme, zaman pencereli ilişkiler ve görsel grafik |
| RAM analiz motoru | Uygulanmadı | İzole Volatility işçisi, sembol paketleri |
| Silinmiş veri/carving | Uygulanmadı | Referans diskler, yanlış pozitif değerlendirmesi |
| Analist notu/onayı | CLI ile karar/gerekçe, sürümlenmiş ve opsiyonel imzalı geçmiş | Rol yönetimi, GUI, bağımsız ikinci onay |
| Rapor | HTML/JSON/CSV; ayrı maskeli paylaşım, politika ve tarayıcıdan PDF | Native PDF/DOCX, gelişmiş şablonlar ve kontrollü metin maskeleme |
| AI yardımcısı | Uygulanmadı | Kaynak zorunluluğu, yerel model, veri aktarım politikası |
| Parser izolasyonu | Kaynak sınırları var, süreç izolasyonu yok | Ayrı düşük yetkili işçiler ve sandbox testleri |
| Kurumsal ölçek | Uygulanmadı | İndeks/depolama, RBAC, çok kullanıcı ve görev kuyruğu |

## 0.12.0 analysis progress

Windows event XML exports retain System metadata, timestamps, ordered Data fields and original encoded byte positions. Full reports expose parse skips and unsupported payloads; shared reports exclude Windows-specific context. See [WINDOWS_EVENT_XML.md](WINDOWS_EVENT_XML.md). Native EVTX parsing and native Windows export validation remain pending.

## 0.11.0 acquisition progress

Read-only resume preflight and gated plain/encrypted recovery are implemented and validated with partial and completed frozen inventories. Capacity boundaries, unchanged checkpoints, lock/option/source/chunk failures and process-termination recovery are covered. See [RESUME_PREFLIGHT.md](RESUME_PREFLIGHT.md).

## 0.10.1 platform progress

Windows collection identity and checkpoint reader conflicts are fixed. All unit tests and 11 integration scripts pass on native Linux AMD64 and under Wine 10.0 for Windows AMD64. Six-target CI and reusable validation receipts are implemented. Native Windows/macOS and ARM64 execution remain pending; see [PLATFORM_TESTING.md](PLATFORM_TESTING.md).

## Sonraki kilometre taşları

1. **Platform doğrulama:** Windows/macOS gerçek cihazları; unsigned binary dağıtımını imzalı sürümlere dönüştürme; USB uygulama denetimi ve izin senaryoları. Kritik alan: kaynağın sürekli değiştiği ortamlar ve okuma hataları.
2. **Edinim dayanıklılığı:** Atomik parça nesneleri, checkpoint, kapasite tahmini, dosya sistemi kimliği ve şifreli yazma uygulandı. Remaining resume space and distinct work/chunk filesystem budgets are implemented in 0.11.0. Physical device identity remains pending. Süreç kesintisi sonrası resume test edildi; fiziksel güç/USB kesintisi doğrulaması henüz yoktur.
3. **Artefakt sürümü:** EVTX/Registry, SQLite tarayıcı profilleri, Linux journal ve macOS native kayıtları için ayrı parser motorları; bozuk girdi fuzzing ve referans sonuç karşılaştırması.
4. **İnceleme deneyimi:** Vaka yönetimi, analist notları, açıklanabilir korelasyon ve ilişki grafiği; arama indeksi; PDF/DOCX rapor motoru.
5. **Özel kaynaklar:** RAM/disk yardımcıları, bulut API'leri, VM/container/mobil dışa aktarımları. Her biri kendi yetki, lisans ve doğrulama çalışmasını gerektirir.
6. **Kurumsal sürüm:** İmzalı teslim zinciri, donanım anahtarları, rol yönetimi, dağıtık işçiler ve ancak kaynak izlenebilirliği hazır olduktan sonra AI.

Önceki 6–8 ay ilk ürün, 12–18+ ay geniş platform tahminleri bu kilometre taşları içindi; bir oturumda tamamlandığı ileri sürülmez. Ön sürümün geliştirilmesi bu takvimin yerini almaz.
