# k957 0.12.0 validation

Date: 2026-09-29. Native Linux AMD64 with Go 1.26.8 and Python 3.14.7; Windows AMD64 compatibility execution under Wine 10.0 with Windows Python 3.13.12. Independent cryptography checks use 49.0.0. No third-party Go modules were added.

- All 20 native validation steps passed: formatting, vet, uncached unit tests, coverage reporting, race detection, release build, version and 12 integrations. [Linux receipt and command logs](validation/0.12.0/linux-amd64/validation.json).
- Windows/Wine passed both Go test packages, version and all 12 integrations (15 executed steps). The prebuilt runner explicitly skipped formatting, vet, coverage, race detection and building; the applicable source checks ran on Linux. [Windows/Wine receipt and command logs](validation/0.12.0/windows-amd64-wine/validation.json). Wine emitted environment/process-termination diagnostics; the tests still completed with successful exits and independent content checks.
- New XML tests cover UTF-8/BOM and both UTF-16 byte orders, declarations, CRLF/surrogate-pair source byte positions, namespace prefixes, ordered duplicate Data names, 64-bit record IDs, UTC normalization, semantic skips, malformed-tail recovery, DTD/entity rejection and record/token/depth/node/text/attribute bounds. Exhausted timeline capacity preserves decoded text for independent literal rules.
- The new CLI integration compares fields against Python's XML parser on fixed synthetic fixtures, checks cross-evidence host/SID correlation and CSV/HTML escaping, scans all shared artifacts for private metadata/messages/data, and verifies unchanged evidence and source bytes. [Linux XML integration](validation/0.12.0/linux-amd64/windows_xml_integration.log), [Windows/Wine XML integration](validation/0.12.0/windows-amd64-wine/windows_xml_integration.log).
- The first Windows XML integration exposed a test-fixture error: Python text output translated LF to CRLF while the expected byte offset assumed LF. The fixture now writes explicit CRLF bytes and derives the expected offset from that byte prefix. Both complete platform suites passed after this correction. The [initial failure log](validation/0.12.0/windows-xml-fixture-before-fix.log) is retained; it is superseded by the passing final receipts.
- The final `FuzzWindowsXML` smoke campaign ran with two workers for approximately 16 seconds and executed 235,035 inputs without failure. [Fuzz log](validation/0.12.0/windows-xml-fuzz.log). This short campaign is not exhaustive validation.
- All six release executables built, with ELF, PE and Mach-O formats checked. Additional Windows AMD64/ARM64, Linux ARM64 and both macOS test packages compiled. Windows AMD64 tests then executed under Wine; the other cross-compiled test executables were not run. [Compilation log](validation/0.12.0/cross-compile.log), [binary formats](validation/0.12.0/build-formats.log).
- Both Go packages also passed with a symlinked Linux temporary directory, covering a macOS-like path canonicalization convention without claiming macOS execution. [Alias test log](validation/0.12.0/temporary-directory-alias.log).
- Linux statement coverage is 84.3% overall. Windows-specific source is outside this measurement. [Coverage report and retained profile](validation/0.12.0/linux-amd64/coverage.log).
- Legacy v1 and resumable v2 example evidence verified successfully with 0.12.0. Tested Linux and Windows AMD64 executable hashes match their release files and receipts. [Legacy evidence log](validation/0.12.0/legacy-evidence.log).

Native Windows/macOS and ARM64 runtime validation still require an accessible host or connected CI runner; the prepared workflow has not executed. Binary EVTX parsing and validation against real native Windows exports remain pending. Physical USB/power loss, real disk exhaustion, native system snapshot commands and application signing are not established by these tests. Evidence schemas remain readable; older checkpoints/reviews remain bound to their original version. See [WINDOWS_EVENT_XML.md](WINDOWS_EVENT_XML.md) for the feature's exact interpretation and limits.

# Historical k957 0.11.0 validation

Date: 2026-09-29. Native Linux AMD64 with Go 1.26.8 and Python 3.14.7; Windows AMD64 compatibility tests under Wine 10.0 with Windows Python 3.13.12. Independent cryptography tests use 49.0.0. No third-party Go modules were added.

- All 19 native validation steps passed: formatting, vet, uncached unit tests, coverage reporting, race detection, build, version and 11 integrations. [Linux receipt and command logs](validation/0.11.0/linux-amd64/validation.json).
- Windows/Wine: both Go test packages, version and 11 integrations passed. The prebuilt runner explicitly skipped formatting, vet, coverage, race detection and building. [Windows/Wine receipt and command logs](validation/0.11.0/windows-amd64-wine/validation.json). Wine emitted runtime diagnostics around forced process termination; recovery and independent content checks still completed successfully.
- Resume preflight tests cover plain/encrypted remaining-byte budgets, full final-output allowance, exact sufficient/insufficient capacity boundaries, distinct work/chunk filesystems, unknown chunk capacity, frozen completed-source reuse, wrong keys and cancellation. Rejections cover locks, changed incomplete sources, unavailable/wrong-size chunks, mismatched options, existing outputs and exhausted epoch capacity; saved work remains unchanged by preflight.
- Both 192 MiB process-termination integrations now inspect the locked checkpoint, validate remaining-space counts after confirmed process exit, then resume with `--check-space`. Chunk hashes, source equality, acquisition epochs and encrypted staging verification pass.
- A same-size staged-content mutation deliberately passes metadata-only preflight and is rejected by actual resume integrity verification. Preflight does not replace content verification.
- Tests with a symlinked temporary root reproduced and fixed a canonical-path assumption in the test volume provider. Both Go packages pass with the aliased temporary directory. [Alias test log](validation/0.11.0/temporary-directory-alias.log). This is a Linux portability check, not execution on macOS.
- All six release binaries built. Additional Linux ARM64, Windows ARM64 and both macOS test binaries compiled for both Go packages without being executed. [Compilation log](validation/0.11.0/cross-compile.log), [binary formats](validation/0.11.0/build-formats.log).
- Linux statement coverage is 83.0% overall; the profile and function report are retained with the [coverage log](validation/0.11.0/linux-amd64/coverage.log). Windows-specific code is excluded from that measurement.

Native Windows/macOS and ARM64 runtime validation still require an accessible host or CI runner; the prepared hosted workflow has not been run. Physical USB/power loss, real disk exhaustion, system snapshot commands on Windows/macOS and application signing remain untested. Older evidence schemas remain readable; checkpoints and review histories remain version-bound. See [RESUME_PREFLIGHT.md](RESUME_PREFLIGHT.md) for exact behavior and compatibility.

# Historical k957 0.10.1 validation

Date: 2026-09-28. Native host: Linux AMD64, Go 1.26.8, Python 3.14.7, GCC available. Windows compatibility environment: Wine 10.0 with Windows Python 3.13.12 and cross-compiled Go test executables. The independent cryptography package is 49.0.0; no third-party Go modules were added.

- Native Linux: all 18 validation steps passed, including formatting, vet, uncached unit tests, race detection, release build, version and all 11 integrations. [Receipt and command logs](validation/0.10.1/linux-amd64/validation.json).
- Windows AMD64 under Wine: both Go test packages, version and all 11 integrations passed. Formatting, vet, race detection and building were explicitly skipped in the prebuilt Windows runner; they ran separately on Linux. [Receipt and command logs](validation/0.10.1/windows-amd64-wine/validation.json).
- Both process-termination/restart integrations passed on each executed environment, using 192 MiB fixtures and independently checking staged/final content. This is process termination, not physical USB or power-loss testing.
- Regression tests cover unchanged Windows files, Unicode/nested/empty paths, temporary checkpoint readers, and persistent Windows replacement conflicts preserving the previous checkpoint and cleaning temporary files. Before the fixes, Windows collection rejected unchanged files and plaintext checkpoint polling caused `Access denied` on replacement.
- All six release executables built. The additional Linux ARM64, Windows ARM64 and macOS Intel/Apple Silicon test executables compiled for both packages; these executables were not run. [Compilation log](validation/0.10.1/cross-compile.log).
- ELF/PE/Mach-O formats were checked. The Linux and Windows AMD64 release executable hashes match their validation receipts; both report version 0.10.1.
- Linux statement coverage: CLI 76.2%, core 83.4%, total 82.7%. [Function coverage](validation/0.10.1/linux-amd64/coverage.txt). Windows-specific code is excluded from this Linux coverage measurement.
- The six-target GitHub Actions workflow passed `actionlint` v1.7.12. [Lint log](validation/0.10.1/workflow-lint.log). The workflow has not been executed on hosted runners.

Native Windows and macOS runtime tests remain unperformed: no accessible unlocked Windows test guest or macOS/CI executor was available. Wine results do not establish native OS, ACL, device or USB behavior. ARM64 runtime, system snapshot commands on Windows/macOS, application signing/notarization, physical interruptions and browser visual checks remain unvalidated. See [PLATFORM_TESTING.md](PLATFORM_TESTING.md) for reproduction and version-bound checkpoint/review compatibility. Older reports below are historical; their platform and feature limitations describe their own versions.

# Historical k957 0.10.0 validation

Date: 2026-09-28. Environment: Linux AMD64, Go 1.26.8, GCC available. No third-party Go modules were added.

- `bash scripts/test.sh`: passed (`go vet ./...` and uncached Go tests).
- `go test -race -coverprofile=/tmp/k957-0.10-coverage.out ./...`: passed; no races reported. Statement coverage: CLI 76.2%, core 83.4%, total 82.7%. Function-level results are in [0.10-coverage.txt](0.10-coverage.txt).
- `gofmt -l` on changed Go files: no output.
- The packaged `legacy-v1.k957` and `demo-resumable.k957` evidence files both passed `verify` with the 0.10.0 binary.
- `bash scripts/build.sh`: all six Linux/Windows/macOS AMD64/ARM64 targets built. ELF/PE/Mach-O formats checked; the native executable reports `k957 0.10.0`.
- All 11 Python integration scripts passed, including the new independent PCAPNG test, classic PCAP regression, encrypted/plain SIGKILL recovery, preflight, analyst reviews, custody, sharing, structured logs and independent cryptographic verification. Command output is in [0.10-integration-output.txt](0.10-integration-output.txt).
- `FuzzPCAPNG`, two workers, 10-second budget: 744,234 executions, passed.
- `FuzzPCAP`, two workers, 10-second budget (about 11 seconds including completion): 410,649 executions, passed.

The new tests cover mixed byte-order sections, per-interface timestamps/offsets, binary timestamp precision, SLL/SLL2 in both containers, distinct interface/section flow groups, source byte offsets, malformed block/option lengths, undefined interfaces, declared section lengths, unsupported packet/metadata handling and resource limits. The Python test checks HTML/CSV/JSON provenance, missing metadata/payload markers in both report types, masked IP/path/time values, and unchanged evidence bytes.

Fuzz campaigns are short smoke tests, not exhaustive validation. Only Linux AMD64 was executed. Windows/macOS/ARM64 device operation, real capture compatibility, visual browser checks and physical USB/power loss were not tested. Older packaged examples and the unprefixed `coverage.out`, `docs/coverage.txt`, `docs/test-output.txt`, `docs/integration-output.txt` and `docs/pcap-fuzz.txt` remain historical 0.9.0 artifacts. Version-bound checkpoints and review ledgers are not migrated; see [PCAPNG.md](PCAPNG.md).

# Historical 0.9.0 test report

Tarih: 28 Eylül 2026. Ortam: kısıtlı Linux AMD64 çalışma ortamı. Derleyici: Go 1.26.1. Çekirdek üçüncü taraf Go modülü kullanmaz.

## Gerçekleştirilen kontroller

| Kontrol | Sonuç |
|---|---|
| `go test -race -coverprofile=coverage.out ./...` | Başarılı; veri yarışı raporlanmadı |
| `go vet ./...` | Başarılı |
| CLI paket statement coverage | %76,2 |
| Core paket statement coverage | %82,4 |
| Toplam statement coverage | %81,7 |
| Native CLI uçtan uca akış | Başarılı |
| Klasik PCAP: iki byte sırası, mikro/nanosaniye zamanı | Başarılı |
| Ethernet, VLAN, raw IP, IPv4/IPv6 TCP/UDP başlıkları | Başarılı |
| Bağımsız Python ile kayıt konumu, zaman ve byte sayaçları | Başarılı |
| Yönlü akışlar, ters yön, sıra dışı zaman ve referans sınırları | Başarılı |
| Eksik payload ile tam başlık / eksik transport başlığı ayrımı | Beklenen kabul/atlama sonuçları |
| Fragment, bozuk kayıt, desteklenmeyen protokol ve PCAPNG | Atlanma/hata nedenleri doğrulandı |
| PCAP kayıt/akış/dosya bütçeleri ve bozuk uzunluklar | Sınırlar doğrulandı |
| Ağ ve log kaynaklarında ortak IP, paket referansları | Başarılı |
| Ağ HTML/JSON/CSV çıktısı ve paylaşımda IP/yol/zaman maskeleme | Başarılı |
| PCAP payload işaretinin bulguya dönüşmemesi ve delilin değişmezliği | Başarılı |
| FuzzPCAP, 2 işçi, yaklaşık 9 saniye | 153.041 yürütme; hata bulunmadı |
| Paylaşım: sekiz çıktı dosyasında 18 hassas değer taraması | Değerler bulunmadı |
| Paylaşım: ham delil, analiz ve imzalı kayıtların değişmezliği | Byte hash'leri aynı |
| Takma değerlerin tablo/ref bağlantıları ve sayıların korunması | Başarılı |
| Açık bırakılan alanlarda çapraz maskeleme, literal ve uzun eşleşme | Başarılı |
| Paylaşım politikası: belirsiz JSON, bilinmeyen kategori ve sınırlar | Reddedildi |
| Bozuk geçmişten paylaşım ve paylaşımdan review üretme | Reddedildi; çıktı oluşturulmadı |
| Paylaşım HTML/CSV içerik kaçışları | Başarılı |
| İki farklı anahtarla register/transfer/accept | Başarılı; eski imzalar korundu |
| Transfer beklerken sorumlu ve kabul sonrası değişim | Doğrulandı |
| İptal, yanlış imzacı ve geçersiz durum geçişleri | Beklenen kabul/ret sonuçları |
| Bağımsız Python ile olay imzası, domain ve hash kontrolü | Başarılı |
| Delil bağı, sıra, olay değiştirme ve yeniden hash'leme | Reddedildi |
| Harici son kayıt özetiyle eski sürüme dönüş | Reddedildi |
| Devir kayıtlarında yinelenen JSON alanı, zaman ve boyut sınırları | Beklenen ret sonuçları |
| Devir HTML/JSON/CSV çıktısı ve içerik kaçışları | Başarılı |
| Ön kontrol: birleşik bütçe ve dosya sistemi başına rezerv | Başarılı; denetimli kapasite değerleri |
| Ön kontrol: kapasite yetersizliği/belirsizliği | blocked/unknown; toplama başlamadı |
| Ön kontrol: mevcut hedef, çakışma, limitler ve iptal | Başarılı |
| Linux native boş alan ve salt metadata planı | Başarılı; kaynak içerikleri aynı, hedef oluşturulmadı |
| Ön kontrol sonrası toplama ve paket doğrulama | Başarılı |
| Şifreli 192 MiB edinimde SIGKILL ve aynı anahtarla devam | Başarılı |
| Python cryptography ile staged checkpoint/parça AES-GCM ve HMAC kontrolü | Başarılı |
| Yanlış anahtar, değiştirilmiş state/chunk ve amaç uyuşmazlığı | Reddedildi |
| Enjekte edilmiş çıktı yazma hatası | Döndürüldü; pipe kilitlenmedi |
| Sentetik düz metin işareti ve kaynak yolu taraması | Şifreli çalışma/çıktı dosyalarında bulunmadı |
| CSV/JSONL alanları, çok satırlı CSV, CRLF ve byte konumları | Başarılı |
| Geçersiz IP, çelişen alan, tekrar JSON anahtarı ve hatalı CSV | Atlanma/hata raporu doğrulandı |
| Üç ortak varlık, farklı delil sayısı ve CSV çıktısı | Başarılı |
| v0.4.0 sırasında FuzzStructuredLogs, yaklaşık 6 saniye | 74.853 yürütme; hata bulunmadı |
| İmzalı iki değerlendirme sürümü ve yeniden analiz | Başarılı |
| Ham delil ve önceki değerlendirme dosyasının değişmemesi | Başarılı |
| Değiştirilmiş geçmiş, yanlış imza anahtarı ve kural dayanağı | Reddedildi |
| Analist notlarında HTML/CSV güvenliği | Otomatik test geçti |
| 192 MiB dosyada SIGKILL ve yeniden başlatma | Başarılı; 24 parça bağımsız doğrulandı |
| Stale lock reddi ve doğrulanmış süreç kapanışı sonrası kurtarma | Başarılı |
| Kayıtlı ön bölümün aynı metadata ile değiştirilmesi | Devam reddedildi |
| Bozuk checkpoint parçası / kaynak değişikliği | Devam reddedildi |
| Edinim dönemleri ve v2 pakette parça hash kontrolü | Başarılı |
| Salt okunur work-status / tamamlanan dosya yeniden kullanımı | Başarılı |
| Python stdlib ile bağımsız ZIP boyut/hash ve kaynak byte karşılaştırması | Başarılı |
| Python cryptography ile bağımsız Ed25519 doğrulaması | Başarılı |
| Python cryptography ile AES-GCM çerçeve çözümü | Başarılı |
| v0.1.0 sırasında FuzzEnvelope, 2 işçi, yaklaşık 5 saniye | 183.868 yürütme, hata bulunmadı |
| v0.1.0 sırasında FuzzRules, 2 işçi, yaklaşık 6 saniye | 9.138 yürütme, hata bulunmadı |
| Altı OS/mimari için cross-compile | Başarılı |
| Binary formatı kontrolü | Linux ELF, Windows PE32+, macOS Mach-O |

v0.9.0 için yeni FuzzPCAP kampanyası çalıştırıldı; sonuçları `pcap-fuzz.txt` içindedir. Kripto/kural sonuçları önceki sürümde değişmemiş kod üzerinde alınan tarihsel sonuçlardır; bu hedefler bu sürümde yeniden fuzz edilmedi. Yapılandırılmış log hedefi v0.4.0 sırasında çalıştırıldı. Kampanyalar kısa duman testleridir; kapsamlı fuzz doğrulaması değildir. Coverage oranı kalite veya doğruluk garantisi değildir. Ayrıntılı final test çıktısı `test-output.txt`, kapsam bilgisi `coverage.txt`, on CLI entegrasyonunun sonuçları `integration-output.txt` içindedir. Son IPv6 uç nokta gösterimi düzenlemesinden sonra tüm Go testleri, race/vet kontrolleri, altı derleme ve PCAP entegrasyonu yeniden başarıyla çalıştırıldı.

Yeni senaryo `python3 scripts/resume_integration.py` ile yeniden çalıştırılabilir. Gerçek bir alt süreç ilk checkpoint sonrasında SIGKILL ile durdurulur; süreç kapanışı doğrulandıktan sonra test kendi stale lock dosyasını kaldırır, devam ettirir ve 24 parçayı Python ile karşılaştırır. Bu, fiziksel güç/USB kesintisi testi değildir.

## Test edilen davranışlar

- Dosya edinimi, imzalı paket açma, HTML/JSON/CSV üretme.
- Delil nesnesi, manifest veya imza değiştirildiğinde reddetme.
- Yanlış güven anahtarı ve imzasız pakete güven anahtarı verilmesi.
- Paket dışı/path traversal isimli ek kayıtların reddi.
- Yinelenen manifest nesnesi reddi.
- Dosya boyutu sınırı, symlink atlama ve kısmi durum kaydı.
- Kaynağın içine çıktı üretme ve var olan dosyayı ezme girişimini engelleme.
- İptal edilmiş toplamanın çıktı bırakmaması.
- AES-GCM için boş veri, küçük veri, tam çerçeve ve çoklu çerçeve.
- Şifreli veride kesilme, değiştirme ve sona veri ekleme reddi.
- Şifre çözme hatasında yeni düz dosyanın kaldırılması.
- HTML delil içeriğinin escape edilmesi; CSV formül başlangıçlarının korunması.
- Geçersiz kurallar, binary metin taraması sınırı, eksik yardımcı komut.
- JSONL/RFC3339 UTC dönüşümü; zaman dilimi olmayan logda tahmin yapılmaması.
- Özel imza anahtarının kaynak kökünde bulunmasının reddi.
- Komut satırından anahtar üretme, toplama, doğrulama, analiz, şifreleme/çözme.

## Platform matrisi

| Platform | Derlendi | Çalıştırıldı |
|---|---|---|
| Linux AMD64 | Evet | Evet, bu kısıtlı ortamda |
| Linux ARM64 | Evet | Hayır |
| Windows AMD64 | Evet | Hayır |
| Windows ARM64 | Evet | Hayır |
| macOS AMD64 | Evet | Hayır |
| macOS ARM64 | Evet | Hayır |

## Gerçekleştirilemeyen veya kapsam dışı kontroller

Fiziksel USB ayırma, güç kesintisi, gerçek disk dolması/bozuk sektör, donanım write blocker, Windows ACL/kurumsal denetim, macOS TCC/notarization, gerçek RAM/disk edinimi, çok terabayt yük, bozuk ağ dosya sistemleri ve bağımsız adli laboratuvar doğrulaması yapılmadı. HTML escaping test edildi; tarayıcı görsel/erişilebilirlik testi yapılmadı. Native sistem yardımcı komutlarının gerçek Windows/macOS çıktıları test edilmedi. Üretim güvenlik denetimi veya NIST sertifikası bulunmaz.

Değerlendirme entegrasyonu: `python3 scripts/review_integration.py`. GUI, çok kullanıcı yetki sistemi ve fiziksel cihaz doğrulaması bu sürümde eklenmedi.

Yeni bağımsız CLI testi: `python3 scripts/structured_integration.py`. 74.853 girdilik fuzz kampanyası kısa bir duman testidir, kapsamlı doğrulama değildir.

Şifreli toplama entegrasyonu: `python3 scripts/encrypted_integration.py` (Python cryptography gerekir). Bilinen sentetik işaretlerin bulunmaması tüm yan kanal/swap/çekirdek sızıntılarının test edildiği anlamına gelmez. Bu sürüm bağımsız üretim güvenlik denetimi değildir.

Ön kontrol entegrasyonu: `python3 scripts/preflight_integration.py`. Alan yetersizliği birim testinde denetimli kapasiteyle üretildi; gerçek disk dolması ve Windows/macOS boş alan API çalıştırma testleri yapılmadı.

Devir entegrasyonu: `python3 scripts/custody_integration.py` (Python cryptography gerekir). İki anahtarlı olay imzaları bağımsız kontrol edildi. Delil paketinin ve eski kayıt dosyalarının byte hashleri değişmedi. Fiziksel devir, gerçek kişi kimliği, anahtar iptal servisi, güvenilir zaman damgası veya merkezi kayıt altyapısı bu testin kapsamı değildir.

Paylaşım entegrasyonu: `python3 scripts/share_integration.py`. İmzalı karar/devir girdileriyle sekiz paylaşım dosyasında 18 bilinen hassas değer tarandı. Bu, gerçek dünya anonimleştirme veya tüm kişisel veriyi tanıma doğrulaması değildir; serbest metinler tamamen çıkarılır. Paylaşım raporunun tarayıcı görsel/erişilebilirlik testi yapılmadı.

PCAP entegrasyonu: `python3 scripts/pcap_integration.py`. Python ile üretilen sentetik kayıtların konumları, zamanları ve uzunlukları bağımsız hesaplandı. Gerçek saha kayıtlarında geniş uyumluluk testi yapılmadı. PCAPNG, canlı paket yakalama, IP fragment birleştirme, TCP oturum yeniden kurma, payload ve checksum analizi desteklenmez. Ağ akışı aynı delildeki yönlü beşli anahtara göre gruplamadır; benzersiz bağlantı veya kişi sayısı değildir. Ayrıntılar `PCAP_TR.md` içindedir.
