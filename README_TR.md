# k957 0.12.0

[English](README.md) · **Türkçe**

k957; mantıksal delil toplama, paket bütünlüğünü doğrulama, belirli sınırlar içinde artefakt analizi ve raporlama için geliştirilmiş çevrimdışı bir komut satırı uygulamasıdır. Go ile yazılmıştır; Linux, Windows ve macOS için AMD64 ve ARM64 çalıştırılabilir dosyaları içerir. Etkileşimli sihirbaz ve HTML rapor arayüzü Türkçedir; İngilizce README, uygulamanın arayüz dilini değiştirmez.

**Durum: geliştirici ön sürümü.** Bu sürüm, çalışan bir toplama ve analiz çekirdeğidir; kapsamlı adli bilişim platformunun tamamı değildir ve üretim ortamı için doğrulanmış sayılmaz. Sürümün özellikleri ve platform durumu [RELEASE.json](RELEASE.json) dosyasında kayıtlıdır.

## Uygulanan özellikler

- **Toplama:** seçilen normal dosyaları alt dizinleriyle birlikte `.k957` paketine kopyalama; manifest, SHA-256 özetleri, toplama sorunları ve isteğe bağlı Ed25519 imzası. Canlı sistem bilgileri yalnızca `--system` ile toplanır.
- **Ön kontrol ve kurtarma:** envanter ve tahmini hedef kapasitesini inceleme; 8 MiB parçalarla sürdürülebilir toplama; kayıtlı çalışmayı inceleme veya doğrulama; devam öncesi kalan alanı hesaplama. Edinim dönemleri ve parçaların kaynak bilgileri korunur.
- **Şifreleme:** AES-256-GCM ile taşıma dosyaları; sürdürülebilir mantıksal toplamada şifreli kontrol noktaları/parçalar ve doğrudan şifreli son çıktı.
- **Analiz:** UTF-8 metin, CSV ve JSONL/NDJSON; Windows olay XML dışa aktarımları; desteklenen PCAP/PCAPNG paket başlıkları ve yönlü TCP/UDP akışları. Düz metin/SHA-256 kuralları ve ortak kullanıcı/cihaz/IP değerleri delil referanslarıyla sunulur.
- **Değerlendirme ve muhafaza:** isteğe bağlı imzalı değerlendirme geçmişiyle analist kararları; harici kişi/anahtar güven listesi ve alıcı kabulüyle ayrı imzalanmış muhafaza/devir beyanları.
- **Raporlama:** çevrimdışı aramalı HTML, JSON ve CSV; hangi alanların açık bırakılacağını belirleyen politikalarla ayrı maskelenmiş paylaşım raporu.

**0.12.0 yeniliği:** Windows olay XML analizi UTF-8 ve BOM işaretli UTF-16 LE/BE kabul eder; sağlayıcı/olay/kayıt kimliklerini ve sıralı Data alanlarını korur, açık saat dilimli zamanları UTC'ye dönüştürür, özgün kodlanmış verideki byte konumlarını ve atlanan kayıtları raporlar. Windows'a özgü ayrıntılar paylaşım raporuna aktarılmaz. Bu özellik XML dışa aktarımlarını analiz eder; ikili EVTX ayrıştırması yapmaz. Ayrıntılar: [Windows olay XML](docs/WINDOWS_EVENT_XML.md) ve [değişiklik geçmişi](CHANGELOG.md).

## Uygulamayı çalıştırma

Hazır çalıştırılabilir dosyalar için Go veya Python kurulumu gerekmez. `dist/` dizinini başlatma betikleriyle aynı üst dizinde tutun; işletim sistemi ve mimariye uygun dosyayı seçin:

- Linux: `dist/k957-linux-amd64` veya `dist/k957-linux-arm64`.
- Windows: `dist/k957-windows-amd64.exe` veya `dist/k957-windows-arm64.exe`.
- macOS: Intel için `dist/k957-darwin-amd64`, Apple Silicon için `dist/k957-darwin-arm64`.

Türkçe sihirbazı açmak için Linux/macOS üzerinde `sh start-unix.sh` çalıştırın veya Windows'ta `start-windows.cmd` dosyasını açın. Sihirbaz temel toplama ve analiz sunar; imzalama, şifreleme, devam ettirme, değerlendirme ve diğer gelişmiş seçenekler için CLI kullanın. Kopyalama sırasında Unix çalıştırma izinleri kaybolduysa seçtiğiniz dosyaya çalıştırma iznini yeniden verin.

Örneğin proje dizininde:

```sh
./dist/k957-linux-amd64 version
./dist/k957-linux-amd64 help
```

Windows PowerShell'de `./dist/k957-windows-amd64.exe version`, Apple Silicon'da `./dist/k957-darwin-arm64 version` kullanın. Aşağıdaki tüm örneklerde **`k957`** yerine uygun çalıştırılabilir dosyanın yolunu yazın veya dosyayı `PATH` üzerinden erişilebilir yapın. Komutlar, kabuğa özgü satır devam işaretleri gerekmemesi için tek satır olarak verilmiştir.

`version` komutu **0.12.0** döndürür. Mevcut genel `help` başlığında eski `0.9.0` etiketi bulunur; gerçek sürüm için `version` çıktısını ve [RELEASE.json](RELEASE.json) dosyasını esas alın.

Bu dosyalar platform uygulama imzası veya macOS noter onayıyla dağıtılmıyor. `noexec` gibi bağlama seçenekleri ve kurumun uygulama denetimleri çalıştırmayı engelleyebilir. Geçerli dağıtım politikasını izleyin.

## Sentetik delille hızlı başlangıç

Komutları proje dizininden çalıştırın. `examples/demo-source` yapay veriler içerir. Yeni bir `case-output` dizini seçin; rapor dizinleri ve çıktı dosyaları önceden mevcut olmamalı, üst dizinleri mevcut olmalıdır.

```sh
mkdir case-output
k957 preflight --root examples/demo-source --out case-output/demo.k957
k957 collect --root examples/demo-source --out case-output/demo.k957 --case DEMO-001 --operator Analyst --scope "Synthetic demonstration" --check-space
k957 verify --in case-output/demo.k957
k957 analyze --in case-output/demo.k957 --out case-output/report --rules examples/rules.json
k957 share --in case-output/demo.k957 --out case-output/shared --rules examples/rules.json
```

`case-output/report/report.html` dosyasını yerel tarayıcıda açın. Ayrı oluşturulan `case-output/shared` dizinini dağıtmadan önce inceleyin. Gerçek çalışmalarda yetkilendirilmiş kaynak dizini ve kaynak ağacının dışında uygun, korumalı bir hedef kullanın.

`preflight`, kaynak içeriklerini edinmeden kontrolleri ve envanter sorunlarını raporlar. Kapasite tahmini yapar; alan ayırmaz ve kaynakla hedefin ayrı fiziksel aygıtlar olduğunu kanıtlamaz. `--check-space`, sonuç `blocked` veya `unknown` olduğunda toplamayı engeller; `warning` ve `pass` durumlarında toplayıcı kendi kontrollerine devam eder.

## Toplama, devam ettirme ve şifreleme

### Toplama varsayılanları

Varsayılan sınırlar **kaynak başına 256 MiB, toplam 2 GiB, 10.000 dosya ve 30 dakikadır**. `--max-file`, `--max-total`, `--max-files` ve `--timeout` ile değiştirilebilir. Boyut sınırları tam sayı byte, süreler `1h` gibi değerler kabul eder. Ön kontrol ve `--check-space`, hedef dosya sistemi başına varsayılan **256 MiB ek boş alan payı** kullanır; `--reserve` ile değiştirilebilir.

Çıktılar kaynak ağacının dışında olmalıdır. Sembolik bağlantılar ve özel dosyalar atlanır; toplama sorunları manifeste kaydedilir. Araç otomatik yetki yükseltmez.

`collect --system`, [system.go](internal/core/system.go) içinde listelenen yerel dosya ve komutlarla platforma özgü sistem/süreç/oturum/ağ bilgilerini isteğe bağlı toplar. `--root` olmadan kullanılabilir; sürdürülebilir `--work` toplamasıyla birleştirilemez. Kullanılamayan veya erişimi reddedilen sistem komutlarının hataları kaydedilir.

### Sürdürülebilir edinim

Aşağıdaki örnek, yapay kaynağı ve yukarıda oluşturulan `case-output` dizinini kullanır:

```sh
k957 collect --root examples/demo-source --work case-output/resume-work --out case-output/resumable.k957 --case DEMO-002 --operator Analyst --scope "Synthetic resumable demonstration" --check-space
k957 work-status --work case-output/resume-work --verify-parts
k957 preflight --resume --root examples/demo-source --work case-output/resume-work --out case-output/resumed.k957
k957 collect --resume --root examples/demo-source --work case-output/resume-work --out case-output/resumed.k957 --case DEMO-002 --operator Analyst --scope "Synthetic resumable demonstration" --check-space
```

İlk toplama tamamlandıysa son komut kayıtlı veriyi yeni bir çıktıda yeniden paketler; kesinti oluşturmaz ve tamamlanmış dosyaları yeniden edinmez. Gerçek kesinti sonrasında özgün kaynak kökü, vaka, operatör, kapsam ve sınırlarla devam edin. İlk envanter sabittir: sonradan oluşturulan dosyalar dahil edilmez, tamamlanan dosyalar saklanan parçalardan kullanılır. Sonuç birden fazla edinim zamanını kapsayabilir.

Devam öncesi kontrol, kayıtlı metadatayı ve kalan kapasiteyi inceler; parça özetlerini yeniden hesaplamaz. `work-status --verify-parts`, kayıtlı parçaları doğrular; kaynağın mevcut ön bölümünü doğrulamaz. Asıl devam işlemi kendi bütünlük kontrollerini yapar. Toplayıcının kapandığı doğrulanmadan çalışma kilidini kaldırmayın. Ayrıntılar: [devam ve kurtarma](docs/RESUME_TR.md), [kalan alan ön kontrolü](docs/RESUME_PREFLIGHT.md).

### İmzalama

Bu yapay örnek, kaynak dizininin dışında yeni bir imza anahtar çifti oluşturur:

```sh
k957 keygen --out case-output/analyst
k957 collect --root examples/demo-source --out case-output/signed.k957 --case DEMO-003 --operator Analyst --scope "Synthetic signed demonstration" --sign-key case-output/analyst.key
k957 verify --in case-output/signed.k957 --trusted-key case-output/analyst.pub
```

`keygen`, `.key` ve `.pub` dosyaları oluşturur. Gerçek vakalarda özel anahtarları kaynak/çalışma ağaçlarının dışında, güvenilir bir ortamda koruyun; açık anahtarın güvenilirliğini delil paketinden bağımsız belirleyin. `--trusted-key` verilmezse özetler kontrol edilir ancak mevcut imza doğrulanmış sayılmaz. Özetlerin tutarlılığı tek başına kökeni kanıtlamaz.

### Şifreli toplama ve taşıma

```sh
k957 encryption-key --out case-output/transport.key
k957 collect --root examples/demo-source --work case-output/encrypted-work --out case-output/encrypted.k957.enc --case DEMO-004 --operator Analyst --scope "Synthetic encrypted demonstration" --encryption-key case-output/transport.key --check-space
k957 unseal --in case-output/encrypted.k957.enc --out case-output/decrypted.k957 --key case-output/transport.key
k957 verify --in case-output/decrypted.k957
```

Şifreli toplama `--work` gerektirir ve yalnızca mantıksal dosya toplamasını destekler. Şifreli çalışmayı özgün `--encryption-key` ile inceleyin veya sürdürün; yeni şifreli edinim ön kontrolünde `--encrypted` kullanılır. `verify`, `analyze` ve `share`, şifresiz `.k957` paketlerini okur; şifreli delili önce korumalı bir konuma `unseal` ile açın.

Önceden oluşturulmuş bir paket ayrıca şifrelenebilir:

```sh
k957 seal --in case-output/demo.k957 --out case-output/demo-transport.k957.enc --key case-output/transport.key
```

`seal`, şifresiz girdisini **silmez**. Her gerçek vaka için yeni rastgele anahtar kullanın ve anahtarı delilden ayrı saklayın. Parola tabanlı veya alıcının açık anahtarıyla şifreleme yoktur. `0600` dosya modu Windows ACL politikasını yapılandırmaz. Ayrıntılar: [şifreli toplama](docs/ENCRYPTED_COLLECTION_TR.md).

## Analiz ve raporlar

Analiz motoru içerikleri yorumlamadan önce delil paketini doğrular. Desteklenen analizler:

- UTF-8 CSV, JSONL/NDJSON ve açık RFC3339 zaman damgalı metinler. Yapılandırılmış alan adları arasında `timestamp`/`time`/`@timestamp`, `user`/`username`, `host`/`hostname` ve kaynak/hedef IP alanları bulunur. Saat dilimi ve eksik yıl tahmin edilmez.
- Windows Event ad alanında tek olay, olay parçaları veya `Events` kapsayıcısı içeren `.xml` dışa aktarımları. Özgün zaman, UTC, kaynak satır/byte konumu, sağlayıcı bilgileri ve sıralı Data alanları ayrıştırıcı sınırları içinde korunur. Harici XML kaynakları veya sağlayıcı DLL'leri yüklenmez.
- Desteklenen Ethernet, ham IP ve Linux SLL/SLL2 kapsüllemesiyle klasik PCAP ve belirli sınırlar içindeki PCAPNG Enhanced Packet Block kayıtları. TCP/UDP başlık alanları ve yönlü akışlar çıkarılır; paket içeriği analizi, yeniden birleştirme ve paket sağlama toplamı doğrulaması uygulanmamıştır.
- Kural JSON'undan büyük/küçük harf duyarsız düz metin satır eşleşmeleri veya tam SHA-256 eşleşmeleri. Kurallar düzenli ifade, Sigma veya YARA değildir. `--rules` verilmezse içerik/özet kuralları yüklenmez.
- En az iki delil nesnesinde ortak kullanıcı/cihaz/IP değerleri. Değer eşitliği; kaynakların bağımsızlığını, kimliği, nedenselliği veya kötü amaçlı etkinliği kanıtlamaz.

Tam analiz her zaman şu dosyaları üretir:

- `report.html`: Türkçe arayüzlü, çevrimdışı ve aramalı rapor.
- `analysis.json`: manifest, kurallar, bulgular, olaylar, ilişkiler, ayrıştırma özetleri ve sınırlamalar.
- `findings.csv`: bulgu kimlikleri, kural eşleşmeleri ve uygulanmışsa analist kararları.
- `timeline.csv`: UTC olayları ve mevcut kaynak referansları.
- `correlations.csv`: farklı delillerdeki ortak varlıkların özeti.

Ek dosyalar koşulludur: kabul edilen XML olayları için `windows-events.csv`, çıkarılan akışlar için `network.csv`, ağ kaydı ayrıştırma özetleri varsa `captures.csv`, doğrulanmış muhafaza geçmişi eklenmişse `custody.csv`. HTML içeriği kaçışlanır; CSV formül başlangıçları etkisizleştirilir. Tarayıcıdan yazdırma ile PDF alınabilir; yerleşik PDF/DOCX üretimi yoktur.

Metin/XML okuma sınırı **dosya başına 8 MiB, toplam 128 MiB**; ağ kaydı okuma sınırı ayrı olarak **dosya başına 64 MiB, toplam 256 MiB** değerindedir. Log olayları, sayılan XML kayıtları ve ağ kayıtları; dosya metadata olayları hariç ortak **50.000** bütçesini kullanır. En fazla **100 kural, 10.000 bulgu ve 10.000 ağ akışı** vardır. XML ve ağ dosyalarının her biri için 20.000 kayıt sınırı ve biçime özgü ek sınırlar uygulanır. Bulgu sınırına ulaşılırsa kalan analiz durur. Ayrıştırma özetleri ve notları inceleyin: rapor kısmi incelemeyi temsil edebilir.

Biçim ayrıntıları: [yapılandırılmış loglar](docs/STRUCTURED_TR.md), [Windows XML](docs/WINDOWS_EVENT_XML.md), [klasik PCAP](docs/PCAP_TR.md), [PCAPNG](docs/PCAPNG.md).

## Analist değerlendirmesi, muhafaza ve paylaşım

Bulgular başlangıçta `unreviewed` durumundadır. Hızlı başlangıç ve imzalama örneklerinden sonra `FINDING_ID` yerine `case-output/report/analysis.json` dosyasındaki gerçek bir bulgu kimliğini yazın:

```sh
k957 review --analysis case-output/report/analysis.json --finding FINDING_ID --decision needs-review --analyst Analyst --note "Requires source context" --sign-key case-output/analyst.key --out case-output/reviews-1.json
k957 analyze --in case-output/demo.k957 --out case-output/reviewed-report --rules examples/rules.json --reviews case-output/reviews-1.json --review-key case-output/analyst.pub
```

Kararlar `confirmed`, `rejected` veya `needs-review` olabilir. Geçmişe eklemek için `--previous` ve yeni çıktı kullanılır; imzalı önceki geçmişler için `--previous-key` gerekir. Yeniden analizde aynı delil, analiz sürümü ve kurallar kullanılmalıdır. Kararlar, delili değiştirmeden bulguları değerlendirir. Ayrıntılar: [analist değerlendirmesi](docs/REVIEW_TR.md).

`custody`; `register`, `transfer`, `accept`, `cancel` ve `note` işlemlerini destekler. İşlemi yapan kişinin imza anahtarını ve harici güven JSON'unu gerektirir. `custody-verify`, geçmişi delil ve güven listesine göre doğrular; `--expected-head`, ayrı saklanan son kayıt özetini kontrol edebilir. `analyze` veya `share` komutuna `--custody`, `--custody-trust` ve isteğe bağlı `--custody-head` ile geçmiş eklenir. İmzalar beyanları doğrular; fiziksel teslimi veya güvenilir zamanı kanıtlamaz. Tam [muhafaza/devir iş akışına](docs/CUSTODY_TR.md) bakın.

`share`; `shared.json`, HTML ve CSV çıktıları içeren ayrı bir `k957-shared-report/1` paylaşım kopyası oluşturur. Varsayılan politika hassas kimlik/yol kategorilerini maskeler; kaynak zamanlarını, serbest metin alıntılarını/notlarını ve Windows'a özgü ayrıntıları çıkarır. Sayılar ve ilişkiler korunur; anonimlik garantisi verilmez. Zamanları açıkça korumak için:

```sh
k957 share --in case-output/demo.k957 --out case-output/shared-with-times --rules examples/rules.json --policy examples/share-policy.json
```

Paylaşım raporu bir delil paketi veya değerlendirmeye dayanak olacak özgün analiz değildir. Çevresindeki vaka dosyalarını değil, yalnızca incelenmiş paylaşım dizinini paylaşın. Ayrıntılar: [paylaşım politikaları](docs/SHARING_TR.md).

## Komutlar ve sonuçları

- `wizard`: etkileşimli Türkçe toplama/analiz yardımcısı.
- `preflight`: yeni veya sürdürülecek edinimin planlanması.
- `collect`: mantıksal dosyalar ve isteğe bağlı canlı sistem bilgileri.
- `work-status`: kontrol noktasını inceleme ve isteğe bağlı parça doğrulama.
- `verify`: paket bütünlüğü ve isteğe bağlı güvenilir imza doğrulaması.
- `analyze`, `share`: tam analiz veya ayrı maskelenmiş rapor.
- `review`: analist karar geçmişinin yeni sürümü.
- `custody`, `custody-verify`: imzalı muhafaza beyanları ve doğrulama.
- `keygen`, `encryption-key`: imza anahtarları veya rastgele AES-256 anahtarı.
- `seal`, `unseal`: kimlik doğrulamalı akış şifrelemesi/şifre çözme.
- `version`, `help`: sürüm ve genel komut yardımı.

Seçenekler için `k957 <command> -h` çalıştırın. Mevcut CLI alt komut yardımını gösterir ancak bu istek için çıkış kodu 1 döndürür; `k957 help` kod 0 döndürür. Parametresiz çalıştırma genel yardımı gösterir; etkileşimli yardımcı için `wizard` veya başlatma betiği kullanın.

Başarılı komutlar 0, hatalar 1 döndürür. Kısmi `collect` işlemi de 1 döndürür; `partial` işaretli, yazımı tamamlanmış paket korunur ve manifest sorunları incelenmelidir. Başarılı `verify`, toplamanın eksiksiz olduğu anlamına gelmez. Tek geçişli modda iptal ve ağır hatalar tamamlanmamış çıktıyı kaldırmaya çalışır; sürdürülebilir mod kayıtlı çalışmayı korur. Zorla sonlandırma eksik bir son dosya bırakabilir. Bu dosyayı doğrulamadan kabul etmeyin; kurtarmada yeni çıktı yolu kullanın.

## Uyumluluk ve sınırlamalar

Hem `k957-evidence/1` hem `/2` okunabilir. Kontrol noktaları ve değerlendirme geçmişleri, üretildikleri analiz sürümüne bağlıdır. Eski çalışmaları özgün çalıştırılabilir dosyayla tamamlayın; geçişi zorlamak için sürüm alanlarını değiştirmeyin. Eski imzalı değerlendirmeleri koruyun, yeni sürümde değerlendirme için yeniden analiz oluşturun.

Paketlenmiş örnek raporlar ve değerlendirme geçmişleri **0.9.0** için üretilmiştir ve tarihsel örneklerdir. İçlerindeki eski mutlak kaynak yolları ve kapsam notları özgün çalıştırmaları anlatır. Yeniden kullanmadan önce [örnek kılavuzunu](examples/README_TR.md) okuyun.

Toplama mantıksal, canlı ve sınırlandırılmıştır; yazma engelleyici veya atomik dosya sistemi görüntüsü değildir. ACL, xattr, alternatif veri akışları, sahiplik, oluşturma/erişim zamanları, seyrek dosya düzeni ve sabit bağlantı ilişkileri korunmaz. Canlı sistemi okumak onu değiştirebilir; dosya değişikliği kontrolleri bütün yarış durumlarını yakalayamaz.

RAM edinimi, fiziksel disk imajı, silinmiş veri kurtarma, yerel EVTX/Registry/MFT/tarayıcı veritabanı ayrıştırması, bulut API'leri, mobil edinim, canlı paket yakalama ve dağıtık analiz uygulanmamıştır. Bu dosyaları kopyalamak içeriklerini yorumlamak anlamına gelmez. [Yol haritası](docs/ROADMAP.md), mevcut özelliklerle bekleyen işleri ayırır.

## Derleme ve doğrulama

Derleme için **Go 1.25 veya üstü** gerekir; dağıtılan 0.12.0 dosyaları **Go 1.26.8** ile derlenmiştir. Üçüncü taraf Go modülü yoktur.

```sh
go test ./...
go vet ./...
go build -trimpath -buildvcs=false -o k957 ./cmd/k957
```

Windows'ta `-o k957.exe` seçin. Altı hedefi derlemek için Bash bulunan bir ortamda `bash scripts/build.sh`, Windows'ta `powershell -File scripts/build.ps1` çalıştırın. Bu betikler `dist/` içindeki aynı adlı dosyaları yeniler. `bash scripts/test.sh`, vet ve kapsam ölçümlü, önbelleksiz birim testlerini çalıştırır.

Tam yerel platform doğrulaması için uygun bir ortamda Python 3.11+ kullanın, yalnızca testlerde gereken bağımlılığı kurun ve yeni bir sonuç dizini seçin:

```sh
python -m pip install -r scripts/requirements-test.txt
python scripts/validate.py --out validation-results
```

Gerektiğinde `python3` kullanın. Doğrulama; biçimlendirme, vet, önbelleksiz testler, kapsam ölçümü, veri yarışı denetimi, yerel sürüm derlemesi, sürüm kontrolü ve 12 entegrasyon betiğini çalıştırır. Yerel `dist` dosyasını yeniden derler; komut günlükleriyle `validation.json` kaydını saklar. Veri yarışı denetimi yerel C derleyicisi gerektirir: Windows AMD64 için GCC/MinGW, macOS için Xcode komut satırı araçları gerekir; Windows ARM64 üzerinde desteklenmez. Kurulum ve önceden derlenmiş Windows/Wine modu için [platform testlerine](docs/PLATFORM_TESTING.md) bakın.

**2026-09-29** tarihli **0.12.0** kayıtlarında:

- Yerel Linux AMD64: veri yarışı denetimi ve 12 entegrasyon betiği dahil 20 doğrulama adımı geçti; toplam kod kapsamı %84,3 oldu.
- Wine 10.0 altında Windows AMD64: iki Go test paketi, sürüm kontrolü ve 12 entegrasyon geçti. Gerçek Windows üzerinde çalıştırma yapılmadı.
- Linux/Windows/macOS AMD64 ve ARM64: altı sürüm hedefi derlendi. macOS ve diğer ARM64 hedeflerinde çalışma testi yapılmadı.
- Altı hedefli [CI iş akışı](.github/workflows/platform-tests.yml) hazırdır ancak çalıştırılmamıştır. Fiziksel USB/güç kesintisi ve gerçek aygıt edinimi henüz doğrulanmamıştır.

[Test raporu ve kayıtlarına](docs/TEST_REPORT.md) bakın. Derleme, Wine altında çalıştırma ve gerçek işletim sisteminde çalıştırma farklı doğrulama düzeyleridir.

## Proje dosyaları

- [cmd/k957](cmd/k957): CLI, sihirbaz ve komut işleme.
- [internal/core](internal/core): toplama, bütünlük, şifreleme, analiz ve dışa aktarım.
- [scripts](scripts): derleme betikleri, entegrasyon kontrolleri ve doğrulama aracı.
- [examples](examples/README_TR.md): yapay deliller, kurallar ve tarihsel raporlar.
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): biçimler ve güven modeli.
- [docs/PREFLIGHT_TR.md](docs/PREFLIGHT_TR.md): yeni edinim planlaması.
- [docs/RESUME_PREFLIGHT.md](docs/RESUME_PREFLIGHT.md): kalan alan planlaması.
- [CHANGELOG.md](CHANGELOG.md), [RELEASE.json](RELEASE.json): sürüm değişiklikleri ve özellikleri.
- [SHA256SUMS.txt](SHA256SUMS.txt): dağıtılan dosyaların özetleri; yayıncı imzası değildir. Yalnızca belge değiştiğinde uygulama sürümü değiştirilmeden bu özetler güncellenir.

`_TR` adlı ayrıntılı belgeler ağırlıklı olarak Türkçedir; bazı tarihsel belgelerde sonradan eklenmiş İngilizce güncelleme notları vardır. İki kök README, aynı güncel sürümü kendi dillerinde anlatır.

## Lisans

[MIT](LICENSE). Yazılım garanti verilmeden sunulur; koşullar için lisans metnine bakın.
