# k957 0.15.0 — ayrıntılı kullanım kılavuzu

**Türkçe** · [English user guide](README.md)

k957; bilgisayardaki verileri delil paketi olarak toplamanıza, sonradan değişip değişmediğini kontrol etmenize, desteklenen kayıtları incelemenize ve rapor oluşturmanıza yardımcı olur. Programı terminale komut yazarak kullanırsınız. Hazır çalıştırılabilir dosyaları kullanmak için yazılım geliştirmeniz gerekmez.

Örneğin günlük dosyalarının bulunduğu bir klasörü koruyabilir, başarısız oturum açma kayıtlarını bulabilir, desteklenen bir tarayıcı geçmişi veritabanını inceleyebilir, farklı bilgisayarlardan alınmış koleksiyonları birlikte değerlendirebilir ve kaynak delile başvuru içeren bir PDF hazırlayabilirsiniz. Bir eşleşmenin bulunması, tek başına saldırı gerçekleştiğini veya bir kişinin sorumlu olduğunu göstermez.

**Sürüm durumu: geliştirici önizlemesi.** Güncel kaynak için Linux AMD64 ve gerçek Windows AMD64 üzerinde kontroller çalıştırılmıştır. Altı işletim sistemi/işlemci hedefi için dosya derlenmektedir. Windows ARM64, gerçek macOS, fiziksel cihaz senaryoları ve doğru çekirdek sembolleriyle bellek nesnelerinin adli doğruluğu henüz doğrulanmamıştır. Hangi kaynak ve dosyanın hangi kapsamda kontrol edildiğini [RELEASE.json](RELEASE.json) ve [test raporundan](docs/TEST_REPORT.md) okuyabilirsiniz.

Bu belge güncel programın kullanımını anlatır. Programın ekran mesajları, etkileşimli sihirbazı ve raporları İngilizcedir. Türkçe kılavuz aynı işlemleri Türkçe açıklar; uygulamanın dilini değiştirmez. Toplanan özgün deliller herhangi bir dilde olabilir.

## Bu kılavuzu nasıl kullanmalısınız?

1. **Hazırlık** ve **İlk uygulama** bölümlerinden başlayın. Bunlarda yapay örnek dosyalar kullanılır.
2. Bir raporu sonuç olarak değerlendirmeden önce **Sonuçları anlama** bölümünü okuyun.
3. Yapacağınız işe uygun **Kullanım senaryosunu** seçin.
4. Belirli bir seçeneğe ihtiyaç duyduğunuzda **Komutların ayrıntılı açıklaması** bölümüne bakın. Her komutta amacı, örneği, beklenen sonucu ve yardım ekranında sunulan tüm seçenekler bulunur.
5. Sorun yaşarsanız **Sorun giderme**, **Sınırlar ve inceleme kapsamı** ile **Diğer belgeler** bölümlerine başvurun.

İçindekiler:

- [Hazırlık](#hazırlık)
- [Temel kavramlar](#temel-kavramlar)
- [İlk uygulama](#ilk-uygulama)
- [Sonuçları anlama](#sonuçları-anlama)
- [Kullanım senaryoları](#kullanım-senaryoları)
- [Komut başvuru kılavuzu](#komut-başvuru-kılavuzu)
- [Kurallar, göstergeler ve etiketli ölçümler](#kurallar-göstergeler-ve-etiketli-ölçümler)
- [Raporlar: çıktıyı seçmek, okumak ve teslim etmek](#raporlar-çıktıyı-seçmek-okumak-ve-teslim-etmek)
- [Bellek: edinim, tam tarama ve çekirdek incelemesi](#bellek-edinim-tam-tarama-ve-çekirdek-incelemesi)
- [Güven, teslim zinciri ve kaynak referansları](#güven-teslim-zinciri-ve-kaynak-referansları)
- [Sınırlar ve kapsam](#sınırlar-ve-kapsam)
- [Sorun giderme](#sorun-giderme)
- [Derleme, doğrulama ve sürüm dosyaları](#derleme-doğrulama-ve-sürüm-dosyaları)
- [İleri okuma](#ileri-okuma)
- [Lisans ve geliştirici](#lisans-ve-geliştirici)

## Hazırlık

### Doğru çalıştırılabilir dosyayı seçin

Kaynak kod deposunun kopyasında derlenmiş programlar bulunmaz. **Derleme, doğrulama ve sürüm dosyaları** bölümündeki adımlarla üretin; başlangıç betikleri `dist/` altında mevcut derleme ister. Hazırlanan programlar ayrıca sürüm dosyaları olarak dağıtılabilir. [Depo ve sürüm hazırlığı](docs/REPOSITORY.md) belgesine bakın.

İşletim sistemine ve işlemci türüne birlikte uygun dosyayı kullanın:

- Intel/AMD 64 bit işlemcili Linux: `dist/k957-linux-amd64`.
- ARM64 işlemcili Linux: `dist/k957-linux-arm64`.
- Intel/AMD 64 bit işlemcili Windows: `dist/k957-windows-amd64.exe`.
- ARM64 işlemcili Windows: `dist/k957-windows-arm64.exe`.
- Intel işlemcili Mac: `dist/k957-darwin-amd64`.
- Apple Silicon işlemcili Mac: `dist/k957-darwin-arm64`.

AMD64 için x64 veya x86-64 adları da kullanılır. Bu ad, yalnızca AMD markalı işlemcilerin desteklendiği anlamına gelmez; güncel Intel işlemciler de bu gruptadır. ARM64 farklı bir işlemci ailesidir. Windows'ta Ayarlar → Sistem → Hakkında bölümünde sistem türünü görebilirsiniz. Mac'te Bu Mac Hakkında bölümünden işlemciyi öğrenebilirsiniz. Linux'ta `uname -m` komutu çoğunlukla `x86_64` veya `aarch64` sonucunu verir.

Hazır programı kullanmak için Go, Python, Office veya web sunucusu kurmanız gerekmez. HTML okumak için tarayıcı, PDF okumak için PDF görüntüleyici yeterlidir. Volatility, Sleuth Kit ve yerel model gibi isteğe bağlı işlemlerin ek gereksinimleri ilgili bölümlerde açıklanır. Raporları bağımsız kontrol etmek için testlerde kullanılan araçlar, normal uygulama kullanımının zorunlu bileşenleri değildir.

### Terminali açın ve programı kontrol edin

Windows'ta proje klasöründe PowerShell veya Windows Terminal açın:

```powershell
.\dist\k957-windows-amd64.exe version
.\dist\k957-windows-amd64.exe help
```

Linux'ta:

```sh
chmod +x ./dist/k957-linux-amd64
./dist/k957-linux-amd64 version
./dist/k957-linux-amd64 help
```

Apple Silicon macOS'ta:

```sh
chmod +x ./dist/k957-darwin-arm64
./dist/k957-darwin-arm64 version
./dist/k957-darwin-arm64 help
```

İşlemcinize göre dosyayı ARM64/Intel karşılığıyla değiştirin. Sürüm çıktısında Cuma Kurt'un geliştirici iletişimi ve proje bağlantıları da gösterilir. İşletim sistemi imzasız programı engelliyorsa önce o sistemin uygulama güven politikasını çözmeniz gerekir; bu sürüm kod imzalı veya macOS için noter onaylı değildir.

Bu belgenin geri kalanındaki **`k957`, seçtiğiniz programın dosya yolunu temsil eder**. Örneğin Windows'ta `k957 analyze ...` yerine `.\dist\k957-windows-amd64.exe analyze ...` yazın. İsterseniz programı PATH içine alabilirsiniz; bunun yapılması zorunlu değildir.

Projede İngilizce etkileşimli sihirbazı başlatan `start-unix.sh` ve `start-windows.cmd` dosyaları da vardır. `dist/` klasörünü bunların beklediği konumda tutun. `wizard` önce toplama mı analiz mi yapmak istediğinizi, ardından dosya yollarını ve olay bilgilerini sorar. Tam kapsamlı bir grafik inceleme arayüzü değildir.

### Dosya yolları, klasörler ve seçenekler

- **Yol**, dosyanın veya klasörün adresidir. `./evidence`, bulunduğunuz klasörün altındaki `evidence` klasörüdür. `C:\Cases\Evidence` mutlak bir Windows yoludur.
- Boşluk içeren yolları tırnak içine alın: `--root "C:\Cases\Example Evidence"`.
- **Seçenekler** `--` ile başlar. Değer alan bir seçenekte değer hemen ardından yazılır: `--case CASE-001`.
- Aç/kapat seçenekleri `--check-space` gibi değersiz etkinleştirilebilir. Kapatmak için eşittir kullanın: `--system=false`. `--system false` yazmayın.
- Boyutlar tam sayı **bayt** olarak yazılır; `2GB` veya `256MiB` yazılmaz. 1 MiB = `1048576`, 256 MiB = `268435456`, 1 GiB = `1073741824`, 2 GiB = `2147483648`, 8 GiB = `8589934592`.
- Süreler `30s`, `5m`, `30m`, `4h` biçimindedir. Süre değeri bir takvim tarihi değildir.
- Açıkça belirttiğiniz çıktı **yeni bir yol** olmalıdır. Program eski paketin, raporun veya kayıt defterinin üzerine sessizce yazmaz. Her denemeye farklı ad verin; gerektiğinde üst klasörü önceden oluşturun.
- Çıktı paketini ve devam edilebilir çalışma klasörünü kaynak klasörün içine koymayın. Toplama aracı, büyüyen kendi çıktısını toplamamalıdır.

Örnekler birbirinden bağımsız iş akışlarıdır. Aynı çıktı adını başka bir örnekte yeniden kullanacaksanız farklı, yeni bir ad seçin. Kılavuzun tamamını tek bir betik gibi çalıştırmayın.

## Temel kavramlar

- **Delil/kaynak:** korunacak ve incelenecek özgün dosyalar veya imajdır. Günlük, veritabanı, olay dosyası veya RAM imajı olabilir.
- **Koleksiyon:** bir toplama çalışmasıdır. Tam toplamada kayıt, imza, özet değerler ve alınan veriler bir klasörde bulunur. Seçilen klasörün toplanması tek `.k957` paketi oluşturabilir.
- **Paket (`.k957`):** toplanan nesneleri ve bunların kaynak, boyut ve özetlerini açıklayan envanteri içerir. Uzantının `.k957` olması, dosyanın şifreli olduğu anlamına gelmez.
- **Manifest:** paketin içindeki envanterdir. Nelerin toplandığını ve karşılaşılan sorunları kaydeder.
- **SHA-256/özet:** dosyanın baytlarından hesaplanan uzun bir değerdir. Baytlar değiştiğinde beklenen özet de değişir. Eşleşmesi bayt tutarlılığını gösterir; dosyanın ne anlama geldiğini kanıtlamaz.
- **İmza:** özel/açık anahtar çiftiyle yapılan kriptografik kontroldür. Özel `.key` imzalar, açık `.pub` doğrular. Açık anahtarın kime ait olduğu ayrıca güvenilir biçimde belirlenmelidir.
- **Parmak izi:** imza açık anahtarını tanımlayan özettir. Program geçici anahtar üretiyorsa parmak izini bağımsız bir yerde saklayın.
- **Güvenilen anahtar:** delilden bağımsız ve güvenilir bir yolla edindiğiniz açık anahtardır. Paketin yanında bulunan anahtar, tek başına bağımsız güven kaynağı değildir.
- **Şifreleme:** aktarım veya çalışma verisinin AES anahtarı olmadan okunmasını engeller. İmza ile şifreleme farklı amaçlara hizmet eder. Şifreleme anahtarının kaybolması, şifreli veriyi kullanılamaz hale getirebilir.
- **Olay/dosya numarası:** `CASE-001` gibi inceleme tanımlayıcısıdır. Türetilmiş olay dosyası birden fazla koleksiyonu birleştirebilir.
- **Bulgu:** analistin değerlendirmesi gereken kural, özet veya gösterge gözlemidir. Otomatik olarak doğrulanmış bir güvenlik olayı değildir.
- **Zaman çizelgesi:** kaynak bağlantısıyla zamana göre sıralanan kayıtlardır. Saat hataları ve eksik saat dilimi yorumlamayı etkileyebilir.
- **Kaynak bağlantısı:** gözlemin hangi koleksiyon özetinden, delil kimliğinden, dosya yolundan, özgün kayıttan veya bayt konumundan geldiğidir.
- **Muhafaza/teslim zinciri:** kayıt ve teslim için imzalı beyanlardır. Fiziksel teslimi veya kişinin gerçek kimliğini tek başına kanıtlamaz.
- **Kapsam:** toplama ve inceleme yetkisinin kapsadığı kaynaklardır. Başkasının da anlayabileceği somut bir açıklama yazın; yalnızca “her şey” yazmak yeterli değildir.
- **Türetilmiş rapor:** delile dayanarak oluşturulan açıklamadır. HTML, PDF, DOCX, CSV ve olay indeksi türetilmiş çıktıdır. Özgün delili ayrıca koruyun.

## İlk uygulama

Bu alıştırma yapay veri içeren `examples/demo-source` klasörünü kullanır. Tam makine toplaması veya RAM edinimi istemez. Komutları proje klasöründe çalıştırın. Yeni bir `case-output` klasörü kullanın veya başka bir yeni ad seçin.

### 1. Çıktı için klasör oluşturun

```sh
mkdir case-output
```

Bu komut normal PowerShell'de de kullanılabilir. Klasör, alıştırmanın çıktılarını bir arada tutar ve örnek kaynak klasörün dışındadır.

### 2. Gerekli alanı tahmin edin

```sh
k957 preflight --root examples/demo-source --out case-output/demo.k957
```

Envanteri, kapasite kontrollerini ve sonucu okuyun. `preflight` inceleme ve tahmin yapar; delil toplamaz, paketi oluşturmaz. Hazır sonucu, ölçüm anındaki durumu anlatır. Boş disk alanı ve canlı dosyalar sonradan değişebilir.

### 3. Tekrar kullanılabilir imza anahtarı oluşturun

```sh
k957 keygen --out case-output/examiner
```

`examiner.key` ve `examiner.pub` oluşur. Özel `.key` dosyasını yalnızca imzalayan kişide tutun. Açık `.pub`, o kişinin çıktısını doğrulayacak kişilerle paylaşılabilir. Öğrenme örneğinde aynı klasör kullanılmıştır; gerçek incelemede anahtar yönetimi delilden bağımsız planlanmalıdır.

### 4. Örnek klasörü toplayın

```sh
k957 collect --root examples/demo-source --out case-output/demo.k957 --case DEMO-001 --operator Analyst --scope "Synthetic demonstration folder" --sign-key case-output/examiner.key --check-space
```

`--root` kaynağı, `--out` yeni paketi seçer. `--case`, `--operator`, `--scope` toplama bilgilerini yazar. `--sign-key`, üçüncü adımın anahtarıyla imzalar. `--check-space`, toplamadan önce kapasite kontrolünü tekrarlar. `--root` ve `--out` açıkça yazıldığı için bu komut yalnızca seçilen klasörü mantıksal olarak toplar; parametresiz tam toplama değildir.

### 5. Paketi doğrulayın

```sh
k957 verify --in case-output/demo.k957 --trusted-key case-output/examiner.pub
```

Paket yapısı, nesne özetleri ve imza verilen anahtara göre kontrol edilir. Başarılı sonuç günlüklerin zararsız olduğunu veya bunları belirli kişinin oluşturduğunu söylemez. Toplanan baytların ve imzanın kontrol koşullarını sağladığını söyler.

### 6. İnceleme raporunu oluşturun

```sh
k957 analyze --in case-output/demo.k957 --out case-output/report --trusted-key case-output/examiner.pub --rules examples/rules.json
```

Tarayıcıda `case-output/report/report.html`, PDF okuyucuda `case-output/report/report.pdf` açın. PDF varsayılan olarak oluşturulur; PDF yazıcısı kurmanız gerekmez. `analysis.json`, CSV dışa aktarımları ve kapsam kayıtlarını birlikte saklayın. Görsel raporun özetlediği ayrıntılar ve bildirilen eksikler bu dosyalarda bulunur.

### 7. Ayrı DOCX/PDF belge paketi hazırlayın

```sh
k957 report-documents --analysis case-output/report/analysis.json --out case-output/documents --format both
k957 report-seal --report case-output/documents --key case-output/examiner.key
k957 report-verify --report case-output/documents --trusted-key case-output/examiner.pub
```

`report-documents`, PDF ve DOCX oluşturur. `report-seal`, türetilmiş dosya paketini ve kaynak bağlantılarını imzalar. `report-verify`, imza kaydını ve kapsadığı dosyaları kontrol eder. DOCX'i sonradan düzenlemek dosyanın baytlarını değiştirir ve önceki imzayı o değiştirilmiş dosya için geçersiz kılar. Analist düzenleme yaparsa yeni sürümü ayrı tanımlayın.

### 8. Maskelenmiş paylaşım kopyası hazırlayın

```sh
k957 share --in case-output/demo.k957 --out case-output/shared --trusted-key case-output/examiner.pub --rules examples/rules.json
```

Yeni klasörü paylaşmadan önce içindeki `report.html` ve `report.pdf` dosyalarını açıp kontrol edin. Varsayılan politika, desteklenen kimlik/yol alanlarını maskeler ve hassas bağlamı dışarıda bırakır. Tam anonimlik garantisi değildir. Maskesiz inceleme klasörünü özel olarak koruyun; paylaşım kopyası onun yerine geçmez.

## Sonuçları anlama

### Toplama ve doğrulama durumları

- `complete`: yapılandırılan kapsam altında toplama tamamlanmıştır. Notları ve metadata eksiklerini de okuyun; bilgisayardaki bütün izlerin alındığı anlamına gelmez.
- `partial`: toplama veya yorumlamanın bir kısmı tamamlanamamıştır. `issues`, koleksiyon kaydı ve paket manifestini inceleyin. Kısmi verinin özet ve imzaları yine geçerli olabilir.
- `verified`: bütünlük kontrolleri geçmiştir. Bağımsız verilen anahtara göre doğrulama ile paketin kendi anahtarına göre doğrulamayı ayırt edin.
- `failed`: işlem kontrol koşullarını sağlayamamıştır. Özet veya tanı kaydı nedenini açıklar. Başarıyla incelenmiş koleksiyon gibi değerlendirmeyin.
- `absent`: profilin seçtiği bir yol mevcut değildir. Bir yolun bulunmaması, saldırının bulunmadığını kanıtlamaz. Kullanılamayan komut, isteğe bağlı Registry konumu veya olay kanalı ayrıca sorun olarak kaydedilebilir.
- `skipped`, `unsupported`, `limited`, `truncated`: o girdi veya yöntem için inceleme kapsamı eksiktir. Böyle bir yöntemde sıfır sonuç görülmesi, gerçekte hiç kayıt olmadığı anlamına gelmez.

### Bir bulguyu okuma

Önce kural veya gösterge adını, ardından delil kimliğini, kaynak yolunu, olay/özgün kayıt numarasını, zamanı ve alıntıyı kontrol edin. Karar vermeden önce özgün doğrulanmış nesneyi veya tam makine çıktısını inceleyin. `failed password` ifadesi normal parola hatasında, otomatik testte veya kötü niyetli etkinlikte görülebilir; yalnızca bu ifade ile ayrım yapılamaz.

İnceleme kararları farklıdır: `confirmed` doğrulandı, `rejected` reddedildi, `needs-review` yeniden değerlendirme gerekiyor. İmzalı karar, analistin beyanını ve gerekçesini kaydeder. Çıkarımın yanılmaz olduğunu göstermez.

### İlerleme, okuma yükü ve durdurma

Canlı ekran hazırlık, bellek, dosyalar, paketleme, doğrulama ve analiz gibi aşamaları gösterir. İş miktarı bilindiğinde yüzde görünür. `estimating`, henüz anlamlı bir yüzde verilemediğini belirtir. Kalan süre bir tahmindir.

`read workload`, aynı baytların bütünlük kontrolü, özet hesabı ve ayrıştırma sırasında birden fazla okunması nedeniyle kaynak boyutunu aşabilir. Örneğin 31 GiB imaj için çok daha yüksek okuma yükü gösterilmesi, delil imajının büyüdüğü anlamına gelmez.

İlerleme stderr kanalına yazılır. Yönlendirme veya boru kullanıldığında makine çıktısı stdout kanalına gider; bazı komutlar terminalde insanın okuyacağı gruplu özet gösterir. JSON'u ayrı saklamak için:

```sh
k957 verify --in case-output/demo.k957 --trusted-key case-output/examiner.pub > case-output/verification.json 2> case-output/verification-progress.log
```

Ctrl+C, işlemi hemen durdurmayı ve `130` çıkış kodunu ister. Geçerli nesne tamamlanmaz, yarım tam koleksiyon imzalanmaz, alt aracın bitmesi beklenmez. Tamamlanmamış klasör kalabilir. Kaldığı yerden sürdürme yalnızca `--work` kullanan mantıksal toplama iş akışında desteklenir; tam makine toplaması, devam edilebilir RAM edinimi değildir.

Diğer bildirilen hatalarda sıfır olmayan çıkış kodu, çoğunlukla `1` kullanılır. Koleksiyon durumunu ayrıca okuyun: mantıksal toplamada yalnızca çıkış koduna bakmak edinim kalitesinin tamamını açıklamaz.

Linux/macOS'ta renkleri `NO_COLOR=1 k957 ...` ile kapatın. PowerShell'de komuttan önce `$env:NO_COLOR="1"` yazıp sonra `Remove-Item Env:NO_COLOR` ile kaldırın. `TERM=dumb` sade ilerleme çıktısını seçer. Yönlendirilen çıktı satır düzeninde kalır. Desteklenen Windows konsollarında ANSI renk/yeniden çizimden önce VT işleme açılır; kurulum başarısızsa sade çıktı kullanılır.

## Kullanım senaryoları

### A. Bir günlük klasörünü korumak

İlgili günlükleri önceden tek klasörde topladıysanız yukarıdaki seçilen klasör alıştırmasını kullanın. `collect`, alt klasörleri de dolaşır; edinilen dosya baytlarını, özetlerini ve mevcut üst verileri kaydeder. Bu mantıksal edinimdir: kullanılmayan disk alanını imajlamaz, silinen dosyaları kurtarmaz veya birden fazla canlı dosyayı aynı anda dondurmaz. Paketi kaynak klasörün dışında tutun. Klasörün neden seçildiğini `--scope` ile açıklayın.

### B. Şu anda kullandığınız bilgisayarı incelemek

`k957 collect`, `output/<bilgisayar>/<UTC zaman damgası>/` oluşturur; önce belleği, sonra canlı sistem durumunu ve işletim sistemi profilini toplamayı dener. İşlem komutun çalıştırıldığı bilgisayarda yapılır. Tam mod ayarlarını değiştirmek için tam olarak `--full` yazın:

```sh
k957 collect --full --output-dir case-output/collections --case CASE-001 --operator Examiner --scope "Approved triage of this computer" --sign-key case-output/examiner.key
k957 verify --store case-output/collections --trusted-key case-output/examiner.pub
k957 analyze --store case-output/collections --trusted-key case-output/examiner.pub --rules examples/rules.json
```

Önce `case-output` üst klasörünü oluşturun. Windows'ta genellikle yönetici terminali ve uyumlu bellek edinim aracı gerekir; Linux'ta fiziksel aralıkların ve `/proc/kcore` kaynağının erişilebilir olması gerekir. macOS için harici bellek edinim aracı gerekir. İsteğe bağlı günlüğün bulunmaması `absent` olarak kaydedilir; bellek ediniminin başarısız olması farklıdır ve koleksiyonu `partial` yapabilir. RAM'in toplandığını söylemeden edinim kaydını kontrol edin.

Yalnızca yapay dosyalarla küçük bir alıştırma için makine genelindeki üç kaynağı açıkça kapatın:

```sh
k957 collect --full --root examples/demo-source --output-dir case-output/demo-collections --system=false --artifacts=false --memory=false --case DEMO --operator Analyst --scope "Synthetic folder only"
```

Bu bilerek daraltılmış bir koleksiyondur; RAM veya dışarıda bırakılan sistem kayıtları hakkında cevap vermez. Tam moddaki dosya sınırları dosya sistemi kaynakları içindir; varsayılan `--memory-limit 0`, eşlenen fiziksel RAM'i yapılandırılmış bayt tavanı olmadan saklar.

### C. Uzun klasör edinimini kaldığı yerden sürdürmek

İlk çalıştırmadan itibaren `--work` kullanın. Kontrol noktası edinim durumunu ve doğrulanan parçaları kaynak/paket dışında saklar. Kesintiden sonra aynı kaynak, vaka, kapsam, sınırlar, imza anahtarı ve çalışma klasörüyle komutu tekrarlayıp `--resume` ekleyin. Kontrol noktası dosyalarını elle değiştirmeyin. Bu anlık görüntü değildir; sürdürülen parçaların ayrı edinim dönemleri vardır.

```sh
k957 preflight --root examples/demo-source --out case-output/resumed.k957 --work case-output/checkpoint
k957 collect --root examples/demo-source --out case-output/resumed.k957 --work case-output/checkpoint --case DEMO --operator Analyst --scope "Synthetic resume exercise" --sign-key case-output/examiner.key --check-space
k957 work-status --work case-output/checkpoint --verify-parts
```

Yalnızca toplama başarıyla tamamlanmadan kesildiyse aynı `collect` komutuna `--resume` ekleyin. Başarıyla oluşturulan çıktı üzerine yazılmaz. Tam makine toplaması ve bellek edinimi bu devam edilebilir mantıksal dosya iş akışını kullanmaz.

### D. Taşıma paketini ve çalışma parçalarını şifrelemek

`encryption-key`, AES-256 anahtar dosyası oluşturur. Mantıksal toplamadaki `--encryption-key`, `--work` gerektirir; parçaları ve son paketi şifreler. Anahtarı taşınan paketten ayrı tutun; anahtar kaybı kurtarmayı engeller. Normal paket doğrulaması ve analizinden önce yeni bir açık metin pakete çözün.

```sh
k957 encryption-key --out case-output/transport.key
k957 collect --root examples/demo-source --out case-output/encrypted.k957 --work case-output/encrypted-work --encryption-key case-output/transport.key --case DEMO --operator Analyst --scope "Synthetic encrypted exercise" --sign-key case-output/examiner.key
k957 unseal --in case-output/encrypted.k957 --out case-output/decrypted.k957 --key case-output/transport.key
k957 verify --in case-output/decrypted.k957 --trusted-key case-output/examiner.pub
```

Şifreleme ile Ed25519 imzası farklı işler yapar: şifreleme okumayı sınırlar; imza, kaydedilen baytları güvenilen açık anahtara karşı doğrular. Sonradan oluşturulan açık rapor kendiliğinden şifrelenmez.

### E. Tarayıcı, olay ve kalıcılık kayıtlarını incelemek

Önce gerçek kaynak dosyalarını toplayın. Analiz, seçili SQLite tarayıcı geçmişi şemalarını, EVTX kayıtlarını, temiz Registry dosyalarını, desteklenen launchd plist ve seçili metin/XML kalıcılık kayıtlarını yorumlar. Mümkünse özgün kayıt referanslarını saklar. Dosya türünün tanınması, o türdeki bütün yapıların yorumlanabildiği anlamına gelmez.

```sh
k957 analyze --in case-output/demo.k957 --out case-output/event-report --trusted-key case-output/examiner.pub --rules examples/event-rules.json
```

Canlı SQLite için `sqlite-acquire`, ayrı ve işlem tutarlı mantıksal yedek üretir. Ham kaynak baytları da gerekiyorsa asıl veritabanı/WAL/journal dosyalarını ayrıca toplayın. Yedek, türetilmiş veritabanıdır ve bu niteliği kayda geçer.

### F. Önceden dışa aktarılmış bulut kayıtlarını incelemek

Bir klasöre yalnızca seçilen CloudTrail JSON veya JSON.gz dışa aktarımlarını koyun. `source-import`, bunları kaynak bilgisiyle paketler; bulut hesabına giriş yapmaz, kayıt indirmez. Hesap/zaman/bölge seçimini ve dışa aktarım yöntemini inceleme notlarına yazın. Dışa aktarılmış baytlar tek başına tüm bulut olaylarının alındığını kanıtlamaz.

```sh
k957 source-import --kind cloudtrail --in cloud-exports --out case-output/cloud.k957 --case CASE-001 --operator Analyst --scope "Selected offline CloudTrail exports" --sign-key case-output/examiner.key
```

### G. Birden fazla bilgisayarın koleksiyonlarını karşılaştırmak

`case`, rastgele `.k957` dosyaları bulunan klasörden değil, koleksiyon deposundan dosya oluşturur. Her tam koleksiyonun imzalı `collection.json` ve ilgili dosyaları bulunur. Doğrulaması başarısız olan koleksiyon raporlanır ve incelemeye alınmaz.

```sh
k957 case --store case-output/collections --out case-output/dossier --trusted-key case-output/examiner.pub --rules examples/event-rules.json
k957 case-query --case case-output/dossier --kind event --text "failed" --limit 50
k957 case-serve --case case-output/dossier
```

Yazdırılan yerel adresi, belirteciyle birlikte aynı bilgisayardaki tarayıcıda açın. Gezinirken `case-serve` açık kalsın; Ctrl+C sunucuyu durdurur. Kesin kaynak için koleksiyon özeti ve delil kimliğiyle filtreleyin. Aynı dosya özeti, edinilen baytların aynı olduğunu gösterir; ortak saldırganı veya kopyalama yönünü kanıtlamaz.

### H. Bulguyu değerlendirmek ve seçimi kaydetmek

Önce referans verilen özgün kaydı okuyun. Kalıcı bulgu kimliğini `analysis.json` içinden alın; satır numarası veya açıklamayı kimlik yerine kullanmayın. `review`, analist kararını analizden ayrı kaydeder. Reddedilen eşleşme özgün analiz geçmişinden silinmez.

```sh
k957 review --analysis case-output/report/analysis.json --finding FINDING_ID --analyst Analyst --decision needs-review --note "Confirm this record against the original source" --out case-output/review-01.json --sign-key case-output/examiner.key
k957 analyze --in case-output/demo.k957 --out case-output/reviewed-report --rules examples/rules.json --reviews case-output/review-01.json --review-key case-output/examiner.pub --trusted-key case-output/examiner.pub
```

`FINDING_ID` yerine o analizdeki gerçek kimliği yazın. Vaka seçiminde `case-bookmark`, seçilen sorgu sayfasını, kaynak bağlarını ve HTML/PDF'yi içeren imzalı not oluşturur. Yalnızca o sayfayı kaydeder; sonraki sayfalardaki bütün eşleşmeleri kaydettiği söylenemez.

### I. Daha az kişisel bilgi içeren rapor paylaşmak

`share`, ayrı bir maskelenmiş rapor üretir. Özgün paket delil olmaya devam eder. Önce varsayılan politikayı kullanın ve dağıtmadan bütün çıktı dosyalarını inceleyin. Açık politika seçimleri hassas alanları koruyabilir; görünen RAM metinleri ve harici araçların çıkardığı dosyalar özellikle kontrol edilmelidir.

```sh
k957 share --in case-output/demo.k957 --out case-output/shared --rules examples/rules.json --trusted-key case-output/examiner.pub
k957 report-seal --report case-output/shared --key case-output/examiner.key
k957 report-verify --report case-output/shared --trusted-key case-output/examiner.pub
```

Maskelenmiş rapor bir paylaşım görünümüdür; vakada hiç kişisel bilgi olmadığı anlamına gelmez. İçeriği son haline getirdikten sonra imzalayın. Sonradan dosya eklemek/değiştirmek rapor doğrulamasını başarısız yapar.

### J. Mevcut RAM veya ham disk imajını incelemek

Güvenilen Volatility çalıştırılabilir dosyası ve eşleşen çevrimdışı sembollerle `memory-examine`; Sleuth Kit ile `disk-examine`/`disk-recover` kullanın. Bu komutlar harici araç bilgilerini ve kaynak özetlerini saklar. Fiziksel disk edinimi yapmaz. Komut örneklerindeki `IMAGE_SHA256`, araç yolları ve seçiciler yerine gerçek, güvenilen değerleri koyun. Başarısız eklenti veya desteklenmeyen dosya sistemi, bilgisayarın boş olduğu anlamına gelmez.

### K. İsteğe bağlı yerel asistan kullanmak

Önce vaka dosyası oluşturun. `case-assistant`, açıkça seçilen kayıt sayfasını alır ve önceden kurulmuş, önbellekte bulunan yerel Ollama modelinden kaynaklı öneriler ister. Model pakete dahil değildir, otomatik indirilmez. Kaynak atıfları biçimsel olarak doğru olsa bile model yanılabilir. İnsan kaynakları kontrol etmelidir; `assistant-review`, kabul/ret kararını ayrı ve imzalı kaydeder. `--question`, `--text` arama filtresinin yerine geçmez.

### L. Teslim zinciri ve saat farklarını kaydetmek

Teslim zinciri kayıtları beyan edilen zilyetliği ve teslimleri açıklar; fiziksel delili taşımaz. Her aktörün kendi imza anahtarını, dışarıda tutulan aktör/açık anahtar listesini ve bağımsız zincir başı saklamasını kullanın. Zamansal ilişkilendirme açık saat/kimlik tahminlerinden aday üretir. Nedensellik kurmaz; farklı bilgisayarlardaki aynı kullanıcı adını sessizce tek kişi kabul etmez.

## Komut başvuru kılavuzu

Aşağıdaki örnekler tek uzun betik değildir; ayrı işlerin şablonlarıdır. Önce üst klasörleri oluşturun; her çalıştırmada yeni çıktı adı seçin. Büyük harfli yer tutucuları değiştirin. `k957 help` komutları listeler; seçenekli komutlarda `k957 <komut> -h` seçenek yardımını gösterir. Sihirbaz etkileşimlidir; version/build-info seçeneksiz çalıştırılır. Seçenek listeleri mevcut çalıştırılabilir dosyadan alınmıştır. Ortak ayrıştırıcı kullanılan yerlerde seçenekleri uygulamadan komuta özgü notları okuyun.

### `wizard`

Etkileşimli toplama/analiz yardımcısını başlatır.

```sh
k957 wizard
```

İngilizce soruları yanıtlayın. Seçenek almaz; wizard -h yardım ekranı değildir.

Komuta özgü seçenek yoktur.

### `preflight`

Delil yazmadan seçilen klasörün edinim kapasitesini tahmin eder.

```sh
k957 preflight --root examples/demo-source --out case-output/planned.k957
```

Sayıları, planlanan boyutu ve dosya sistemi kapasitesini döndürür. Tahmindir; alan ayırmaz, canlı kaynakların değişmeyeceğini garanti etmez.

Seçenekler (basılı varsayılan yoksa yardım açık bir varsayılan göstermiyor demektir):

- `--encrypted` — Ön kontrolde şifreli devam edilebilir modun alanını tahmin eder; anahtar okumaz. Varsayılan: kapalı.
- `--encryption-key string` — AES-256 anahtar dosyası. Şifreli devam için ilk edinimdeki aynı anahtarı kullanın; özel imza anahtarı değildir.
- `--max-file int` — Her dosya sistemi kaynağı için azami edinilecek bayt. Sınırı aşan kaynaklar edinim kaydında belirtilir; bellek analizi sınırı değildir. Varsayılan: `268435456`.
- `--max-files int` — Azami dosya sistemi kaynak sayısı. Sayıyı büyütmek dosya sayısı kapsamını genişletir; RAM sonuç tavanı değildir. Varsayılan: `10000`.
- `--max-total int` — Azami toplam edinilen dosya sistemi baytı. Son paket boyutuyla birebir aynı değildir; bellek analizi tavanı değildir. Varsayılan: `2147483648`.
- `--out string` — Yeni çıktı dosyası/klasörü veya keygen için yeni anahtar yolu kökü. Türü komuta göre değişir; mevcut çıktının üzerine yazılmaz.
- `--reserve int` — Hedef dosya sisteminde bırakılacak ek boş alan, bayt. Toplama/ön kontrol içindir; bellek analizine sabit tavan koymaz. Varsayılan: `268435456`.
- `--resume` — Var olan --work kontrol noktasını aynı kaynak/kapsam/sınırlarla sürdürür veya ön kontrolde kalan alanı hesaplar. Varsayılan: kapalı.
- `--root string` — Mantıksal toplamada kaynak klasör; tam modda profile ek olarak toplanacak klasör.
- `--work string` — Mantıksal edinimin devam edilebilir çalışma klasörü; kaynak ve çıktı dışında olmalıdır.

### `collect`

Seçilen klasörden imzalı mantıksal paket oluşturur.

```sh
k957 collect --root examples/demo-source --out case-output/selected.k957 --case DEMO --operator Analyst --scope "Synthetic files" --sign-key case-output/examiner.key
```

Yeni paket ve edinim kaydı oluşturur. Hiç argüman verilmezse tam makine modu seçilir; sonraki başlığa bakın.

Seçenekler (basılı varsayılan yoksa yardım açık bir varsayılan göstermiyor demektir):

- `--case string` — Toplamada vaka kimliği; case-* inceleme komutlarında türetilmiş vaka klasörünün yolu.
- `--check-space` — Yeni veya sürdürülen mantıksal edinimden önce alan ön kontrolünü çalıştırır. Varsayılan: kapalı.
- `--encryption-key string` — AES-256 anahtar dosyası. Şifreli devam için ilk edinimdeki aynı anahtarı kullanın; özel imza anahtarı değildir.
- `--max-file int` — Her dosya sistemi kaynağı için azami edinilecek bayt. Sınırı aşan kaynaklar edinim kaydında belirtilir; bellek analizi sınırı değildir. Varsayılan: `268435456`.
- `--max-files int` — Azami dosya sistemi kaynak sayısı. Sayıyı büyütmek dosya sayısı kapsamını genişletir; RAM sonuç tavanı değildir. Varsayılan: `10000`.
- `--max-total int` — Azami toplam edinilen dosya sistemi baytı. Son paket boyutuyla birebir aynı değildir; bellek analizi tavanı değildir. Varsayılan: `2147483648`.
- `--operator string` — Edinimi yapan kişinin adı; geliştirici adı otomatik incelemeci kimliği değildir.
- `--out string` — Yeni çıktı dosyası/klasörü veya keygen için yeni anahtar yolu kökü. Türü komuta göre değişir; mevcut çıktının üzerine yazılmaz.
- `--reserve int` — Hedef dosya sisteminde bırakılacak ek boş alan, bayt. Toplama/ön kontrol içindir; bellek analizine sabit tavan koymaz. Varsayılan: `268435456`.
- `--resume` — Var olan --work kontrol noktasını aynı kaynak/kapsam/sınırlarla sürdürür veya ön kontrolde kalan alanı hesaplar. Varsayılan: kapalı.
- `--root string` — Mantıksal toplamada kaynak klasör; tam modda profile ek olarak toplanacak klasör.
- `--scope string` — Yetkilendirilmiş edinim kapsamının açıklaması. Nelerin neden toplandığını anlaşılır yazın.
- `--sign-key string` — Ed25519 özel imza anahtar dosyası. Özel anahtar gizlidir; .pub doğrulama içindir.
- `--system` — Canlı sistem anlık kayıtlarını toplar. Mantıksal modda açıkça etkinleştirilir; tam modda varsayılan açıktır.
- `--timeout duration` — Toplama süresi üst sınırı; örneğin 30m veya 4h. Genel bellek analizi/Volatility için otomatik süre tavanı değildir. Varsayılan: `30m0s`.
- `--work string` — Mantıksal edinimin devam edilebilir çalışma klasörü; kaynak ve çıktı dışında olmalıdır.

### `collect --full`

Fiziksel belleği, canlı durumu ve işletim sistemi profilini toplar.

```sh
k957 collect --full --output-dir case-output/collections --case CASE-001 --operator Analyst --sign-key case-output/examiner.key
```

Bilgisayar/zaman klasörlerinde imzalı koleksiyon kaydı, delil ve edinilebilen bellek bulunur. Ayrıştırıcıyı --full seçer; mod seçiciyi --full=true şeklinde yazmayın.

Seçenekler (basılı varsayılan yoksa yardım açık bir varsayılan göstermiyor demektir):

- `--artifacts` — Yerleşik işletim sistemi artefakt profilini toplar; kapatmak için --artifacts=false. Varsayılan: `true`.
- `--case string` — Toplamada vaka kimliği; case-* inceleme komutlarında türetilmiş vaka klasörünün yolu.
- `--full` — Tam makine toplama modunu seçer. Mod seçimi için tam olarak --full kullanın. Varsayılan: `true`.
- `--max-file int` — Her dosya sistemi kaynağı için azami edinilecek bayt. Sınırı aşan kaynaklar edinim kaydında belirtilir; bellek analizi sınırı değildir. Varsayılan: `268435456`.
- `--max-files int` — Azami dosya sistemi kaynak sayısı. Sayıyı büyütmek dosya sayısı kapsamını genişletir; RAM sonuç tavanı değildir. Varsayılan: `100000`.
- `--max-total int` — Azami toplam edinilen dosya sistemi baytı. Son paket boyutuyla birebir aynı değildir; bellek analizi tavanı değildir. Varsayılan: `8589934592`.
- `--memory` — Tam modda fiziksel bellek edinimini dener; --memory=false ile bilerek kapatılır. Varsayılan: `true`.
- `--memory-limit int` — Fiziksel bellek ediniminde saklanacak azami bayt; 0 eşlenen RAM demektir. Analiz boyut sınırı değildir. Varsayılan: `0`.
- `--memory-tool string` — Harici bellek edinim aracının yolu. Varsayılan keşif Windows WinPmem içindir.
- `--memory-tool-arg value` — Harici edinim aracına tek argüman. Seçeneği tekrarlayın; en az bir argüman {output} içermelidir.
- `--operator string` — Edinimi yapan kişinin adı; geliştirici adı otomatik incelemeci kimliği değildir.
- `--output-dir string` — Tam koleksiyonun kök klasörü; içinde bilgisayar adı ve zaman damgalı alt klasörler oluşturulur. Varsayılan: `"output"`.
- `--reserve int` — Hedef dosya sisteminde bırakılacak ek boş alan, bayt. Toplama/ön kontrol içindir; bellek analizine sabit tavan koymaz. Varsayılan: `268435456`.
- `--root string` — Mantıksal toplamada kaynak klasör; tam modda profile ek olarak toplanacak klasör.
- `--scope string` — Yetkilendirilmiş edinim kapsamının açıklaması. Nelerin neden toplandığını anlaşılır yazın.
- `--sign-key string` — Ed25519 özel imza anahtar dosyası. Özel anahtar gizlidir; .pub doğrulama içindir.
- `--system` — Canlı sistem anlık kayıtlarını toplar. Mantıksal modda açıkça etkinleştirilir; tam modda varsayılan açıktır. Varsayılan: `true`.
- `--timeout duration` — Toplama süresi üst sınırı; örneğin 30m veya 4h. Genel bellek analizi/Volatility için otomatik süre tavanı değildir. Varsayılan: `4h0m0s`.

### `source-import`

Seçili çevrimdışı CloudTrail dışa aktarımlarını kaynak bilgisiyle paketler.

```sh
k957 source-import --kind cloudtrail --in cloud-exports --out case-output/imported.k957 --case CASE-001 --operator Analyst --scope "Selected exports"
```

Yalnızca seçili JSON/gzip dışa aktarımları desteklenir; uzaktaki buluttan veri edinmez.

Seçenekler (basılı varsayılan yoksa yardım açık bir varsayılan göstermiyor demektir):

- `--case string` — Toplamada vaka kimliği; case-* inceleme komutlarında türetilmiş vaka klasörünün yolu.
- `--in string` — Girdi dosyası/klasörü: bu komutun yukarıdaki açıklamasındaki türü kullanın. --store ile tek paket --in birlikte kullanılmaz.
- `--kind string` — Komuta göre dışa aktarım türü veya dizin kayıt türü. Örneğin source-import için cloudtrail; sorguda event/finding/activity. Varsayılan: `"cloudtrail"`.
- `--operator string` — Edinimi yapan kişinin adı; geliştirici adı otomatik incelemeci kimliği değildir.
- `--out string` — Yeni çıktı dosyası/klasörü veya keygen için yeni anahtar yolu kökü. Türü komuta göre değişir; mevcut çıktının üzerine yazılmaz.
- `--scope string` — Yetkilendirilmiş edinim kapsamının açıklaması. Nelerin neden toplandığını anlaşılır yazın.
- `--sign-key string` — Ed25519 özel imza anahtar dosyası. Özel anahtar gizlidir; .pub doğrulama içindir.

### `sqlite-acquire`

Ayrı, işlem tutarlı SQLite mantıksal yedeği oluşturur.

```sh
k957 sqlite-acquire --in browser-source/History --out case-output/history.k957 --case CASE-001 --operator Analyst --scope "Selected browser database" --sign-key case-output/examiner.key
```

Türetilmiş yedeğin ve kaynak bilgilerinin paketini üretir. Özgün ana veritabanı/WAL baytlarının yerine geçmez.

Seçenekler (basılı varsayılan yoksa yardım açık bir varsayılan göstermiyor demektir):

- `--case string` — Toplamada vaka kimliği; case-* inceleme komutlarında türetilmiş vaka klasörünün yolu.
- `--in string` — Girdi dosyası/klasörü: bu komutun yukarıdaki açıklamasındaki türü kullanın. --store ile tek paket --in birlikte kullanılmaz.
- `--operator string` — Edinimi yapan kişinin adı; geliştirici adı otomatik incelemeci kimliği değildir.
- `--out string` — Yeni çıktı dosyası/klasörü veya keygen için yeni anahtar yolu kökü. Türü komuta göre değişir; mevcut çıktının üzerine yazılmaz.
- `--scope string` — Yetkilendirilmiş edinim kapsamının açıklaması. Nelerin neden toplandığını anlaşılır yazın.
- `--sign-key string` — Ed25519 özel imza anahtar dosyası. Özel anahtar gizlidir; .pub doğrulama içindir.

### `work-status`

Mevcut devam edilebilir kontrol noktasını inceler.

```sh
k957 work-status --work case-output/checkpoint --verify-parts
```

Edinim durumunu bildirir; parça doğrulaması saklanan baytları okuyup özetleri kontrol eder.

Seçenekler (basılı varsayılan yoksa yardım açık bir varsayılan göstermiyor demektir):

- `--encryption-key string` — AES-256 anahtar dosyası. Şifreli devam için ilk edinimdeki aynı anahtarı kullanın; özel imza anahtarı değildir.
- `--verify-parts` — Kontrol noktasındaki parçaları özetleriyle doğrular; çok sayıda parça ek disk okuması gerektirir. Varsayılan: kapalı.
- `--work string` — Mantıksal edinimin devam edilebilir çalışma klasörü; kaynak ve çıktı dışında olmalıdır.

### `verify`

Bir açık paket veya depodaki tam koleksiyonları doğrular.

```sh
k957 verify --in case-output/demo.k957 --trusted-key case-output/examiner.pub
```

--in yoksa varsayılan ./output deposu taranır. Ortak ayrıştırıcı analiz/paylaşım seçeneklerini de gösterir; --rules, --out, --reviews ve --review-key burada analiz üretmez. --hash-set ve --iocs reddedilir; --policy share içindir. Doğrulamada --in/--store ve --trusted-key kullanın.

Seçenekler (basılı varsayılan yoksa yardım açık bir varsayılan göstermiyor demektir):

- `--custody string` — Tek paket analizine eklenecek teslim zinciri kayıt dosyası.
- `--custody-head string` — Teslim zinciri için bağımsız saklanan beklenen baş özeti.
- `--custody-trust string` — Teslim kayıtlarını doğrulamak için dış aktör/açık anahtar güven listesinin JSON yolu.
- `--hash-set string` — İncelemecinin SHA-256 listesi. known-good/known-bad etiketi inceleme girdisidir; otomatik zararlı kararı değildir.
- `--in string` — Girdi dosyası/klasörü: bu komutun yukarıdaki açıklamasındaki türü kullanın. --store ile tek paket --in birlikte kullanılmaz.
- `--iocs string` — Çevrimdışı göstergelerin JSON dosyası; seçili IP, alan adı ve SHA-256 eşleşmeleri için.
- `--out string` — Yeni çıktı dosyası/klasörü veya keygen için yeni anahtar yolu kökü. Türü komuta göre değişir; mevcut çıktının üzerine yazılmaz.
- `--policy string` — share için maskeleme; case-correlate için saat/kimlik tahminleri JSON dosyası. İki şema birbirinin yerine kullanılamaz.
- `--review-key string` — Değerlendirme kaydı imzası için bağımsız güvenilen açık anahtar.
- `--reviews string` — Tek paket analizine uygulanacak değerlendirme kayıt JSON dosyası.
- `--rules string` — Metin veya yapılandırılmış olay kuralları JSON dosyası; eşleşmeler incelemeci kontrolü gerektirir.
- `--store string` — Tam koleksiyon kök klasörü; --in ile tek paket yolunun alternatifi.
- `--trusted-key string` — Bağımsız edinilmiş Ed25519 açık anahtar dosyası; ilgili paket/rapor imzacısına güveni doğrular.

### `analyze`

Delili doğrular, desteklenen incelemeleri yapar ve rapor üretir.

```sh
k957 analyze --in case-output/demo.k957 --out case-output/analysis-02 --rules examples/rules.json --trusted-key case-output/examiner.pub
```

Tek paket için --in; depo için --store veya varsayılan ./output kullanılır. HTML ve PDF varsayılan çıktıdır. --policy share içindir. Değerlendirme/teslim girdileri ilgili tek paket kapsamını gerektirir.

Seçenekler (basılı varsayılan yoksa yardım açık bir varsayılan göstermiyor demektir):

- `--custody string` — Tek paket analizine eklenecek teslim zinciri kayıt dosyası.
- `--custody-head string` — Teslim zinciri için bağımsız saklanan beklenen baş özeti.
- `--custody-trust string` — Teslim kayıtlarını doğrulamak için dış aktör/açık anahtar güven listesinin JSON yolu.
- `--hash-set string` — İncelemecinin SHA-256 listesi. known-good/known-bad etiketi inceleme girdisidir; otomatik zararlı kararı değildir.
- `--in string` — Girdi dosyası/klasörü: bu komutun yukarıdaki açıklamasındaki türü kullanın. --store ile tek paket --in birlikte kullanılmaz.
- `--iocs string` — Çevrimdışı göstergelerin JSON dosyası; seçili IP, alan adı ve SHA-256 eşleşmeleri için.
- `--out string` — Yeni çıktı dosyası/klasörü veya keygen için yeni anahtar yolu kökü. Türü komuta göre değişir; mevcut çıktının üzerine yazılmaz.
- `--policy string` — share için maskeleme; case-correlate için saat/kimlik tahminleri JSON dosyası. İki şema birbirinin yerine kullanılamaz.
- `--review-key string` — Değerlendirme kaydı imzası için bağımsız güvenilen açık anahtar.
- `--reviews string` — Tek paket analizine uygulanacak değerlendirme kayıt JSON dosyası.
- `--rules string` — Metin veya yapılandırılmış olay kuralları JSON dosyası; eşleşmeler incelemeci kontrolü gerektirir.
- `--store string` — Tam koleksiyon kök klasörü; --in ile tek paket yolunun alternatifi.
- `--trusted-key string` — Bağımsız edinilmiş Ed25519 açık anahtar dosyası; ilgili paket/rapor imzacısına güveni doğrular.

### `case`

Koleksiyonlar arasında türetilmiş inceleme dosyası oluşturur.

```sh
k957 case --store case-output/collections --out case-output/dossier --rules examples/event-rules.json
```

Sorgulanabilir SQLite dizini, envanter, zaman çizelgeleri ve HTML/PDF üretir. Varsayılan çıktı delil deposu dışında case/<UTC zaman> klasörüdür.

Seçenekler (basılı varsayılan yoksa yardım açık bir varsayılan göstermiyor demektir):

- `--hash-set string` — İncelemecinin SHA-256 listesi. known-good/known-bad etiketi inceleme girdisidir; otomatik zararlı kararı değildir.
- `--iocs string` — Çevrimdışı göstergelerin JSON dosyası; seçili IP, alan adı ve SHA-256 eşleşmeleri için.
- `--out string` — Yeni çıktı dosyası/klasörü veya keygen için yeni anahtar yolu kökü. Türü komuta göre değişir; mevcut çıktının üzerine yazılmaz.
- `--review value` — case için tekrarlanabilir değerlendirme kayıt yolu; tek paket analizindeki --reviews seçeneğinden farklı yazılır.
- `--review-key string` — Değerlendirme kaydı imzası için bağımsız güvenilen açık anahtar.
- `--rules string` — Metin veya yapılandırılmış olay kuralları JSON dosyası; eşleşmeler incelemeci kontrolü gerektirir.
- `--store string` — Tam koleksiyon kök klasörü; --in ile tek paket yolunun alternatifi.
- `--trusted-key string` — Bağımsız edinilmiş Ed25519 açık anahtar dosyası; ilgili paket/rapor imzacısına güveni doğrular.

### `case-query`

Kapsamı belirlenmiş dizin kayıtlarından sınırlı bir sayfa arar.

```sh
k957 case-query --case case-output/dossier --kind event --text "failed" --limit 50 --offset 0
```

JSON sayfası ve kapsam döndürür. Filtreler birlikte uygulanır; metin araması gerçek alt dize aramasıdır. Ortak ayrıştırıcıdaki --port yalnızca case-serve sunucusunu etkiler.

Seçenekler (basılı varsayılan yoksa yardım açık bir varsayılan göstermiyor demektir):

- `--after string` — Başlangıç zamanı dahil RFC3339 filtre, örneğin 2026-10-01T00:00:00Z. Z, UTC anlamına gelir.
- `--before string` — Bitiş zamanı dahil RFC3339 filtre, örneğin 2026-10-02T00:00:00Z.
- `--case string` — Toplamada vaka kimliği; case-* inceleme komutlarında türetilmiş vaka klasörünün yolu.
- `--digest string` — Sorguyu tek koleksiyonun tam SHA-256 özetiyle sınırlar; dosya özetiyle karıştırmayın.
- `--evidence string` — Koleksiyon içindeki delil kimliğine göre sorgu kapsamı. Tek başına farklı koleksiyonlarda küresel kimlik değildir.
- `--host string` — Koleksiyonun bilgisayar adına göre tam kapsam filtresi.
- `--kind string` — Komuta göre dışa aktarım türü veya dizin kayıt türü. Örneğin source-import için cloudtrail; sorguda event/finding/activity.
- `--limit int` — Sorgu sayfasının satır sayısı. Normal sorgu/seçim 1..200, asistan 1..20; bütün sonuç sayısı değildir. Varsayılan: `100`.
- `--native-parser string` — Yalnızca olay satırlarında birebir yerel ayrıştırıcı adı; örneğin EVTX, SQLite veya USN.
- `--native-record string` — Yalnızca olay satırlarında birebir özgün kayıt kimliği; kaynak kapsamıyla birlikte kullanın.
- `--offset int` — Sorguda atlanacak satır sayısı; disk incelemesinde dosya sistemi başlangıcının sektör sayısı. Bayt anlamına gelmez.
- `--port int` — Yalnızca case-serve yerel sunucu portu; 0 boş port seçer. Sorgu komutunda sunucu açmaz.
- `--text string` — Gerçek alt dize arama filtresi; düzenli ifade veya SQL değildir.
- `--usn-file-id string` — USN ham küçük uçlu dosya kimliğinin 16/32 onaltılık karakteri; 0x eklemeyin, baştaki sıfırları/byte sırasını koruyun.

### `case-assistant`

Seçilen kaynaklı kayıtları açıkça belirtilen önbellekteki yerel modele sorar.

```sh
k957 case-assistant --case case-output/dossier --model MODEL_NAME:TAG --kind event --text "failed" --limit 20 --question "Summarize these selected records with citations" --out case-output/proposal.json
```

MODEL_NAME:TAG yerine önbellekteki gerçek Ollama modelini yazın. Seçilen girdileri ve öneriyi saklar; otomatik bulgu kararı vermez.

Seçenekler (basılı varsayılan yoksa yardım açık bir varsayılan göstermiyor demektir):

- `--case string` — Toplamada vaka kimliği; case-* inceleme komutlarında türetilmiş vaka klasörünün yolu.
- `--digest string` — Sorguyu tek koleksiyonun tam SHA-256 özetiyle sınırlar; dosya özetiyle karıştırmayın.
- `--endpoint string` — Açıkça seçilen yerel Ollama adresi. Uzak hizmet adresi değildir; loopback erişimi gerekir. Varsayılan: `"http://127.0.0.1:11434"`.
- `--evidence string` — Koleksiyon içindeki delil kimliğine göre sorgu kapsamı. Tek başına farklı koleksiyonlarda küresel kimlik değildir.
- `--kind string` — Komuta göre dışa aktarım türü veya dizin kayıt türü. Örneğin source-import için cloudtrail; sorguda event/finding/activity. Varsayılan: `"event"`.
- `--limit int` — Sorgu sayfasının satır sayısı. Normal sorgu/seçim 1..200, asistan 1..20; bütün sonuç sayısı değildir. Varsayılan: `20`.
- `--model string` — Önceden yerel önbelleğe alınmış gerçek model etiketi; :tag bölümü gerekir. Model kendiliğinden indirilmez.
- `--model-digest string` — İsteğe bağlı, önbellekteki model için beklenen tam özet; değişen model kullanımını reddeder.
- `--offset int` — Sorguda atlanacak satır sayısı; disk incelemesinde dosya sistemi başlangıcının sektör sayısı. Bayt anlamına gelmez.
- `--out string` — Yeni çıktı dosyası/klasörü veya keygen için yeni anahtar yolu kökü. Türü komuta göre değişir; mevcut çıktının üzerine yazılmaz.
- `--question string` — Yerel asistana sorulan sınırlı incelemeci sorusu; kayıt seçimi için --text ayrıca gerekir.
- `--text string` — Gerçek alt dize arama filtresi; düzenli ifade veya SQL değildir.

### `assistant-review`

Asistan önerisine ayrı, imzalı incelemeci kararı kaydeder.

```sh
k957 assistant-review --case case-output/dossier --in case-output/proposal.json --decision reject --analyst Analyst --note "Source context does not support the proposal" --sign-key case-output/examiner.key --out case-output/proposal-review
```

Kabul/ret öneriye ilişkindir; modeli doğrulamaz, iddiaları özgün delile dönüştürmez.

Seçenekler (basılı varsayılan yoksa yardım açık bir varsayılan göstermiyor demektir):

- `--analyst string` — Değerlendirme, seçim veya öneri kararını veren kişinin kimliği.
- `--case string` — Toplamada vaka kimliği; case-* inceleme komutlarında türetilmiş vaka klasörünün yolu.
- `--decision string` — review için confirmed/rejected/needs-review; assistant-review için accept/reject. Karar gerekçesini --note ile yazın.
- `--in string` — Girdi dosyası/klasörü: bu komutun yukarıdaki açıklamasındaki türü kullanın. --store ile tek paket --in birlikte kullanılmaz.
- `--note string` — Karar, seçim veya teslim için gerekli açıklama/gerekçe; özgün delil içeriğini değiştirmez.
- `--out string` — Yeni çıktı dosyası/klasörü veya keygen için yeni anahtar yolu kökü. Türü komuta göre değişir; mevcut çıktının üzerine yazılmaz.
- `--sign-key string` — Ed25519 özel imza anahtar dosyası. Özel anahtar gizlidir; .pub doğrulama içindir.

### `case-correlate`

Açık saat/kimlik tahminleriyle zamansal adaylar türetir.

```sh
k957 case-correlate --case case-output/dossier --field user --window 5m --out case-output/candidates.json
```

İsteğe bağlı --policy tahminleri sağlar; yeterli tahmin yoksa belirsizlik görünür kalır. Adaylar nedensellik bulgusu değildir.

Seçenekler (basılı varsayılan yoksa yardım açık bir varsayılan göstermiyor demektir):

- `--case string` — Toplamada vaka kimliği; case-* inceleme komutlarında türetilmiş vaka klasörünün yolu.
- `--field string` — İlişkilendirme alanı: user, host, source_ip veya destination_ip. Varsayılan: `"user"`.
- `--out string` — Yeni çıktı dosyası/klasörü veya keygen için yeni anahtar yolu kökü. Türü komuta göre değişir; mevcut çıktının üzerine yazılmaz.
- `--policy string` — share için maskeleme; case-correlate için saat/kimlik tahminleri JSON dosyası. İki şema birbirinin yerine kullanılamaz.
- `--window duration` — Zamansal aday aralığı; en çok 24h. Yakın zamanlı olmak nedensellik değildir. Varsayılan: `5m0s`.

### `case-bookmark`

İmzalı incelemeci notunu ve seçilen sorgu sayfasını saklar.

```sh
k957 case-bookmark --case case-output/dossier --kind event --text "failed" --limit 50 --title "Authentication review" --analyst Analyst --note "Selected for source verification" --sign-key case-output/examiner.key --out case-output/bookmark
```

Seçim üst verisi, kaynağa bağlı satırlar ve HTML/PDF oluşturur. Sayfa sınırları beyan edilen seçimin parçasıdır.

Seçenekler (basılı varsayılan yoksa yardım açık bir varsayılan göstermiyor demektir):

- `--after string` — Başlangıç zamanı dahil RFC3339 filtre, örneğin 2026-10-01T00:00:00Z. Z, UTC anlamına gelir.
- `--analyst string` — Değerlendirme, seçim veya öneri kararını veren kişinin kimliği.
- `--before string` — Bitiş zamanı dahil RFC3339 filtre, örneğin 2026-10-02T00:00:00Z.
- `--case string` — Toplamada vaka kimliği; case-* inceleme komutlarında türetilmiş vaka klasörünün yolu.
- `--digest string` — Sorguyu tek koleksiyonun tam SHA-256 özetiyle sınırlar; dosya özetiyle karıştırmayın.
- `--evidence string` — Koleksiyon içindeki delil kimliğine göre sorgu kapsamı. Tek başına farklı koleksiyonlarda küresel kimlik değildir.
- `--host string` — Koleksiyonun bilgisayar adına göre tam kapsam filtresi.
- `--kind string` — Komuta göre dışa aktarım türü veya dizin kayıt türü. Örneğin source-import için cloudtrail; sorguda event/finding/activity.
- `--limit int` — Sorgu sayfasının satır sayısı. Normal sorgu/seçim 1..200, asistan 1..20; bütün sonuç sayısı değildir. Varsayılan: `100`.
- `--native-parser string` — Yalnızca olay satırlarında birebir yerel ayrıştırıcı adı; örneğin EVTX, SQLite veya USN.
- `--native-record string` — Yalnızca olay satırlarında birebir özgün kayıt kimliği; kaynak kapsamıyla birlikte kullanın.
- `--note string` — Karar, seçim veya teslim için gerekli açıklama/gerekçe; özgün delil içeriğini değiştirmez.
- `--offset int` — Sorguda atlanacak satır sayısı; disk incelemesinde dosya sistemi başlangıcının sektör sayısı. Bayt anlamına gelmez.
- `--out string` — Yeni çıktı dosyası/klasörü veya keygen için yeni anahtar yolu kökü. Türü komuta göre değişir; mevcut çıktının üzerine yazılmaz.
- `--sign-key string` — Ed25519 özel imza anahtar dosyası. Özel anahtar gizlidir; .pub doğrulama içindir.
- `--text string` — Gerçek alt dize arama filtresi; düzenli ifade veya SQL değildir.
- `--title string` — İmzalı seçimin incelemeciye gösterilen başlığı.
- `--usn-file-id string` — USN ham küçük uçlu dosya kimliğinin 16/32 onaltılık karakteri; 0x eklemeyin, baştaki sıfırları/byte sırasını koruyun.

### `case-serve`

Aynı bilgisayarda belirteç korumalı salt okunur görüntüleyici sunar.

```sh
k957 case-serve --case case-output/dossier --port 0
```

0 portu boş yerel port seçer. Yazdırılan adresi açıp işlemi çalışır tutun. Uzak çok kullanıcılı hizmet değildir.

Seçenekler (basılı varsayılan yoksa yardım açık bir varsayılan göstermiyor demektir):

- `--after string` — Başlangıç zamanı dahil RFC3339 filtre, örneğin 2026-10-01T00:00:00Z. Z, UTC anlamına gelir.
- `--before string` — Bitiş zamanı dahil RFC3339 filtre, örneğin 2026-10-02T00:00:00Z.
- `--case string` — Toplamada vaka kimliği; case-* inceleme komutlarında türetilmiş vaka klasörünün yolu.
- `--digest string` — Sorguyu tek koleksiyonun tam SHA-256 özetiyle sınırlar; dosya özetiyle karıştırmayın.
- `--evidence string` — Koleksiyon içindeki delil kimliğine göre sorgu kapsamı. Tek başına farklı koleksiyonlarda küresel kimlik değildir.
- `--host string` — Koleksiyonun bilgisayar adına göre tam kapsam filtresi.
- `--kind string` — Komuta göre dışa aktarım türü veya dizin kayıt türü. Örneğin source-import için cloudtrail; sorguda event/finding/activity.
- `--limit int` — Sorgu sayfasının satır sayısı. Normal sorgu/seçim 1..200, asistan 1..20; bütün sonuç sayısı değildir. Varsayılan: `100`.
- `--native-parser string` — Yalnızca olay satırlarında birebir yerel ayrıştırıcı adı; örneğin EVTX, SQLite veya USN.
- `--native-record string` — Yalnızca olay satırlarında birebir özgün kayıt kimliği; kaynak kapsamıyla birlikte kullanın.
- `--offset int` — Sorguda atlanacak satır sayısı; disk incelemesinde dosya sistemi başlangıcının sektör sayısı. Bayt anlamına gelmez.
- `--port int` — Yalnızca case-serve yerel sunucu portu; 0 boş port seçer. Sorgu komutunda sunucu açmaz.
- `--text string` — Gerçek alt dize arama filtresi; düzenli ifade veya SQL değildir.
- `--usn-file-id string` — USN ham küçük uçlu dosya kimliğinin 16/32 onaltılık karakteri; 0x eklemeyin, baştaki sıfırları/byte sırasını koruyun.

### `rules-evaluate`

Kuralları açıkça etiketlenmiş örnek kümesine karşı ölçer.

```sh
k957 rules-evaluate --rules examples/event-rules.json --corpus labelled-corpus.json --out case-output/rule-measurements.json
```

Belgelenmiş şemada gerçek etiketli örnek kümesi gerekir. Doğru/yanlış pozitif/negatifleri raporlar; ölçüm yalnızca o kümeyi açıklar.

Seçenekler (basılı varsayılan yoksa yardım açık bir varsayılan göstermiyor demektir):

- `--corpus string` — Kural değerlendirmesi için etiketli örnek kümesinin JSON yolu; sıradan delil paketi değildir.
- `--out string` — Yeni çıktı dosyası/klasörü veya keygen için yeni anahtar yolu kökü. Türü komuta göre değişir; mevcut çıktının üzerine yazılmaz.
- `--rules string` — Metin veya yapılandırılmış olay kuralları JSON dosyası; eşleşmeler incelemeci kontrolü gerektirir.

### `report-seal`

Tamamlanan türetilmiş rapor demetindeki bütün dosyaları imzalar.

```sh
k957 report-seal --report case-output/report --key case-output/examiner.key
```

Bildirim ve Ed25519 mühür oluşturur; sonradan dosya eklemek/değiştirmek doğrulamayı bozar. Bu komutta --report ve --key işler; ortak yardımın belge üretim/güven seçenekleri diğer rapor komutları içindir.

Seçenekler (basılı varsayılan yoksa yardım açık bir varsayılan göstermiyor demektir):

- `--analysis string` — Mevcut sürümün ürettiği analysis.json dosyasının yolu; HTML veya PDF yolu değildir.
- `--format string` — Belge türü: pdf, docx veya both. both iki belgeyi üretir. Varsayılan: `"both"`.
- `--key string` — Komuta göre AES-256 şifreleme anahtarı veya Ed25519 rapor mühürleme özel anahtarı. Birbirinin yerine kullanılamaz.
- `--out string` — Yeni çıktı dosyası/klasörü veya keygen için yeni anahtar yolu kökü. Türü komuta göre değişir; mevcut çıktının üzerine yazılmaz.
- `--report string` — Mühürlenecek/doğrulanacak türetilmiş rapor klasörü; özgün .k957 paket yolu değildir.
- `--trusted-key string` — Bağımsız edinilmiş Ed25519 açık anahtar dosyası; ilgili paket/rapor imzacısına güveni doğrular.

### `report-verify`

Rapor demetini saklanan mührüne karşı doğrular.

```sh
k957 report-verify --report case-output/report --trusted-key case-output/examiner.pub
```

--report ve isteğe bağlı bağımsız --trusted-key kullanın. Demet baytlarını/kaynak bağlarını kontrol eder; olgusal doğruluk veya güvenilir zamanı kanıtlamaz. Diğer ortak rapor seçenekleri burada belge üretmez.

Seçenekler (basılı varsayılan yoksa yardım açık bir varsayılan göstermiyor demektir):

- `--analysis string` — Mevcut sürümün ürettiği analysis.json dosyasının yolu; HTML veya PDF yolu değildir.
- `--format string` — Belge türü: pdf, docx veya both. both iki belgeyi üretir. Varsayılan: `"both"`.
- `--key string` — Komuta göre AES-256 şifreleme anahtarı veya Ed25519 rapor mühürleme özel anahtarı. Birbirinin yerine kullanılamaz.
- `--out string` — Yeni çıktı dosyası/klasörü veya keygen için yeni anahtar yolu kökü. Türü komuta göre değişir; mevcut çıktının üzerine yazılmaz.
- `--report string` — Mühürlenecek/doğrulanacak türetilmiş rapor klasörü; özgün .k957 paket yolu değildir.
- `--trusted-key string` — Bağımsız edinilmiş Ed25519 açık anahtar dosyası; ilgili paket/rapor imzacısına güveni doğrular.

### `report-documents`

Mevcut analiz JSON kaydından yerel PDF ve/veya DOCX üretir.

```sh
k957 report-documents --analysis case-output/report/analysis.json --out case-output/documents --format both
```

--analysis, --out ve --format kullanın. analysis.json ile eksiltmeleri açıklayan documents.json saklanır. Ortak --report/--key/--trusted-key mühürleme/doğrulama içindir.

Seçenekler (basılı varsayılan yoksa yardım açık bir varsayılan göstermiyor demektir):

- `--analysis string` — Mevcut sürümün ürettiği analysis.json dosyasının yolu; HTML veya PDF yolu değildir.
- `--format string` — Belge türü: pdf, docx veya both. both iki belgeyi üretir. Varsayılan: `"both"`.
- `--key string` — Komuta göre AES-256 şifreleme anahtarı veya Ed25519 rapor mühürleme özel anahtarı. Birbirinin yerine kullanılamaz.
- `--out string` — Yeni çıktı dosyası/klasörü veya keygen için yeni anahtar yolu kökü. Türü komuta göre değişir; mevcut çıktının üzerine yazılmaz.
- `--report string` — Mühürlenecek/doğrulanacak türetilmiş rapor klasörü; özgün .k957 paket yolu değildir.
- `--trusted-key string` — Bağımsız edinilmiş Ed25519 açık anahtar dosyası; ilgili paket/rapor imzacısına güveni doğrular.

### `disk-examine`

Mevcut ham dosya sistemi/disk imajını Sleuth Kit fls ile listeler.

```sh
k957 disk-examine --image images/disk.raw --sha256 IMAGE_SHA256 --tool tools/fls --out case-output/disk-list
```

İmaja özgü inode referanslarını kaydedin. --offset bayt değil sektör sayısıdır. Ortak yardımda --inode, disk-recover içindir; bu listelemedir, imaj edinimi değildir.

Seçenekler (basılı varsayılan yoksa yardım açık bir varsayılan göstermiyor demektir):

- `--image string` — Mevcut ham disk/dosya sistemi veya raw/LiME bellek imajının yolu; komuta göre türü değişir.
- `--inode string` — Yalnızca kurtarma için bu imaja özgü inode referansı; disk listeleme çıktısından alın.
- `--offset int` — Sorguda atlanacak satır sayısı; disk incelemesinde dosya sistemi başlangıcının sektör sayısı. Bayt anlamına gelmez.
- `--out string` — Yeni çıktı dosyası/klasörü veya keygen için yeni anahtar yolu kökü. Türü komuta göre değişir; mevcut çıktının üzerine yazılmaz.
- `--sector-size int` — Disk sektör boyutu; 512..4096 aralığında ikinin kuvveti olan bayt sayısı. Varsayılan: `512`.
- `--sha256 string` — İmajın beklenen 64 onaltılık karakterlik SHA-256 özeti; güvenilen edinim kaydından alın. Kurtarmada gerekir.
- `--tool string` — Bu inceleme için güvenilen harici Volatility veya Sleuth Kit çalıştırılabilir dosyası.

### `disk-recover`

icat ile açıkça seçilen, imaja özgü tek inode içeriğini çıkarır.

```sh
k957 disk-recover --image images/disk.raw --sha256 IMAGE_SHA256 --inode INODE_REFERENCE --tool tools/icat --out case-output/recovered
```

Yer tutucuları güvenilen özet ve bu imajdaki inode ile değiştirin. Kurtarma özgün yolu veya çalıştırma geçmişini kanıtlamaz.

Seçenekler (basılı varsayılan yoksa yardım açık bir varsayılan göstermiyor demektir):

- `--image string` — Mevcut ham disk/dosya sistemi veya raw/LiME bellek imajının yolu; komuta göre türü değişir.
- `--inode string` — Yalnızca kurtarma için bu imaja özgü inode referansı; disk listeleme çıktısından alın.
- `--offset int` — Sorguda atlanacak satır sayısı; disk incelemesinde dosya sistemi başlangıcının sektör sayısı. Bayt anlamına gelmez.
- `--out string` — Yeni çıktı dosyası/klasörü veya keygen için yeni anahtar yolu kökü. Türü komuta göre değişir; mevcut çıktının üzerine yazılmaz.
- `--sector-size int` — Disk sektör boyutu; 512..4096 aralığında ikinin kuvveti olan bayt sayısı. Varsayılan: `512`.
- `--sha256 string` — İmajın beklenen 64 onaltılık karakterlik SHA-256 özeti; güvenilen edinim kaydından alın. Kurtarmada gerekir.
- `--tool string` — Bu inceleme için güvenilen harici Volatility veya Sleuth Kit çalıştırılabilir dosyası.

### `memory-examine`

Doğrulanmış RAM imajında kurulu Volatility yöntemlerini dener.

```sh
k957 memory-examine --image images/memory.lime --sha256 IMAGE_SHA256 --tool tools/vol --symbols offline-symbols --platform windows --plugin all --out case-output/kernel-results
```

Bu bilgisayarın değil imajın platformunu seçin. Kurulu uygun eklentiler denenir; eksik parametre/modül/sembol ve hatalar ayrı kaydedilir.

Seçenekler (basılı varsayılan yoksa yardım açık bir varsayılan göstermiyor demektir):

- `--image string` — Mevcut ham disk/dosya sistemi veya raw/LiME bellek imajının yolu; komuta göre türü değişir.
- `--out string` — Yeni çıktı dosyası/klasörü veya keygen için yeni anahtar yolu kökü. Türü komuta göre değişir; mevcut çıktının üzerine yazılmaz.
- `--platform string` — Bellek imajının platformu: linux, windows veya mac. Komutun çalıştığı bilgisayardan farklı olabilir. Varsayılan: komutun çalıştığı işletim sistemi; farklı kaynak için açıkça seçin.
- `--plugin string` — all kurulu uygun eklentileri dener; belirli eklenti adı tek yöntemi seçer. Kurulu araç ve semboller kapsamı belirler. Varsayılan: `"all"`.
- `--sha256 string` — İmajın beklenen 64 onaltılık karakterlik SHA-256 özeti; güvenilen edinim kaydından alın. Kurtarmada gerekir.
- `--symbols string` — Uyumlu çevrimdışı JSON/sıkıştırılmış sembol klasörü; eklenti kodu klasörü değildir.
- `--tool string` — Bu inceleme için güvenilen harici Volatility veya Sleuth Kit çalıştırılabilir dosyası.
- `--work-dir string` — Harici bellek analizinin özel kopyaları için yeterli boş alana sahip mevcut çalışma alanı.

### `share`

Doğrulanmış delilden ayrı maskelenmiş rapor dışa aktarır.

```sh
k957 share --in case-output/demo.k957 --out case-output/shared-02 --rules examples/rules.json --trusted-key case-output/examiner.pub
```

Tek paket --in gerekir; depo işlemi değildir. --policy paylaşım politikasıdır, zamansal ilişkilendirme politikası değildir. Dağıtmadan bütün çıktıyı kontrol edin.

Seçenekler (basılı varsayılan yoksa yardım açık bir varsayılan göstermiyor demektir):

- `--custody string` — Tek paket analizine eklenecek teslim zinciri kayıt dosyası.
- `--custody-head string` — Teslim zinciri için bağımsız saklanan beklenen baş özeti.
- `--custody-trust string` — Teslim kayıtlarını doğrulamak için dış aktör/açık anahtar güven listesinin JSON yolu.
- `--hash-set string` — İncelemecinin SHA-256 listesi. known-good/known-bad etiketi inceleme girdisidir; otomatik zararlı kararı değildir.
- `--in string` — Girdi dosyası/klasörü: bu komutun yukarıdaki açıklamasındaki türü kullanın. --store ile tek paket --in birlikte kullanılmaz.
- `--iocs string` — Çevrimdışı göstergelerin JSON dosyası; seçili IP, alan adı ve SHA-256 eşleşmeleri için.
- `--out string` — Yeni çıktı dosyası/klasörü veya keygen için yeni anahtar yolu kökü. Türü komuta göre değişir; mevcut çıktının üzerine yazılmaz.
- `--policy string` — share için maskeleme; case-correlate için saat/kimlik tahminleri JSON dosyası. İki şema birbirinin yerine kullanılamaz.
- `--review-key string` — Değerlendirme kaydı imzası için bağımsız güvenilen açık anahtar.
- `--reviews string` — Tek paket analizine uygulanacak değerlendirme kayıt JSON dosyası.
- `--rules string` — Metin veya yapılandırılmış olay kuralları JSON dosyası; eşleşmeler incelemeci kontrolü gerektirir.
- `--store string` — Tam koleksiyon kök klasörü; --in ile tek paket yolunun alternatifi.
- `--trusted-key string` — Bağımsız edinilmiş Ed25519 açık anahtar dosyası; ilgili paket/rapor imzacısına güveni doğrular.

### `review`

Yeni bağımsız değerlendirme kaydına analist kararı ekler.

```sh
k957 review --analysis case-output/report/analysis.json --finding FINDING_ID --analyst Analyst --decision needs-review --note "Verify source context" --out case-output/review-02.json --sign-key case-output/examiner.key
```

Kararlar confirmed, rejected veya needs-review değerleridir. --previous ile devam edip yeni çıktı yazın; --previous-key önceki imzalı kaydı bağımsız güvenilen anahtarla doğrular.

Seçenekler (basılı varsayılan yoksa yardım açık bir varsayılan göstermiyor demektir):

- `--analysis string` — Mevcut sürümün ürettiği analysis.json dosyasının yolu; HTML veya PDF yolu değildir.
- `--analyst string` — Değerlendirme, seçim veya öneri kararını veren kişinin kimliği.
- `--decision string` — review için confirmed/rejected/needs-review; assistant-review için accept/reject. Karar gerekçesini --note ile yazın.
- `--finding string` — Mevcut analysis.json içindeki kalıcı bulgu kimliği; satır numarası değildir.
- `--note string` — Karar, seçim veya teslim için gerekli açıklama/gerekçe; özgün delil içeriğini değiştirmez.
- `--out string` — Yeni çıktı dosyası/klasörü veya keygen için yeni anahtar yolu kökü. Türü komuta göre değişir; mevcut çıktının üzerine yazılmaz.
- `--previous string` — Devam edilecek önceki değerlendirme/teslim kaydı; çıktı için yine yeni yol seçilir.
- `--previous-key string` — Önceki imzalı değerlendirme kaydı için bağımsız güvenilen açık anahtar.
- `--sign-key string` — Ed25519 özel imza anahtar dosyası. Özel anahtar gizlidir; .pub doğrulama içindir.

### `custody`

Doğrulanmış paket için imzalı teslim/zilyetlik beyanı ekler.

```sh
k957 custody --in case-output/demo.k957 --trusted-key case-output/examiner.pub --trust actor-trust.json --action register --actor Analyst --sign-key case-output/examiner.key --location "Evidence storage" --note "Initial registration" --out case-output/custody-01.json
```

Önce gerçek aktör açık anahtarını içeren actor-trust.json oluşturun. transfer alıcı önerir; accept alıcı tarafından imzalanır. Ortak yardımdaki --anchor/--anchor-key, custody-verify içindir.

Seçenekler (basılı varsayılan yoksa yardım açık bir varsayılan göstermiyor demektir):

- `--action string` — İşlem türü: register ilk kayıt; transfer teslim önerisi; accept kabul; cancel iptal; note not ekleme. Geçerli zincir durumu gerekir.
- `--actor string` — Dış güven listesindeki birebir aktör kimliği. Bu kişinin özel imza anahtarıyla uyumlu olmalıdır.
- `--anchor string` — Dışarıda bağımsız saklanan imzalı teslim zinciri başı dosyası; custody-verify için.
- `--anchor-key string` — Çapayı imzalayan bağımsız tanığın güvenilen açık anahtar dosyası; --anchor ile gerekir.
- `--at string` — Beyan edilen olay zamanı, RFC3339 biçimi. Verilmezse şimdiki zaman; güvenilir zaman damgası değildir.
- `--expected-head string` — Önceki/güncel teslim zincirinin bağımsız saklanan baş özeti; geriye alma tespiti için.
- `--in string` — Girdi dosyası/klasörü: bu komutun yukarıdaki açıklamasındaki türü kullanın. --store ile tek paket --in birlikte kullanılmaz.
- `--location string` — Beyan edilen saklama veya teslim yeri; yazılan metin fiziksel yeri doğrulamaz.
- `--note string` — Karar, seçim veya teslim için gerekli açıklama/gerekçe; özgün delil içeriğini değiştirmez.
- `--out string` — Yeni çıktı dosyası/klasörü veya keygen için yeni anahtar yolu kökü. Türü komuta göre değişir; mevcut çıktının üzerine yazılmaz.
- `--previous string` — Devam edilecek önceki değerlendirme/teslim kaydı; çıktı için yine yeni yol seçilir.
- `--sign-key string` — Ed25519 özel imza anahtar dosyası. Özel anahtar gizlidir; .pub doğrulama içindir.
- `--to string` — Yalnızca transfer işlemindeki alıcının güven listesindeki kimliği.
- `--trust string` — Dış aktör/açık anahtar güven politikası JSON dosyası; paketin gömülü anahtarı değildir.
- `--trusted-key string` — Bağımsız edinilmiş Ed25519 açık anahtar dosyası; ilgili paket/rapor imzacısına güveni doğrular.

### `custody-anchor`

Bağımsız dış saklama için teslim zinciri başını imzalar.

```sh
k957 custody-anchor --ledger case-output/custody-01.json --trust actor-trust.json --sign-key witness.key --witness Witness --reference "Separate retention record" --out case-output/head-anchor.json
```

Bağımsız tanık anahtarı kullanın, çapayı delil/zincirden ayrı saklayın. İkisini yalnızca birlikte tutmak, ikisinin birlikte eskiye alınmasını tespit etmez.

Seçenekler (basılı varsayılan yoksa yardım açık bir varsayılan göstermiyor demektir):

- `--ledger string` — Doğrulanacak veya çapalanacak teslim zinciri JSON kaydı.
- `--out string` — Yeni çıktı dosyası/klasörü veya keygen için yeni anahtar yolu kökü. Türü komuta göre değişir; mevcut çıktının üzerine yazılmaz.
- `--reference string` — Bağımsız baş saklama kaydının dış referansı; tanık notu olarak saklanır.
- `--sign-key string` — Ed25519 özel imza anahtar dosyası. Özel anahtar gizlidir; .pub doğrulama içindir.
- `--trust string` — Dış aktör/açık anahtar güven politikası JSON dosyası; paketin gömülü anahtarı değildir.
- `--witness string` — Bağımsız zincir başını imzalayan tanığın beyan edilen kimliği.

### `custody-verify`

İmzaları, aktör politikasını, teslim durumunu ve saklanan başı doğrular.

```sh
k957 custody-verify --in case-output/demo.k957 --trusted-key case-output/examiner.pub --ledger case-output/custody-01.json --trust actor-trust.json --anchor case-output/head-anchor.json --anchor-key witness.pub
```

Alternatif olarak bağımsız saklanan --expected-head kullanın. Beyan edilen teslim/zaman fiziksel teslim kanıtı veya güvenilir zaman damgası değildir.

Seçenekler (basılı varsayılan yoksa yardım açık bir varsayılan göstermiyor demektir):

- `--anchor string` — Dışarıda bağımsız saklanan imzalı teslim zinciri başı dosyası; custody-verify için.
- `--anchor-key string` — Çapayı imzalayan bağımsız tanığın güvenilen açık anahtar dosyası; --anchor ile gerekir.
- `--expected-head string` — Önceki/güncel teslim zincirinin bağımsız saklanan baş özeti; geriye alma tespiti için.
- `--in string` — Girdi dosyası/klasörü: bu komutun yukarıdaki açıklamasındaki türü kullanın. --store ile tek paket --in birlikte kullanılmaz.
- `--ledger string` — Doğrulanacak veya çapalanacak teslim zinciri JSON kaydı.
- `--trust string` — Dış aktör/açık anahtar güven politikası JSON dosyası; paketin gömülü anahtarı değildir.
- `--trusted-key string` — Bağımsız edinilmiş Ed25519 açık anahtar dosyası; ilgili paket/rapor imzacısına güveni doğrular.

### `keygen`

Ed25519 imza anahtar çifti oluşturur.

```sh
k957 keygen --out case-output/examiner-02
```

examiner-02.key ve examiner-02.pub oluşturur; özel .key gizli tutulur, .pub bağımsız saklanır/paylaşılır.

Seçenekler (basılı varsayılan yoksa yardım açık bir varsayılan göstermiyor demektir):

- `--out string` — Yeni çıktı dosyası/klasörü veya keygen için yeni anahtar yolu kökü. Türü komuta göre değişir; mevcut çıktının üzerine yazılmaz.

### `encryption-key`

Rastgele AES-256 taşıma anahtarı oluşturur.

```sh
k957 encryption-key --out case-output/transport-02.key
```

Yeni simetrik anahtar dosyası oluşturur. Açık/özel anahtar çifti değildir; şifreli paketle birlikte paylaşılmamalıdır.

Seçenekler (basılı varsayılan yoksa yardım açık bir varsayılan göstermiyor demektir):

- `--out string` — Yeni çıktı dosyası/klasörü veya keygen için yeni anahtar yolu kökü. Türü komuta göre değişir; mevcut çıktının üzerine yazılmaz.

### `seal`

Mevcut dosyayı doğrulanabilir akış çerçeveleriyle şifreler.

```sh
k957 seal --in case-output/demo.k957 --out case-output/demo.encrypted --key case-output/transport.key
```

Yeni şifreli dosya yazar. Delil imzası oluşturmaz; imza iş akışını ayrıca kullanın.

Seçenekler (basılı varsayılan yoksa yardım açık bir varsayılan göstermiyor demektir):

- `--in string` — Girdi dosyası/klasörü: bu komutun yukarıdaki açıklamasındaki türü kullanın. --store ile tek paket --in birlikte kullanılmaz.
- `--key string` — Komuta göre AES-256 şifreleme anahtarı veya Ed25519 rapor mühürleme özel anahtarı. Birbirinin yerine kullanılamaz.
- `--out string` — Yeni çıktı dosyası/klasörü veya keygen için yeni anahtar yolu kökü. Türü komuta göre değişir; mevcut çıktının üzerine yazılmaz.

### `unseal`

Taşıma dosyasını yeni açık metin dosyaya çözer.

```sh
k957 unseal --in case-output/demo.encrypted --out case-output/demo-restored.k957 --key case-output/transport.key
```

Yanlış anahtar veya değiştirilmiş doğrulanabilir çerçeve işlemi başarısız yapar. Analizden önce çözülen delil paketini doğrulayın.

Seçenekler (basılı varsayılan yoksa yardım açık bir varsayılan göstermiyor demektir):

- `--in string` — Girdi dosyası/klasörü: bu komutun yukarıdaki açıklamasındaki türü kullanın. --store ile tek paket --in birlikte kullanılmaz.
- `--key string` — Komuta göre AES-256 şifreleme anahtarı veya Ed25519 rapor mühürleme özel anahtarı. Birbirinin yerine kullanılamaz.
- `--out string` — Yeni çıktı dosyası/klasörü veya keygen için yeni anahtar yolu kökü. Türü komuta göre değişir; mevcut çıktının üzerine yazılmaz.

### `version`

Sürümü ve geliştiricinin herkese açık iletişim bilgilerini gösterir.

```sh
k957 version
```

Yalnızca sürüm etiketi çalıştırılabilir dosyanın baytlarını tanımlamaz.

Komuta özgü seçenek yoktur.

### `build-info`

Derleyici, hedef, modül, kaynak kimliği ve geliştirici üst verisini gösterir.

```sh
k957 build-info
```

Tekrarlanabilirlik için bu çıktıyı çalıştırılabilir dosyanın SHA-256 özetiyle birlikte saklayın. Kaynak kimliği ile çalıştırılabilir dosya özeti farklıdır.

Komuta özgü seçenek yoktur.

## Kurallar, göstergeler ve etiketli ölçümler

### Metin kuralları: açıklayabildiğiniz ifadeyle başlayın

Aşağıdakini metin düzenleyicide UTF-8 olarak `my-rules.json` adıyla kaydedin. Bu JSON dizisidir; nesneler virgülle ayrılır, JSON yorum satırı kabul etmez. `id` kalıcı kural adınız, `description` eşleşmenin neden inceleneceği, `contains` gerçek arama ifadesidir. Örnek ön inceleme yardımcısıdır, zararlı yazılım dedektörü değildir:

```json
[
  {"id":"LOGIN-FAILED","description":"Review a failed authentication reference","contains":"failed password"},
  {"id":"SCRIPT-REFERENCE","description":"Review a script interpreter reference","contains":"powershell"}
]
```

```sh
k957 analyze --in case-output/demo.k957 --out case-output/custom-report --rules my-rules.json --trusted-key case-output/examiner.pub
```

Desteklenen metin kayıtları ve RAM dizelerinde anlamlı ifade arayın. Belge, yöneticinin betiği veya kopyalanmış günlükteki ifade kötü niyet olmadan eşleşebilir. Eşleşme olmaması; kaynağın edinilmemesi, ayrıştırıcının kapsam dışı olması veya içeriğin uymaması demek olabilir; eylemin hiç gerçekleşmediğini kanıtlamaz. Alan/işleçler için [yapılandırılmış kurallar](docs/STRUCTURED_TR.md), örnekler için [olay kuralları](examples/event-rules.json) dosyasına bakın.

### Yapılandırılmış olay kuralları: koşulları birleştirin

Bu kural `all` kullanır: iki koşul da doğru olmalıdır. `type` yorumlanan Windows olayını belirtir; olay kimliği seçimi daraltır. Rastgele baytlarda 1102 sayısını aramaz:

```json
[
  {
    "id":"LOG-CLEARED",
    "description":"Review whether log clearing was authorized",
    "event":{"all":[
      {"field":"type","op":"equals","value":"windows_event"},
      {"field":"windows.event_id","op":"equals","value":"1102"}
    ]}
  }
]
```

Desteklenen koşullar seçili eşitlik/alt dize ve IP CIDR karşılaştırmalarını içerir. Belgelenmiş olay alanlarını kullanın; yanlış yazılmış veya bulunmayan alan yeni delil çıkarmayı sağlamaz. `any`, alternatifler verildiğinde en az birinin eşleşmesini ister. İsteğe bağlı `techniques`, incelemecinin verdiği ATT&CK kimliklerini içerir; uygulama kelime eşleşmesinden kendiliğinden teknik çıkarsamaz.

### Çevrimdışı göstergeler: gözlenen kesin değerler

`indicators.json` olarak kaydedin. `example.test` ve `192.0.2.1` gösterim değerleridir; gerçek tehdit iddiası değildir:

```json
{
  "schema":"k957-indicators/1",
  "name":"Demonstration indicators",
  "source":"Examiner-supplied synthetic list",
  "indicators":[
    {"id":"DOMAIN-001","kind":"domain","value":"example.test"},
    {"id":"IP-001","kind":"ip","value":"192.0.2.1"}
  ]
}
```

```sh
k957 analyze --in case-output/demo.k957 --out case-output/indicator-report --iocs indicators.json --trusted-key case-output/examiner.pub
```

Türler `domain`, `ip`, `sha256` olabilir. Alan adları ASCII/punycode kullanır; büyük/küçük harf normalize edilir, sondaki nokta çıkarılır; alt alanlar kendiliğinden eşleşmez. Desteklenen tarayıcı alanları, DNS soruları, HTTP Host, TLS sunucu adları, olay IP'leri ve edinilen dosya/imaj özetleri gözlem sağlar. Çevrimiçi itibar sorgusu, aktif DNS isteği veya rastgele metin içinde gösterge araması yapılmaz. Liste ve eşleşme referansları saklanır. IOC eşleşmesi otomatik ele geçirilme kararı değildir.

### Özet listeleri: aynı baytlar, incelemecinin verdiği anlam

Gerçek 64 karakterli SHA-256 değerlerini metin dosyasına yazın. Tek başına özet `known-bad` sayılır; açık etiket daha anlaşılırdır:

```text
# Replace the placeholders with actual SHA-256 values before use.
known-good TRUSTED_REFERENCE_SHA256 Approved reference file
known-bad SELECTED_CANDIDATE_SHA256 Candidate requiring examination
```

```sh
k957 analyze --in case-output/demo.k957 --out case-output/hash-report --hash-set my-hashes.txt --trusted-key case-output/examiner.pub
```

Yukarıdaki yer tutucular geçerli özet değildir. Özetleri güvenilen referans dosyalardan veya kayıtlı delilden alın; yalnızca tanımadığınız dosyaya zararlı etiketi uydurmayın. Çelişen etiket/kararlar reddedilir. `known-good` bulgu olmadan kaydedilir; `known-bad` incelenmemiş aday oluşturur. Sınırlar: 32 MiB girdi ve 500.000 özet. [Özet listesi ayrıntıları](docs/CASE.md#hash-sets).

### Yapılandırılmış kuralı bilinen etiketlerle ölçmek

Yukarıdaki yapılandırılmış kuralı `log-rule.json`, aşağıdaki örnek kümesini `labelled-corpus.json` olarak kaydedin:

```json
{
  "schema":"k957-rule-corpus/1",
  "name":"Two synthetic Windows events",
  "events":[
    {"type":"windows_event","windows":{"event_id":1102}},
    {"type":"windows_event","windows":{"event_id":4624}}
  ],
  "positive":[{"rule":"LOG-CLEARED","event_index":0}]
}
```

```sh
k957 rules-evaluate --rules log-rule.json --corpus labelled-corpus.json --out case-output/log-rule-measurements.json
```

Olay dizinleri sıfırdan başlar. Listelenmeyen olay/kural çiftleri negatif etiketlidir; pozitif etiketi unutmak ölçümü değiştirir. Doğru pozitif beklenen ve eşleşen; yanlış pozitif eşleşen ama negatif etiketli; yanlış negatif beklenen ama kaçırılan; doğru negatif negatif olup eşleşmeyendir. Precision eşleşmelerin pozitif etiketli oranı; recall pozitiflerin bulunan oranıdır. Tanımsız oranlar yazılmaz. İki yapay satır mekanizmayı gösterir, gerçek tespit başarısını ölçmez. Çalıştırıcı yalnızca yapılandırılmış olay kurallarını destekler: en çok 100 kural, 10.000 olay, 100.000 etiket.

## Raporlar: çıktıyı seçmek, okumak ve teslim etmek

### Hangi dosyayı açmalıyım?

- **`report.html`**: görsel rapor, filtre ve gezinme için yerel tarayıcıda açın. Rapor türüne göre etkileşim değişir. Türetilmiş okuma görünümüdür; kaynak demeti saklayın.
- **`report.pdf`**: analiz, paylaşım, vaka ve seçilen kayıt çıktılarında varsayılan üretilir. Kolay açılan okuma kopyası/yazdırma için kullanın. Üretim için tarayıcı, AI modeli veya çevrimiçi PDF hizmeti gerekmez.
- **`analysis.json`**: tek analizin makinece okunabilir kaydı; kesin kaynak alanlarını kontrol etme ve sonradan belge üretme için uygundur.
- **`case.json` / `case-index.sqlite`**: vaka özeti ve yeniden oluşturulabilen koleksiyonlar arası inceleme dizini. Dizin imzalı özgün kaynak veritabanı değildir.
- **CSV dosyaları**: hesap tablosuna uygun zaman çizelgesi, bulgu, envanter, dosya türü, gösterge ve uygulanabilir diğer görünümler. Dosyalar rapor türüne/mevcut delile göre değişir. CSV formül koruması riskli dizelerin hesap tablosundaki görünümünü değiştirir; özgün delil ayrı saklanır.
- **`documents.json`**: belge üretim makbuzu. Biçimleri, kaynak görünüm bağını, sayfa sayısını, dışarıda bırakılan içeriği ve PDF karakter değiştirmelerini kontrol edin.
- **`report.docx`**: Word uyumlu kopya için `report-documents --format docx` veya `both` ile açıkça isteyin. Düzenleme, imzalı demetin baytlarını değiştirir.
- **`timeline.jsonl`, `attack-navigator.json`, değer listeleri ve `review-queue.json`**: taşınabilir analiz görünümleri. JSONL zaman çizelgesinde yalnızca mutlak zamanı olan olaylar bulunur; ATT&CK eşlemeleri incelemeci girdisidir, tüm teknik sürümlerine karşı doğrulanmaz. [Raporlama ayrıntıları](docs/REPORTING.md).

### Sonuçlardan önce yöntem durumunu okuyun

Koleksiyon/doğrulama durumu ve kapsamla başlayın. Ardından yöntem notu, edinim sorunları, kaynak referansları ve eksiltmeleri okuyun. Dosya değişiklik zamanı, kişinin dosyayı çalıştırdığını kanıtlamaz. Registry son yazma zamanı değer oluşturma zamanı değildir. TLS sunucu adı çözülmüş HTTPS içeriği değildir. Kullanılamayan ayrıştırıcıdan sıfır satır çıkması temiz sistem kararı değildir.

Önemli her gözlem için koleksiyon özeti, delil kimliği, özgün kayıt veya bayt/adres referansı, ham zaman/kodlama, yöntem/sınırlar ve kararınızı saklayın. `Software developer` yazılım yazarını gösterir; incelemeyi yapan/onaylayan kişiyi tanımlamaz.

### PDF bir okuma sürümüdür

PDF/DOCX okunabilir görünüm sınırlarına sahiptir: genellikle en çok 500 bulgu/olay/envanter/IOC/değerlendirme satırı, 200 not/kapsam satırı, 400 edinim sorunu; bellek/vaka önizlemeleri rapora göre değişir. Paragraf 16 KiB, toplam belge metni 1 MiB sınırındadır. Vaka PDF'leri her dahil edilen kayıt türünden en çok 200 satır örnekler. Bütün satırların kağıtta bulunduğunu varsaymadan `documents.json` içindeki gerçek eksiltmeleri okuyun.

Belge sınırları tam RAM JSONL veya çekirdek çıktısını kesmez. HTML/JSON da sınırlı önizleme içerebilir; tamlık gerektiğinde tam yan dosyalara bakın. `report-documents`, tek analiz JSON dosyasından eksik RAM yan dosyalarını yeniden oluşturmaz veya kopyalamaz. Desteklenmeyen PDF karakterleri görünür `[U+XXXX]` olarak kaydedilir; özgün Unicode metni JSON/HTML ve DOCX'te kalır. Yerel PDF; gömülü yazı tipi, bölüm, kaynak referansı ve sayfa numarası kullanan belirli bir belge üreticisidir, AI tarafından yazılmış metin değildir.

### Maskeleme politikası örneği

Varsayılan `share` görünümü temkinlidir. Açık politika için `share-policy.json` olarak kaydedin:

```json
{"schema":"k957-share-policy/1","keep":["timestamps"],"literals":[]}
```

```sh
k957 share --in case-output/demo.k957 --out case-output/shared-policy --policy share-policy.json --trusted-key case-output/examiner.pub
```

Bu seçim zaman damgalarını korur. Diğer keep/literal seçimleri [paylaşım belgesinde](docs/SHARING_TR.md) açıklanır; kullanmadan okuyun. Paylaşılan raporların ayrı açıklama bağı vardır; özel tam RAM dizeleri/çekirdek döküm dosyaları dışarıda bırakılır. Bunları paylaşılan demete elle kopyalamayın. Maskeleme, bağlamdan kişiyi yeniden tanımaya karşı garanti değildir.

### Yalnızca son demeti mühürleyin

```sh
k957 report-seal --report case-output/report --key case-output/examiner.key
k957 report-verify --report case-output/report --trusted-key case-output/examiner.pub
```

Mühür, dahil edilen her normal dosyanın yolunu, boyutunu, SHA-256 değerini ve raporun kaynak bağlarını içerir. Doğrulama beklenmeyen/eksik/değişen dosyaları ve güvensiz yolları reddeder. Açık anahtarı bağımsız saklayın. Gömülü anahtarla iç tutarlılık kontrolü, ayrı güvenilir kanaldan edinilen anahtarla kontrolden daha zayıftır. Rapor mührü analiz sonucunu onaylamaz veya bağımsız güvenilir zamanı sağlamaz. Saklama planında özgün imzalı delil, analiz yan dosyaları, son rapor ve doğrulama kaydı birlikte düşünülmelidir.

## Bellek: edinim, tam tarama ve çekirdek incelemesi

### Birbirinden farklı üç iş

1. **Edinim**, RAM imajını saklar. Tam mod önce belleği dener; başarılı yakalama yöntem/bayt/özet/boşluk/okuma hatalarını kaydeder. Canlı RAM değişir; bütün sayfaların aynı andaki atomik görünümü değildir.
2. **Varsayılan analiz**, desteklenen raw/LiME imajı doğrular ve akış halinde tarar. Uygulanabilir tam dizeleri, metin kuralı eşleşmelerini, URL ve seçili yapısal gözlemleri çıkarır. İşletim sistemi çekirdek yapılarından tam süreç listesi kurmaz.
3. **Çekirdek incelemesi**, güvenilen harici Volatility kurulumu ve tam uyumlu çevrimdışı semboller kullanır. Kurulu aracın desteklediği süreç, soket ve diğer yöntemleri deneyebilir. Yöntemin çalışması imaj/platform/sembol/modül/gerekli seçicilere bağlıdır. Her imajdan yapılabilecek bütün adli sonuçları garanti edemez.

### RAM edinimi

Linux, görünür `System RAM` aralıklarını `/proc/kcore` eşlemeleriyle okuyup LiME yazar. Gizli aralıklar, lockdown, eksik eşlemeler ve izinler edinimi engelleyebilir/daraltabilir. Okuma hataları sıfır sayfalarla gösterilip kayda geçebilir; sıfır sayfa özgün belleğin kesin sıfır olduğunu kanıtlamaz.

Windows, çalıştırılabilir dosya yanında veya `tools` klasöründe tam bir `winpmem*.exe` keşfeder ya da açık araç kabul eder. WinPmem uyumluluk/yetki gerektiren harici sürücü/araçtır. Belgelenmiş sözdizimi `-o <dosya>` olan araç için:

```sh
k957 collect --full --memory-tool tools/winpmem.exe --memory-tool-arg=-o --memory-tool-arg="{output}" --output-dir case-output/collections
```

Seçtiğiniz aracın gerçekten bu sözdizimini kullandığını kontrol edin. Her `--memory-tool-arg` tek argümandır; en az biri `{output}` içermelidir; hedef yol bunun yerine konur. macOS'ta yerleşik fiziksel bellek edinimi yoktur. Harici aracın özeti saklanır; bu tek başına sürücüyü veya tüm yorumlayıcı bağımlılıklarını doğrulamaz.

### Otomatik RAM boyutu, sonuç veya araç süresi tavanı yoktur

Varsayılan tarayıcı tek doğrulanmış dosya tanımlayıcısından okur ve gerçekten tüketilen baytların özetini alır. İmajın tamamını RAM'e yüklemez, imaj büyüklüğünde `/tmp` kopyası gerektirmez. Yapılandırılmış imaj boyutu, LiME aralık sayısı veya tam sonuç sayısı tavanı yoktur. Tam özel JSONL; ASCII/UTF-16LE yazdırılabilir dizeleri yeniden birleştirilebilir parçalarla, metin eşleşmelerini, tam URL ve desteklenen gözlemleri adres/kodlamayla saklar. CSV uygulanabilir tam eşleşme/gözlem satırlarını akışla yazar. Analiz/HTML/PDF önizlemeleri ayrıca sınırlanır ve belirtilir.

Harici inceleme yine tam özel imaj/sembol kopyası ister. Kapasiteyi kontrol edip önce geçici, sonra çıktı dosya sistemini değerlendirir; açık `--work-dir` kabul eder. Otomatik 8 GiB imaj tavanı, sabit 64 MiB RAM çalışma rezervi, iki dakikalık eklenti süresi, 32 MiB çıktı, 64 KiB stderr veya 100.000 çekirdek satırı tavanı yoktur. Disk dolması, iptal, bozuk çıktı, değişen girdi ve uyumsuz sembol gerçek hatalardır. Hem özel kopyaya hem boyutu öngörülemeyen kurtarılan dosya/sonuçlara alan bırakın; boş alan diğer programlara karşı rezerve edilmez.

### Otomatik çekirdek incelemesini ayarlamak

Linux/macOS örneğinde yolları mevcut güvenilen dosya/klasörlerle değiştirin:

```sh
export K957_VOLATILITY=/opt/forensics/vol
export K957_MEMORY_SYMBOLS=/data/offline-symbols
export K957_MEMORY_WORK_DIR=/data/memory-work
k957 analyze --store case-output/collections
```

PowerShell karşılığı:

```powershell
$env:K957_VOLATILITY="C:\Forensics\vol.exe"
$env:K957_MEMORY_SYMBOLS="D:\offline-symbols"
$env:K957_MEMORY_WORK_DIR="D:\memory-work"
.\k957-windows-amd64.exe analyze --store case-output/collections
```

Çalışma klasörü isteğe bağlıdır; uygun ve mevcut hedef olmalıdır. Otomatik platform seçimi edinim kaydı/paket manifestosunu kullanır. Başka platformdan içe alınan RAM için toplayıcı işletim sistemine güvenmek yerine açık `memory-examine --platform` seçin.

### Bellek sonucunun tamamını okumak

`memory.csv` ve analizde imaj özeti, yöntem durumları, tam yan dosya referans/sayılarına bakın. Temel önizlemeler imaj başına en çok 500 eşleşme, 500 gözlem, 50 URL gösterir; kalanlar tam JSONL'de korunur. Çekirdek makbuzları denenen/kullanılamayan/başarısız yöntemleri, araç/sembol özetlerini, JSON, yardım/stderr ve çıkarılan dosyaları saklar. `all`, kurulu uygun platform/genel yöntemlerini keşfeder; PID, YARA kuralı veya adres gerektiren yönteme değer uydurmaz. Eksik yöntem açıkça bildirilir.

Bellek metinlerinde parola, belirteç, kişisel mesaj ve ilgisiz bilgi bulunabilir. Tam sonuçları özel tutun, paylaşımı ayrıca inceleyin. Güncel 8 GiB üstü yapay Windows denetimi çalıştırma/saklamayı doğrular; geçerli gerçek imajda çekirdek kurtarma doğruluğunu ölçmez. Pozitif çekirdek referans imajı doğruluğu henüz doğrulanmamıştır. [Tam bellek belgesi](docs/MEMORY.md).

## Güven, teslim zinciri ve kaynak referansları

### Bağımsız saklanan anahtar neden önemlidir?

Bayt değişince özet/parmak izi değişir; fakat hem delili hem özeti değiştirebilen kişi yeni uyumlu çift koyabilir. Bağımsız tuttuğunuz açık anahtarla doğrulanan imza, baytları o anahtara bağlar. Yeni üretilmiş gömülü anahtar yalnızca iç tutarlılık sağlar. Tam toplama ürettiği özel anahtarı siliyorsa görünen parmak izini edinim sırasında bağımsız kaydedin; silinen anahtarla sonradan yeni imza atamazsınız.

Özel imza anahtarı `.key`, açık doğrulama anahtarı `.pub` uzantılıdır. AES taşıma anahtarları ayrı simetrik sırdır. Özel anahtarı rapor demetiyle e-postalamayın; kaybolanı yenisiyle değiştirip aynı imzacı olduğunu iddia etmeyin. Anahtarları kendi erişim/saklama yönteminizle koruyun.

### En küçük aktör güven dosyası

Aktöre özel anahtarı `keygen` ile oluşturun, `.pub` dosyasını okuyun, yer tutucuyu gerçek 64 karakterli onaltılık açık anahtarla değiştirin. `actor-trust.json` olarak kaydedin:

```json
{
  "schema":"k957-custody-trust/1",
  "keys":[{"actor":"Analyst","public_key":"ACTUAL_PUBLIC_KEY_HEX"}]
}
```

Yer tutucu değiştirilmeden geçersizdir. Dize anahtar baytlarıdır, `.pub` dosya yolu değildir. Her farklı aktör/anahtarı bilinçli ekleyin. Güven dosyasını bağımsız saklayın; bu sizin politikanızdır, delilin sizin yerinize seçmesi gereken bir değer değildir.

### Teslim sırası

İlk sahibi kaydedin, sonra o kişi `transfer --to Recipient` ile teslim önerir. Alıcı kendi güvenilen anahtarıyla `accept` imzalar. Sahip bekleyen teslimi iptal edebilir. Sahip notu yalnızca geçerli durum kuralları içinde eklenebilir. Her adım önceki zincire başvurup yeni kayıt yazar. Gösterilen başı başka yerde saklayın; sonraki kontrolde `--expected-head` veya bağımsız tanık çapası kullanın. Güven şeması anahtar yenileme/iptalini destekler; tarihsel anahtarların korunması önemlidir. [Teslim zinciri örnekleri ve yaşam döngüsü](docs/CUSTODY_TR.md).

### Saat tahminleri ve kimlik

RFC3339 zamanında açık saat dilimi kullanın; `Z`, yerel saat değil UTC demektir. Özgün ham zaman/kodlama önemlidir. Pozitif saat farkı kaynak saatin ileride olduğunu belirtir; UTC tahmini için çıkarılır. Bilinmeyen kayma/kimlik belirsiz kalır. Aynı kullanıcı adı/IP, koleksiyonlar arasında aynı kişiyi kanıtlamaz. Saat/kimlik politikalarının şeması ayrıdır; paylaşım politikası ilişkilendirmede kullanılmaz. [İnceleme iş akışları](docs/EXAMINATION_WORKFLOWS.md).

## Sınırlar ve kapsam

### Toplama neleri korur, neleri sağlamaz?

Mantıksal toplama edinilen dosya içeriğini ve desteklenen dosya tanımlayıcısı üst verisini korur. Tam fiziksel disk imajı, VSS/anlık görüntü, silinmiş alan kurtarma veya atomik çok dosyalı görüntü değildir. Linux seçili sahiplik/zaman/xattr/ham ACL; Windows seçili tanıtıcı üst verisi ve owner/group/DACL SDDL; macOS seçili zaman/sahiplik/xattr sağlar. Windows alternatif akış içeriği/SACL ve yerel macOS ACL kapsamı iddia edilmez. Üst veri sınırları ve okunamayan kaynaklar belirtilir.

Tam profiller bilinen sistem artefakt yollarını seçer; her işletim sistemi sürümünde bütün özel günlük, uygulama veritabanı ve kalıcılık yönteminin edinildiği garantisi değildir. Gerekirse ek `--root` veya ayrı kapsamlı edinim kullanın. Bulut uyarlayıcısı seçili çevrimdışı CloudTrail'dir; bulut hesabından edinim yoktur.

### Desteklenen yorumlama

- Seçili tarayıcı SQLite şemaları ve yan dosya işlemleri; mantıksal yedek özgün baytlardan ayrıdır.
- EVTX kayıt/başlık/CRC/BinXML görünümleri; sağlayıcı mesaj DLL'leri yüklenmez.
- Temiz Registry REGF 1.3–1.6 seçili anahtar/değerleri; kirli dosya günlük tekrar oynatma, silinen hücre ve tüm bölünmüş veriler kapsanmaz.
- Seçili launchd/task/systemd ve Prefetch başlık bilgileri; tam çalıştırma geçmişi değildir.
- Seçili çevrimdışı USN v2/v3 kayıtları ve kaynağa özgü dosya grupları; MFT kurma, canlı journal edinimi veya USN v4 yorumlama değildir.
- PCAP/PCAPNG seçili IPv4/IPv6/TCP/UDP, DNS/HTTP Host/TLS ClientHello görünümleri. TLS çözme, QUIC, canlı yakalama, tüm uygulama içeriği veya parçalı paket birleştirme yoktur.
- Dosya imzası envanteri, yerel ayrıştırıcıların anlamsal yorumladığından daha çok türü tanır.
- RAM akış gözlemleri ve ayrıca yapılandırılan harici çekirdek incelemesi.

### Birbirinden ayrı kapasiteler

Dosya toplama varsayılanları komut bölümündedir; değiştirmek edinim kapsamını değiştirir. Karmaşık yerel artefakt çalışanları en çok 128 MiB girdi, 32 MiB görünüm çıktısı ve çalışan başına 30 saniye kabul eder. PCAP görünümü dosya başına 64 MiB/toplam 256 MiB, dosya başına 20.000 paket, 10.000 akış ve akış başına 20 referansla sınırlıdır. Genel bulgu/değerlendirme görünümü ve vaka çıktısının ayrı kapasiteleri vardır: eski envanter en çok 100.000 nesne; inceleme dizini bir milyon satır/2 GiB; sorgu sayfası 200 satır, kaydırma bir milyon ve çalıştırma beş saniye.

Bunlar tavansız tam RAM sonuçlarından ayrıdır. Her çıktının gerçek kapsam/eksiltmelerine bakın. “Destekleniyor”, tanımlı görünümün işlenebilmesi demektir; bütün işletim sistemi sürümleri veya bozuk/kötü niyetli girdilerin pozitif doğrulandığı anlamına gelmez. Harici araçlar güvenilen yerel koddur, tam işletim sistemi sandbox'ı değildir. Linux çalışanları ek güvenlik kısıtları uygular; diğer platformlar eşdeğer sandbox iddia etmez. [Mimari](docs/ARCHITECTURE.md), [artefakt kapsamı](docs/ARTIFACTS.md), [bilinen eksikler](docs/PRODUCT_GAPS.md).

### Denenen platformlar ve sürüm durumu

Güncel kaynakta saklanan yerel Linux AMD64 ve Windows AMD64 doğrulamaları, Windows konsol/API kontrolleri ve harici araç entegrasyonları vardır. Altı çalıştırılabilir dosyada derleme/statik bağlantı kontrolleri yapılır. Yerel Windows ARM64/macOS, geniş fiziksel cihaz kapsamı ve geçerli çekirdek doğruluğu açıktır. Windows 100.000 nesne yük denetimi test raporundaki ayrı kaynak/çalıştırmaya aittir; her derlemede tüm testlerin geçtiğini söylemeyin. Yapay geçersiz imaj Volatility testi pozitif çekirdek nesnesi kurtarma testi değildir.

Çalıştırılabilir dosya geliştirici önizlemesidir; mahkeme sertifikası, geniş zararlı tespit doğruluğu iddiası değildir. [Geliştirme planı](docs/DEVELOPMENT_PLAN.md) kayıtlı kapsamı açıklar. [Sürüm üst verisi](RELEASE.json), [test raporu](docs/TEST_REPORT.md) ve [platform matrisi](docs/PLATFORM_TESTING.md) gerçek çalıştırma/sınırları gösterir.

## Sorun giderme

### “Command not found” veya Windows dosyayı bulamıyor

Gerçek platform dosya adını kullanın. PowerShell, mevcut klasördeki program için `.\k957-windows-amd64.exe` ister. Linux/macOS, `./k957-linux-amd64` veya uygun hedefi kullanır. Kılavuzdaki `k957` kısa gösterimdir; kendi dosya adınızla değiştirin veya klasörü bilinçli PATH'e ekleyin.

### “Exec format error” veya yanlış işlemci

Intel/AMD x86-64 için AMD64, ARM64 işletim sistemi için ARM64 seçin. İşlemcinin komut kümesini desteklemesi işletim sisteminin onu kullandığını garanti etmez. Linux ELF dosyası Windows/macOS'ta doğal olarak çalışmaz. Dosya seçiminden sonra `build-info` kontrol edin.

### Bilinmeyen seçenek, beklenmeyen argüman veya kapanmayan boolean

Komutun seçeneği desteklediğini kontrol edin, iki tire kullanın, boşluklu yolları tırnaklayın. `--memory false` yerine `--memory=false` yazın. Tam toplama seçenekleri tam olarak `--full` gerektirir. Boyut için tam sayı bayt, süre için `30m` gibi biçim kullanın; `30 minutes` değil. Ortak yardımda o komutta işlemeyen seçenekler olabilir; yukarıdaki notları okuyun.

### Çıktı zaten var

`report-02` gibi yeni ad/klasör seçip önceki sonucu saklayın. Açık çıktı yeni olmalıdır; devam etmek için eski sonucu silmek gerekmez. Üst klasörler mevcut olmalıdır. Çıktı/çalışma yolu kaynakla çakışmamalıdır.

### Eksik dosyalar veya “partial” koleksiyon

`collection.json` ve edinim kaydını okuyun. İsteğe bağlı yol başka sürümde bulunmayabilir. İzin, okuma hatası, sınır nedeniyle atlama ve bellek hatası ayrı değerlendirilir. Yetkili uygun ayrıcalıklarla çalıştırın veya belgelenmiş kapsam/sınırı düzenleyin; program bitti diye kısmi edinime tam demeyin.

### Bellek çalışma alanı yetersiz

`version`/`build-info` kontrol edin; eski dosya geçmişteki imaj boyutlu varsayılan geçici kopyayı isteyebilir. Güncel temel tarayıcı harici imajı kopyasız akışla okur. Volatility özel imaj/sembol kopyası; paket içi imaj/arşiv çalışanları ayrıca alan ister. Yeterli kapasitede `--work-dir` veya `K957_MEMORY_WORK_DIR` seçin. Başka disk boş olsa da `/tmp` küçük RAM tabanlı dosya sistemi olabilir. Kaynak ve özel kopyanın yanında çıktı/dökümler için alan gerekir. Yer açmak için edinilen imajı silmeyin; başka hedef seçin.

### Doğrulama başarısız

Başarısız paket ve hata kaydını araştırmak için koruyun. Doğru bağımsız açık anahtarı seçtiğinizi ve koleksiyon dosyalarının mevcut olduğunu kontrol edin. Değişmiş baytlar üzerinde yeni özet/imza üretip doğrulamayı “düzeltmeyin”. Yanlış anahtar ve değişmiş delil farklı nedenlerdir. Depodaki tek hata bile sıfır olmayan çıkış verir; başarılı koleksiyonlar ayrı listelenir.

### Analiz hiçbir şey bulmadı

Kaynak türü, edinilen bayt, ayrıştırıcı kapsamı, kural dosyası, zaman/filtre ve atlanan satırlara bakın. İş akışını bilinen yapay örnekle doğrulayın. Desteklenmeyen veritabanı veya eksik sembol, şüpheli faaliyet olmadığını kanıtlayamaz.

### Volatility yöntemleri başarısız veya kullanılamıyor

Her yöntemin saklanan tanı/yardım çıktısını okuyun. Araç/platform/sembol uyumu ve isteğe bağlı modülleri kontrol edin. Bazı yöntemler PID, adres veya YARA kuralı ister; yalnızca `all` ile çalışamaz. Gerekli harici kurulumla belirli yöntemi yeniden deneyin; k957 seçici uydurmaz. Çalışan Volatility kurulumu eşleşen sembol olmadan imajı yorumlayamayabilir.

### Windows'ta kaçış karakterleri veya tekrarlanan ilerleme blokları

Güncel derleme desteklenen gerçek konsolda ANSI çizimden önce VT işler; desteklenmeyen ortamda satır çıktısına döner. Eski kopya yerine güncel dosyayı kullandığınızı kontrol edin. `TERM=dumb` sade ilerleme, `NO_COLOR` renksiz görünüm ister. Yönlendirme satır düzenindedir. Unicode görünümü terminal/yazı tipine de bağlıdır; özgün kaynak ayrı korunur.

### PDF bütün satırları göstermiyor veya [U+XXXX] yazıyor

`documents.json` okuyun; PDF sınırlı okuma sürümüdür. Kalan satırlar için referans verilen JSON/CSV/tam RAM yan dosyalarını açın. `[U+XXXX]` yazı tipinde desteklenmeyen karakteri kaydeder, kaybolan delil baytı değildir; özgün metin için HTML/JSON/DOCX kullanın. Yalnız PDF'nin bütün tam sonuçları içerdiğini söylemeyin.

### Görüntüleyici açılmıyor veya yanıt vermiyor

`case-serve` açık kalsın; tüm loopback adresi/belirtecini aynı bilgisayarda kullanın. 0 portu dolu sabit porttan kaçınır. Bunu sunucu ürünü sanıp ağa açmayın. Büyük sorguda sayfa/süre sınırı vardır; boş sayfayı özgün kayıt yok sanmak yerine koleksiyon/delil/yerel referansı daraltın.

### Kesilmiş edinim

Ctrl+C hemen 130 çıkışı ister. Desteklenen devamdan önce çalışma durumuna bakın; ilk parametre/imza/şifre anahtarlarını koruyup aynı kontrol noktasını kullanın. Tamamlanan paket mevcut aynı çıktıya sürdürülemez. Tam makine/RAM toplaması gerekiyorsa yeni koleksiyon olarak yapılır; yarım klasörü mantıksal devam kontrol noktası değildir.

## Derleme, doğrulama ve sürüm dosyaları

### Hazır dosya kullanmak ile kaynak derlemek

Hazır programı kullanmak için Go/Python gerekmez. Derlemek için [go.mod](go.mod) sürümünü, Go 1.26.0 veya yenisini (saklanan güncel derlemeler Go 1.26.8 kullanır) kurup deponun derleme betiğini çalıştırın. İlk bağımlılık indirmesi ağ isteyebilir. Betik altı statik hedef dosyasını oluşturup platform kütüphanesi bağımlılıklarını kontrol eder; derleme tek başına yerel çalışma testi değildir.

```sh
scripts/build.sh
```

Windows PowerShell:

```powershell
.\scripts\build.ps1
```

Her hedefin başarı/hata özetini okuyun. Etkileşimsiz günlükte sade çıktı kullanılır; `NO_COLOR` rengi kapatır. Dosyalar `dist/` altına gider. `SOURCE.json` derleme girdisi kimliği, `SHA256SUMS.txt` dosya baytları, `RELEASE.json` doğrulama kapsamını kaydeder; denenmeyen hedefin yerel çalışmasının geçtiğini iddia etmez.

### Geliştirici kontrolleri

Doğrulamayı özgün delil üzerinde çalıştırmayın. Araç yapay/geçici örnekler üretir. Python test bağımlılıkları bağımsız doğrulama içindir, normal CLI kullanımı için değildir:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r scripts/requirements-test.txt
.venv/bin/python scripts/validate.py --help
GOCACHE=/tmp/k957-go-cache go test ./...
GOCACHE=/tmp/k957-go-cache go vet ./...
python3 scripts/check_language.py
```

Windows'ta Unix yolları yerine `.venv\Scripts\python.exe` ve uygun ortam sözdizimini kullanın. Platform/bağımlılık/yük seçeneklerini seçmeden doğrulama yardımını okuyun. Araç/model ayarlanmamışsa test atlanabilir; atlama yeteneğin pozitif doğrulandığı anlamına gelmez. [Platform testleri](docs/PLATFORM_TESTING.md), [kaynak yükü](docs/SOURCE_SCALE.md) tekrar üretilebilir çalıştırmaları açıklar.

### Doğru kimlikleri saklamak

Araç sürümü, kaynak kimliği, çalıştırılabilir SHA-256, sistem/işlemci, harici araç/sembol kimliği, girdi özeti, komut/ayar ve çıktı doğrulamasını kaydedin. Yayın özetlerini sistemin SHA-256 aracıyla karşılaştırın; özet dosyasının kendisi de güvenilen iletim/saklama kanalı gerektirir. Aynı kaynak kimliğiyle yerelde derlenen dosyanın baytları farklı olabilir.

## İleri okuma

- [Örnekler](examples/README.md): sağlanan yapay iş akışları ve örnek veriler.
- [İnceleme iş akışları](docs/EXAMINATION_WORKFLOWS.md): ayrıştırıcı, vaka sorgusu, asistan, seçim, araç incelemesi ve teslim.
- [Artefaktlar](docs/ARTIFACTS.md), [Windows olay XML](docs/WINDOWS_EVENT_XML.md), [USN journal](docs/USN_JOURNAL.md): kesin kaynak görünümleri.
- [Bellek](docs/MEMORY.md), [vaka dizini](docs/CASE.md), [raporlama](docs/REPORTING.md): tam çıktı ve kapsam.
- [Ön kontrol](docs/PREFLIGHT_TR.md), [devam](docs/RESUME_TR.md), [şifreli toplama](docs/ENCRYPTED_COLLECTION_TR.md): edinim işleri.
- [Analist değerlendirmesi](docs/REVIEW_TR.md), [teslim zinciri](docs/CUSTODY_TR.md), [paylaşım](docs/SHARING_TR.md): bağımsız karar/açıklama.
- [Mimari](docs/ARCHITECTURE.md), [test raporu](docs/TEST_REPORT.md), [platform testleri](docs/PLATFORM_TESTING.md): uygulama yapısı ve kontrol kanıtları.
- [Geliştirme planı](docs/DEVELOPMENT_PLAN.md), [eksikler](docs/PRODUCT_GAPS.md), [geliştirme ilerlemesi](docs/IMPLEMENTATION_PROGRESS.md), [değişiklik günlüğü](CHANGELOG.md): mevcut kapsam ve geçmiş.

docs altındaki tarihsel `_TR` adları uyumluluk için korunmuştur; Türkçe kullanıcı kılavuzu kökteki `README_TR.md` dosyasıdır. Diğer uygulama/belge metni İngilizcedir.

## Lisans ve geliştirici

Geliştirici: **Cuma Kurt**. Bunlar yazılım yazarının iletişim bilgileridir; inceleme veya olay müdahalesi görevlendirmesi değildir:

- E-posta: [cumakurt@gmail.com](mailto:cumakurt@gmail.com)
- Kaynak deposu: [github.com/cumakurt/k957](https://github.com/cumakurt/k957)
- LinkedIn: [Cuma Kurt](https://www.linkedin.com/in/cuma-kurt-34414917/)

[LICENSE](LICENSE), [üçüncü taraf bildirimleri](THIRD_PARTY_NOTICES.md), [bağımlılık/yazı tipi lisansları](licenses) dosyalarını okuyun. Harici araç ve isteğe bağlı modellerin kendi kurulum/uyumluluk/lisans koşulları vardır. Sorun bildirirken kaynak kimliği, sürüm, hassas bilgisi çıkarılmış komut ve hatayı ekleyin; özel delil/sır göndermek yerine yapay tekrar üretim örneği kullanın.
