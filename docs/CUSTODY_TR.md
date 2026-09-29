# İmzalı muhafaza ve devir kayıtları — v0.7.0

`custody` komutu, doğrulanmış bir k957 delil paketi için imzalı beyan geçmişi oluşturur. Her işlem yeni bir JSON dosyasına yazılır; önceki dosya ve delil değiştirilmez. Her olayın kendi Ed25519 imzası korunur. `custody-verify` tüm imzaları, kişi/anahtar eşleşmelerini, işlem sırasını ve delil bağını yeniden kontrol eder.

Bu kayıtlar dijital beyanlardır. Fiziksel teslimi, gerçek kişi kimliğini, hukuki yetkiyi veya güvenilir zaman damgasını kanıtlamaz. Dosya tabanlı özel anahtarlar, harici güven listesinin doğru hazırlanması ve son kayıt özetinin bağımsız saklanması gerekir.

## Güven listesi

Her kişi kendi özel anahtarını kullanır. Mevcut `keygen` komutu anahtar çiftini oluşturur:

```sh
k957 keygen --out /guvenli/alice
k957 keygen --out /guvenli/bob
```

Yetkili yönetici, açık anahtarları ayrı bir kanaldan doğrulayıp `trust.json` dosyasına ekler. Örnekteki yer tutucular yerine ilgili `.pub` dosyasının **64 karakterlik küçük harfli hex içeriği** yazılır:

```json
{
  "schema": "k957-custody-trust/1",
  "keys": [
    {"actor": "Alice", "public_key": "ALICE_PUB_ICERIGI"},
    {"actor": "Bob", "public_key": "BOB_PUB_ICERIGI"}
  ]
}
```

`actor` büyük/küçük harfe duyarlıdır; başında/sonunda boşluk olamaz. Aynı açık anahtar birden fazla kayıtta kullanılamaz. Geçmişteki tüm imzacıların kişi/anahtar eşleşmeleri verilen listede bulunmalıdır. Güven listesi delilden bağımsız yönetilir; pakete eklenmiş herhangi bir liste otomatik güvenilir değildir. Bu sürüm sertifika otoritesi, anahtar iptal servisi veya tarihsel yetki politikası uygulamaz.

## İşlem sırası

| İşlem | İmzalayan | Etkisi |
|---|---|---|
| register | İlk sorumlu | Yalnızca ilk kayıt; sorumluyu belirler |
| transfer | Mevcut sorumlu | `--to` kişisine teslim isteği açar; sorumlu henüz değişmez |
| accept | Bekleyen teslimin alıcısı | Teslimi kabul eder; sorumluyu değiştirir |
| cancel | Mevcut sorumlu | Bekleyen teslimi iptal eder |
| note | Mevcut sorumlu | Bekleyen teslim yokken açıklama ekler |

Bekleyen teslim varken yeni transfer veya note eklenemez; accept/cancel gerekir. Bir kayıtta yalnızca bir mevcut sorumlu modellenir; eşzamanlı çoğaltılmış nüshalar, grup sorumluluğu ve çift onaylı imha iş akışı yoktur.

İlk kayıt:

```sh
k957 custody --in /delil/vaka.k957 --trust /guvenli/trust.json \
  --action register --actor Alice --location "Delil dolabı A" \
  --note "Doğrulanmış paket kayda alındı" \
  --sign-key /guvenli/alice.key --out /kayit/custody-001.json
```

Komut JSON çıktısında `head` döndürür. Bu 64 karakterlik özeti bağımsız bir vaka kaydında saklayın. Sonraki örneklerde `ONCEKI_HEAD` yerine önceki işlemin bağımsız kayıttan alınan head değeri yazılır:

```sh
k957 custody --in /delil/vaka.k957 --trust /guvenli/trust.json \
  --previous /kayit/custody-001.json --expected-head ONCEKI_HEAD \
  --action transfer --actor Alice --to Bob --location "Laboratuvar kabul" \
  --note "İnceleme için teslim isteği" --sign-key /guvenli/alice.key \
  --out /kayit/custody-002.json
```

Teslim alan Bob kendi güvenilir ortamında paketi ve önceki kaydı doğrular, sonra kendi özel anahtarıyla kabul eder. Buradaki `ONCEKI_HEAD`, custody-002 için saklanan head değeridir:

```sh
k957 custody --in /delil/vaka.k957 --trust /guvenli/trust.json \
  --previous /kayit/custody-002.json --expected-head ONCEKI_HEAD \
  --action accept --actor Bob --location "İnceleme istasyonu B" \
  --note "Paket kontrol edilerek teslim alındı" --sign-key /guvenli/bob.key \
  --out /kayit/custody-003.json
```

`--at` isteğe bağlı RFC3339 olay zamanıdır; örneğin `2026-09-28T08:00:00+03:00`. Verilmezse kayıt anı kullanılır. Olay zamanı kayıt anından ileri, önceki olay/kayıt zamanları ise sonraki kayıtların zamanlarından ileri olamaz. Yanlış veya geriye giden sistem saati işlemin reddedilmesine neden olabilir. Saatler kullanıcı/yerel sistem beyanıdır; TSA/NTP doğrulaması yapılmaz.

## Doğrulama ve rapor

`SON_HEAD` yerine custody-003 için bağımsız saklanan değeri kullanın:

```sh
k957 custody-verify --in /delil/vaka.k957 \
  --ledger /kayit/custody-003.json --trust /guvenli/trust.json \
  --expected-head SON_HEAD

k957 analyze --in /delil/vaka.k957 --out /rapor/vaka-001 \
  --custody /kayit/custody-003.json --custody-trust /guvenli/trust.json \
  --custody-head SON_HEAD
```

Delil paketi imzalıysa ve kökeni de doğrulanacaksa bu komutlara ayrıca `--trusted-key /guvenli/edinim.pub` eklenir. Bu anahtar delil imzasını doğrular; devir imzacılarının güven listesi ayrı bir girdidir.

JSON doğrulama sonucu kayıtların çözülmüş içeriğini, `current_holder`, varsa `pending_to`, `head` ve kullanılan güven listesinin özetini gösterir. Rapor HTML bölümü, `analysis.json` içindeki custody alanı ve `custody.csv` aynı geçmişi içerir. CSV alanlarında formül başlangıçları etkisizleştirilir; HTML içerikleri escape edilir. Rapor geçmişi yeniden doğrulamak için özgün custody JSON ve güven listesi de saklanmalıdır.

`--expected-head` / `--custody-head` verilmezse geçerli imzalı eski bir sürüm de kabul edilir. Tek başına hash zinciri, son olayların kaldırıldığını veya başka bir dalın varlığını ispatlayamaz. Beklenen head değerini doğrulanacak aynı dosyadan okumak bağımsız kontrol sağlamaz. Paylaşımlı merkezi kayıt/dağıtık uzlaşma yoktur.

## Delil bağı ve sınırlar

- Önce paketteki bütün nesneler ve manifest hash'leri doğrulanır. Kayıtlar vaka, paket kimliği ve **manifestin tam byte SHA-256 özeti** ile bağlanır. ZIP dosyasının tamamının byte hash'i bu alan değildir. Aynı manifest ve nesneleri koruyan ZIP yeniden paketleme, aynı delil bağına sahip olabilir.
- `.k957` düz paket gerekir. Şifreli toplama çıktısı önce yetkili analiz ortamında `unseal` ile açılır; custody komutları şifreli zarfı doğrudan işlemez.
- Devir JSON ve raporlar şifrelenmez; kişi, konum ve notlar okunabilir. Uygun erişim izinleriyle saklayın. Base64 alanı şifreleme değildir.
- En fazla 10.000 olay ve 32 MiB kayıt dosyası; en fazla 1.000 anahtar ve 1 MiB güven listesi. Kişi 256, konum 1.024, not 16.000 byte ile sınırlıdır. Küçük harfli alan adları, bilinmeyen alanlar, yinelenen JSON anahtarları, aşırı iç içelik ve yanlış imza kodlamaları kontrol edilir.
- Mevcut hedefin üzerine yazılmaz. Yazma kesintisinde yarım yeni dosya kalabilir; doğrulamadan kullanmayın. Önceki sürümü saklayın.
- Yeni kayıt formatı analiz sürümüne bağlı değildir; v1/v2 delil paketleriyle kullanılır. Açık edinim checkpoint'leri yine oluşturuldukları k957 sürümüyle tamamlanmalıdır. Analist `review` kayıtlarının sürüm bağı devam eder.

## Formatın bağımsız doğrulanması

`payload_base64`, imzalanan JSON'un tam byte dizisini taşır. Yeniden JSON serileştirmesi yapılmadan Base64 çözülür. İmza girdisi `k957/custody/signature/v1` metni + sıfır byte + payload'dır. Her olayın head değeri, `k957/custody/head/v1` metni + sıfır byte + 32 byte açık anahtar + 64 byte imza + payload dizisinin SHA-256 özetidir. Claim içindeki `previous`, önceki olayın head değeridir. İlk olayda boştur. `signer_sha256`, açık anahtarın 32 ham byte'ının SHA-256 özetidir.

`scripts/custody_integration.py`, Python cryptography ile iki farklı imzacının imzalarını, domain ayrımını, hash zincirini ve rapor sonuçlarını bağımsız doğrular. Test çıktıları `docs/TEST_REPORT.md` ve `docs/integration-output.txt` içindedir.
