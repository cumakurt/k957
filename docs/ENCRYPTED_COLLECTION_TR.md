# k957 0.5.0 — Toplama sırasında şifreleme

Yeni `collect --work ... --encryption-key ...` modu çalışma checkpoint'ini, delil parçalarını ve final paketi şifreli yazar. Final ZIP akışı şifreleme katmanına doğrudan aktarılır; uygulama ara bir düz ZIP dosyası oluşturmaz. Bayrak verilmezse önceki düz toplama davranışı sürer.

## Kullanım

Anahtarı güvenilir ortamda, kaynak ve çalışma dizinlerinin dışında oluşturun:

```sh
k957 encryption-key --out /guvenli/VAKA-005.key
k957 collect --root /kaynak \
  --work /harici/VAKA-005-work --out /harici/VAKA-005.k957.enc \
  --case VAKA-005 --operator Analist --scope "Onaylı klasör" \
  --encryption-key /guvenli/VAKA-005.key
```

Edinim imzası da isteniyorsa bağımsız `--sign-key /guvenli/analist.key` eklenebilir. Şifreleme ve imza farklı amaçlarla kullanılır. Şifreli toplama şu anda yalnızca `--work` kullanan mantıksal dosya toplamasında çalışır; `--system` ve tek geçişli toplama desteklenmez. Uygun olmayan seçenekler sessizce yok sayılmaz, hata döner.

Kesintiden sonra aynı kaynak/kapsam/limitler ve **aynı anahtarla** komuta `--resume` ekleyin. Mevcut stale lock prosedürü `RESUME_TR.md` içindedir; çalışan toplayıcının kilidini kaldırmayın.

Durum kontrolü:

```sh
k957 work-status --work /harici/VAKA-005-work \
  --encryption-key /guvenli/VAKA-005.key --verify-parts
```

Normal toplama komutu yalnızca şifreli durum, nesne ve hata sayılarını yazdırır; tam manifesti stdout'a dökmez. `work-status` açıkça istendiğinde çözülen vaka/kaynak metadata'sını terminale yazdırır. Bu çıktıyı nereye yönlendirdiğinizi kontrol edin. Hata mesajlarında kaynak yolları bulunabilir; işletim sistemi komut satırlarını kaydedebilir.

Analiz ortamında açma ve doğrulama:

```sh
k957 unseal --in /harici/VAKA-005.k957.enc \
  --out /guvenli-analiz/VAKA-005.k957 --key /guvenli/VAKA-005.key
k957 verify --in /guvenli-analiz/VAKA-005.k957
k957 analyze --in /guvenli-analiz/VAKA-005.k957 --out /guvenli-analiz/rapor
```

İmzalı edinimde `verify`/`analyze` için ayrıca `--trusted-key` kullanın. `unseal` bilinçli olarak düz paket oluşturur; analiz ve raporlar bu sürümde otomatik şifrelenmez. Şifreli analiz birimi kullanabilirsiniz. Doğrudan `.enc` üzerinde analiz desteği henüz yoktur.

## Neler korunuyor?

- `state.enc`: vaka bilgisi, kaynak yolları, orijinal hash'ler, parça aralıkları ve edinim dönemlerini içeren checkpoint'in şifreli hali.
- `chunks/`: 8 MiB'lık parçaların şifreli halleri. Dosya adları orijinal SHA-256 yerine anahtarlı HMAC değerleridir.
- Geçici checkpoint/parça dosyaları da yazılmadan önce bellekte şifrelenir.
- Final çıktı: mevcut `K957ENC1` akış zarfı. Var olan `unseal` komutuyla açılır; içinde standart v2 delil paketi bulunur.
- Yanlış anahtar veya değiştirilmiş ciphertext doğrulamada reddedilir. Şifreli/düz çalışma modu mevcut çalışma üzerinde değiştirilemez.

`active.lock` şifrelenmez; süreç numarası ve başlangıç zamanı içerir. Dizin yapısı, dosya sayısı, boyutlar, filesystem zamanları ve aynı anahtarla aynı parçanın tekrar kullanılması gibi metadata tamamen gizlenmez. Her vaka için yeni rastgele anahtar üretin.

## Kriptografik biçim

Anahtar dosyası önceki sürümle uyumlu 32 byte rastgele anahtarın hex metnidir; parola değildir. HMAC-SHA256 ile iki ayrı amaç anahtarı türetilir:

- `k957/stage/aead/v1`: staged blob AES-256-GCM anahtarı.
- `k957/stage/name/v1`: parça dosya adları için HMAC anahtarı.

Blob: `K957STG1` (8 byte), rastgele 12 byte nonce, ciphertext ve 16 byte GCM tag. AAD, checkpoint için `aes256-gcm-stage/1:state`, parça için `aes256-gcm-stage/1:chunk:<orijinal-sha256-hex>` olur. Bu ayrım parça/checkpoint yer değiştirmesini reddeder. Her yeni blob yazımında yeni nonce üretilir. Final taşıma zarfı mevcut master anahtar/akış biçimini kullanır; staged blob anahtarından ayrıdır.

## Sınırlar ve işletim

- Anahtarı kaybederseniz kurtarma mekanizması yoktur. Anahtarı delille aynı USB'de taşımayın; kaynak/çalışma ağacında anahtar yolu kullanımı engellenir.
- Anahtar bu sürümde dosyadan okunur. Donanım anahtarı, parola KDF'si, alıcı açık anahtarıyla şifreleme, anahtar kasası veya otomatik anahtar döndürme yoktur.
- Kaynak sistemin RAM'i, swap/pagefile, crash dump veya ele geçirilmiş çekirdeği bu uygulamanın depolama şifrelemesiyle korunmaz. Bellek sıfırlama garantisi verilmez.
- Doğrulanmış eski checkpoint'in geri konmasını veya tüm çalışma dizininin silinmesini önleyen dış zaman/sürüm otoritesi yoktur. AEAD değişiklikleri saptar; eksiksiz tarihçe ve geri alma koruması sağlamaz.
- Kaynak klasör ve orijinal dosyalar yerlerinde kalır. Önceden düz toplanmış veriler otomatik şifrelenmez veya güvenli silinmez. Düz çalışmayı şifreli moda yerinde dönüştürmek reddedilir; yeni çalışma başlatılmalıdır.
- Checkpoint ve dosya başına bellek sınırları korunur; AES-GCM sırasında ciphertext/bellek kopyaları nedeniyle tepe RAM kullanımı artar. 8 MiB parça belleğe alınır, tüm delil paketi alınmaz.
- Disk dolması/çıktı hatası paket üretimini durdurur; tamamlanmamış yeni çıktı kaldırılmaya çalışılır, çalışma parçaları korunur. SIGKILL/güç kesintisinde yarım çıktı kalabilir; yeni çıktı adıyla devam edin.
- Fiziksel USB/güç kesintisi ve Windows/macOS cihaz testleri yapılmadı. Test edilen süreç ölümü bunların eşdeğeri değildir.
- Kriptografik bileşenler Go standart kütüphanesidir; bu özel paket/akış uygulaması bağımsız güvenlik denetiminden geçmedi ve sertifikalı ürün iddiası yoktur.
- Önceki sürüm checkpoint'lerini oluşturan binary ile tamamlayın. Eski v1/v2 final delilleri yeni sürümle analiz edilebilir; analist değerlendirmeleri sürüm dayanağına bağlıdır.
