# k957 0.2.0 — Kesintiye dayanıklı mantıksal toplama

Update for 0.11.0: `preflight --resume` estimates remaining space from saved work; `collect --resume --check-space` gates collection with that plan. See [RESUME_PREFLIGHT.md](RESUME_PREFLIGHT.md). Earlier-version checkpoints still require their original binary.

Bu sürümün geliştirmesi, önceki yol haritasındaki checkpoint/devam ettirme adımıdır. `collect --work` yeni bir çalışma klasörüne 8 MiB parçalar kaydeder. `--resume` aynı envanter ve kapsam üzerinde devam eder. Eski `collect` akışı değişmez; `--work` verilmediyse 0.1.0'daki tek geçişli davranış sürer.

## Kullanım

İlk çalıştırma (üç ayrı yol, mevcut kaynak ve yeni çıktı/çalışma dizini):

```sh
k957 collect --root /kaynak \
  --work /harici-disk/VAKA-002-work \
  --out /harici-disk/VAKA-002.k957 \
  --case VAKA-002 --operator Analist --scope "Onaylı klasör"
```

Kontrollü iptal (Ctrl+C) veya hata sonrası aynı komuta `--resume` ekleyin:

```sh
k957 collect --root /kaynak \
  --work /harici-disk/VAKA-002-work \
  --out /harici-disk/VAKA-002.k957 \
  --case VAKA-002 --operator Analist --scope "Onaylı klasör" \
  --resume
```

Durumu salt okunur olarak incelemek için:

```sh
k957 work-status --work /harici-disk/VAKA-002-work --verify-parts
```

Çıktı: planlanan dosya/bayt, tamamlanan dosya, alınan bayt/parça, parça doğrulama durumu, kilit varlığı ve edinim dönemleri. `--verify-parts` kullanılmazsa hash doğrulaması yapılmaz. Bu komut kaynak dosyaları doğrulamaz; yalnızca kaydedilmiş parçaları kontrol eder. Kilit varlığı çalışan süreç olduğunun kanıtı değildir.

Tamamlanan paket standart `verify` ve `analyze` komutlarıyla kullanılır. Opsiyonel `--sign-key` final paketi imzalar. İmza anahtarı çalışma veya kaynak ağacında bulunamaz. Aynı çalışmanın tamamlanmış verisinden başka bir paket üretmek için `--resume` ve yeni `--out` kullanılabilir; bu yeniden kaynak edinimi değildir.

## Kaydedilen bilgiler

- İlk çalıştırmada sabitlenen kaynak envanteri, boyut ve değiştirilme zamanı.
- Her parça için byte başlangıcı, boyut, SHA-256, edinim dönemi kimliği ve alınma zamanı.
- Her çalıştırma için başlangıç/bitiş, hostname, OS/mimari ve sonuç.
- Dosyanın tamamı için SHA-256, toplam boyut ve tamamlanma zamanı.
- Final pakette v2 şema; Analyze raporunda edinim dönemleri ve açık sınırlama notu.

Parça önce geçici dosyaya yazılır, `fsync` edilir ve hash adına taşınır. Checkpoint geçici dosyada hazırlanıp `fsync`/rename ile değiştirilir. Desteklendiğinde klasör senkronizasyonu da denenir. Parça kaydı tamamlanmadan checkpoint o parçayı referans almaz. Kayda girmemiş parça veya geçici dosyalar devam sırasında delil kabul edilmez.

## Devam sırasında doğrulama

1. Kapsam, kaynak kökü, vaka, operatör ve boyut/dosya limitleri ilk çalışmayla aynı olmalı.
2. Kaydedilmiş parçalar yeniden SHA-256 ile doğrulanır; tamamlanmış dosyanın birleşik hash'i de kontrol edilir.
3. Yarım dosyanın boyut ve zamanı ilk envanterle karşılaştırılır.
4. Yarım dosyanın daha önce alınmış ön bölümü kaynaktan yeniden okunur; her parça hash'i karşılaştırılır. Sadece boyut/zaman eşitliğine güvenilmez.
5. Sonraki parçalar yeni edinim dönemiyle kaydedilir.
6. Final paket oluşturulurken parçalar tekrar doğrulanır; `verify` hem parça hem dosya hash'lerini denetler.

Kaynak değişmiş veya parça bozulmuşsa sessiz yeniden yazma yapılmaz. Mevcut çalışma korunur; hata açıklanır. Değişen kaynak için yeni çalışma diziniyle yeni edinim başlatın.

## Donmuş envanter ve farklı zamanlar

**Paket tek bir anlık görüntü değildir.** İlk çalıştırmadan sonra oluşturulan dosyalar dahil edilmez. Tamamlanmış dosyalar tekrar kaynak okuması yapılmadan saklanan parçalardan kullanılır; kaynak sonradan değişse veya silinse bile eski edinim korunur. Yarım dosyanın devamı için kaynak hâlâ erişilebilir olmalıdır. Ön bölüm yeniden okunması da canlı sistemde atomik snapshot garantisi vermez.

Kapsam veya operatör değiştirilerek aynı çalışma sürdürülemez. Yeni kaynak edinimi gerekiyorsa yeni çalışma açın. Sistem anlık görüntüsü komutları bu moda dahil edilmedi: `--work --system` açık hata verir. Bunları ayrı `collect --system` edinimi olarak alın.

## Ani süreç ölümü / stale lock

Her yazan süreç `active.lock` oluşturur. Başka süreç aynı çalışmayı açamaz. Ctrl+C ve normal hata kapanışlarında kilit kaldırılmaya çalışılır. SIGKILL, güç kaybı veya fiziksel bağlantı kopması sonrasında kilit kalabilir.

1. Hiçbir toplayıcının o çalışma dizinini kullanmadığını süreçlerden ve operatörlerden doğrulayın.
2. Çalışmayı başka süreç kullanmıyorsa yalnızca ilgili `active.lock` dosyasını kaldırın. Çalışan bir sürecin kilidini silmeyin.
3. `work-status --verify-parts` ile veriyi kontrol edin.
4. `--resume` ile sürdürün. Önceki dönem `running` durumunda kalmışsa sonlanma saati uydurulmaz; `interrupted; end time unknown` olarak gösterilir.

Final ZIP yazılırken SIGKILL olmuşsa yarım çıktı ayrıca kalabilir. Çıktıyı kanıt olarak kabul etmeyin; `verify` uygulayın. Devam için farklı yeni bir `--out` adı seçebilirsiniz. Araç var olan çıktıyı ezmez.

## Sınırlar

- Varsayılan çalışma klasörü düz metin delil içerir. v0.5 ile `--encryption-key` seçeneği şifreli checkpoint/parçalar ve final çıktı ekler; ENCRYPTED_COLLECTION_TR.md dosyasına bakın. Mevcut `seal` ayrıca sonradan şifreleme için kullanılabilir.
- Düz checkpoint ayrı imzalı değildir; şifreli modda AEAD bütünlük denetimi vardır. Çalışma dizini güvenilir depolamada tutulmalı ve yetkisiz değişiklikten korunmalıdır. Bir saldırganın hem state.json hem veriyi değiştirmesine karşı kimlik doğrulama garantisi yoktur.
- Sufficient space is required for staging and the final package. Optional fresh/resume capacity preflight is available; physical source/output device separation is not verified.
- Dizin fsync ve rename dayanıklılığı dosya sistemi/OS/donanıma bağlıdır; elektrik kesintisi veya bozuk USB donanımı garantisi verilmez.
- 32 MiB checkpoint, 16 MiB final manifest, 1.000 edinim dönemi sınırı vardır. Çok fazla küçük dosya/parça metadata sınırına ulaşabilir.
- İlk envanter oluşturulmadan kesilirse devam edilecek state.json bulunmayabilir; yeni çalışma dizini gerekir.
- OS/mimari binary'leri derlenir; gerçek Windows/macOS USB testleri yapılmadı. Windows ACL ve macOS uygulama izinleri ayrıca yönetilmelidir.
- Çalışma dosyaları otomatik silinmez. Final paketi doğrulayıp saklama politikasını uyguladıktan sonra operatör yönetir. Güvenli silme iddiası yoktur.

## Uyumluluk

0.2.0, v1 ve v2 delil paketlerini okur. `--work` paketleri `k957-evidence/2` kullanır. Eski 0.1.0 analiz binary'si v2 paketi açamaz. Checkpoint sürümü `k957-work/1` ve üretici uygulama sürümüyle bağlıdır; farklı uygulama sürümlerine otomatik checkpoint migrasyonu yoktur.
