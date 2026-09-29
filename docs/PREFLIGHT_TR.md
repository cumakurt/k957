# Toplama öncesi kontrol

Version 0.11.0 also supports `preflight --resume` and `collect --resume --check-space` for existing plain/encrypted checkpoints. See [RESUME_PREFLIGHT.md](RESUME_PREFLIGHT.md) for remaining-space accounting, required original options/key and validation limits. The fresh-acquisition workflow is documented below.

`preflight`, yeni bir mantıksal edinimin kaynak envanterini ve tahmini depolama ihtiyacını JSON olarak gösterir. Dosya içeriklerini okumaz/kopyalamaz, çıktı veya çalışma dizini oluşturmaz, yer ayırmaz. Dizin/metadata okumaları işletim sistemindeki erişim kayıtlarını etkileyebilir; hedefte sıfır değişiklik garantisi değildir.

```sh
k957 preflight --root /kaynak --out /harici/vaka.k957 \
  --work /harici/vaka-work --reserve 268435456
```

Hedeflerin üst dizinleri mevcut, çıktı ve çalışma alanı ise henüz oluşturulmamış olmalıdır. `--work` verilmezse yalnızca çıktı için bütçe hesaplanır. `--encrypted` şifreli çalışma/çıktı ek yükünü hesaba katar; anahtar okumaz ve doğrulamaz. Sonuç standart çıktıya yazılır; yolları ve dosya adlarını içerebilir. JSON'u kaydedecekseniz kaynağın dışında, uygun erişim izinlerine sahip bir konum seçin.

## Sonuçların anlamı

| outcome | Anlamı | CLI çıkış kodu |
|---|---|---|
| pass | Uygulanan kontrollerde sorun bulunmadı | 0 |
| warning | Kaynak/hedef aynı dosya sistemi, boş seçim veya envanter dışlamaları var | 0 |
| unknown | Dosya sistemi kimliği veya boş alan belirlenemedi | 1 |
| blocked | Yol çakışması, mevcut hedef veya tahmini alan yetersizliği var | 1 |

Birden fazla durum varsa blocked, unknown, warning, pass sırasıyla en güçlü sonuç seçilir. `checks` ve `inventory_issues` her zaman incelenmelidir; warning sonucu tam envanter garantisi vermez.

## Alan hesabı

Ön kontrol, devam ettirilebilir toplamanın metadata envanterini kullanır. Varsayılanlar dosya başına 256 MiB, toplam 2 GiB ve 10.000 dosyadır; `--max-file`, `--max-total`, `--max-files` ile değiştirilebilir. Symlink/özel dosyalar ve limit dışı dosyalar gerekçeleriyle atlanır. Dosya sayısı sınırına erişildiğinde kalan ağaç gezilmez. `eligible_bytes`, seçilen dosyaların mantıksal boyutudur; fiziksel disk doluluğu değildir. Tek geçişli toplama ve daha sonra değişmiş bir kaynak farklı sonuç verebilir.

Tahmin, seçili byte sayısına ZIP/manifest için %1 + dosya başına 1 KiB + 16 MiB; çalışma alanı için %10 + dosya/parça başına 4 KiB + 64 MiB planlama payı ekler. Şifreli modda blob ve zarf ek yükleri ayrıca eklenir. Bunlar kanıtlanmış en kötü durum sınırları değildir. Özellikle dosya sistemi tahsis birimi, quota, snapshot, sıkıştırma, uzun yollar, büyüyen kaynak ve eşzamanlı yazıcılar gerçek tüketimi değiştirebilir.

Çıktı ve çalışma alanı aynı dosya sistemindeyse ihtiyaçları toplanır; `--reserve` yalnızca bir kez eklenir. Farklı dosya sistemlerinde her birine ayrı rezerv eklenir. Aynı dosya sisteminden farklı zamanlarda alınan kapasite örneklerinin küçüğü kullanılır. Varsayılan rezerv 256 MiB'dir. Toplama alan tüketirken tekrar kontrol yapılmaz, alan kilitlenmez/rezerve edilmez.

Linux/macOS üzerinde statfs ve aygıt kimliği, Windows üzerinde GetDiskFreeSpaceExW ve volume GUID kullanılır. Farklı bölümler aynı fiziksel aygıtta olabilir; bu modül fiziksel disk ayrımı veya write blocker kontrolü yapmaz. Kimliği belirlenemeyen ağ/paylaşım dosya sistemleri unknown dönebilir.

## Toplamanın önüne bağlama

```sh
k957 collect --root /kaynak --out /harici/vaka.k957 \
  --work /harici/vaka-work --case VAKA-001 --operator Analist \
  --scope "Onaylı klasör" --check-space --reserve 268435456
```

`--check-space` isteğe bağlıdır. blocked/unknown halinde toplama başlamaz; warning/pass halinde devam eder. Ayrıntılı JSON için bağımsız `preflight` komutunu kullanın. Şifreli toplamada `--encryption-key` verilmesi tahmini şifreli moda geçirir; stderr yalnızca ön kontrol sonucunu gösterir.

Fresh acquisition rebuilds its inventory after preflight. Resume planning uses the frozen checkpoint and supports `--check-space`; see [RESUME_PREFLIGHT.md](RESUME_PREFLIGHT.md). System snapshots remain unsupported. Reading/writing permissions, destination health and evidence content integrity are not established by a capacity plan; collection performs its own checks. No point-in-time consistency or reserved capacity is implied.

## Doğrulama ve uyumluluk

Controlled unit tests cover capacity boundaries, uncertainty, combined/separate budgets and resume guards. `scripts/preflight_integration.py`, `scripts/resume_integration.py` and `scripts/encrypted_integration.py` exercise native capacity, unchanged checkpoint bytes and gated recovery. Current platform receipts are in [TEST_REPORT.md](TEST_REPORT.md). Native Windows/macOS devices and physical disk exhaustion remain untested.

v0.5 ve daha eski açık checkpoint işleri oluşturuldukları binary sürümüyle tamamlanmalıdır. Bu sürüm eski v1/v2 final delil paketlerini okuyabilir; değerlendirme dosyaları ise analiz sürümüne bağlıdır ve yeni analiz için yeniden üretilmelidir.
