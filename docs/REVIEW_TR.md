# k957 0.3.0 — Analist değerlendirmesi

Yeni `review` komutu bir otomatik bulguya analist kararı ve gerekçe ekler. Ham delil paketi değiştirilmez; her güncelleme yeni bir JSON değerlendirme dosyasına yazılır. Raporun yeniden üretilmesi için delil yeniden doğrulanır ve analiz tekrar hesaplanır.

## İş akışı

1. Delili analiz edin:

```sh
k957 analyze --in vaka.k957 --rules rules.json --out ilk-analiz
```

`ilk-analiz/analysis.json`, `findings.csv` veya HTML raporundaki `F-...` bulgu kimliğini kopyalayın. Kimlik aynı delil manifesti, kural kimliği, kaynak ve eşleşme konumunda tekrar üretilebilir. Analiz çalıştırma kimliği her çalıştırmada yenidir; bulgu kimliği bu nedenle değişmez.

2. İlk değerlendirmeyi oluşturun:

```sh
k957 review --analysis ilk-analiz/analysis.json \
  --finding F-TAM_BULGU_KIMLIGI \
  --decision needs-review --analyst "Analist A" \
  --note "Kaynak kayıt ve kullanıcı bağlamı incelenecek." \
  --out degerlendirme-v1.json
```

Kararlar: `confirmed` (bulgu analistçe doğrulandı), `rejected` (bulgu değerlendirmede reddedildi), `needs-review` (ek inceleme gerekli). Bunlar suçluluk, fail kimliği veya kesin kötü amaçlılık hükmü değildir. Analist adı ve gerekçe zorunludur. Analist adı 256, gerekçe 16.000 byte ile sınırlıdır.

3. Eski dosyayı koruyarak sonraki kararı ekleyin:

```sh
k957 review --analysis ilk-analiz/analysis.json \
  --previous degerlendirme-v1.json \
  --finding F-TAM_BULGU_KIMLIGI \
  --decision rejected --analyst "Analist B" \
  --note "Sentetik test verisi olduğu doğrulandı." \
  --out degerlendirme-v2.json
```

4. Değerlendirmeyi rapora uygulayın:

```sh
k957 analyze --in vaka.k957 --rules rules.json \
  --reviews degerlendirme-v2.json --out degerlendirilmis-rapor
```

Aynı delil manifesti, kurallar, sürüm ve otomatik bulgu sonuçları gereklidir. Uyuşmazlık varsa rapor üretilmez. Son karar bulgu tablosunda gösterilir; önceki kararlar geçmiş tablosunda kalır. Reddedilen bulgular silinmez. Tüm geçmiş `analysis.json` içinde korunur. `findings.csv` son karar, analist ve gerekçeyi içerir.

## İmzalı değerlendirme

```sh
k957 keygen --out analist-imza
k957 review --analysis ilk-analiz/analysis.json \
  --finding F-TAM_BULGU_KIMLIGI --decision confirmed \
  --analyst "Analist A" --note "Kaynak kayıt kontrol edildi." \
  --sign-key analist-imza.key --out imzali-v1.json
k957 analyze --in vaka.k957 --rules rules.json \
  --reviews imzali-v1.json --review-key analist-imza.pub \
  --out imzali-rapor
```

İmzalı geçmişe ekleme yapılırken `--previous-key` ile önceki imza doğrulanmalı ve `--sign-key` ile yeni sürüm imzalanmalıdır. İmzalı geçmişin sessizce imzasız devamına izin verilmez. Yeni imzalayan önceki imzalayandan farklı olabilir; önceki dosyaları koruyun.

Delil imzası için `--trusted-key`, değerlendirme imzası için `--review-key` ayrı güven dayanaklarıdır. İmza mevcut olsa da güvenilir anahtar verilmemişse rapor doğrulanmış imza iddiasında bulunmaz.

## Güven ve sınırlar

- Girdi `analysis.json` bir delil doğrulama belgesi olarak kabul edilmez. Rapor uygulama aşamasında gerçek paket yeniden doğrulanır ve analiz tekrar hesaplanır.
- Değerlendirme dayanağı; uygulama sürümü, delil manifestinin SHA-256'sı, kurallar ve otomatik bulguların kanonik özetidir. Analiz çalıştırma zamanı/kimliği bu özete dahil değildir.
- Olaylar sıralı hash zinciri oluşturur. İmzasız zincir kimlik doğrulaması sağlamaz; dosyayı değiştirebilen biri zinciri yeniden hesaplayabilir.
- Ed25519 imzası yeni sürümün tamamını onaylar; bir kullanıcı hesabı, RBAC veya her önceki analistin ayrı kimlik kanıtı değildir. Analist isimleri serbest metindir. Anahtar sahipliği ve güveni kurum tarafından yönetilmelidir.
- Önceki dosyayı silme, valid eski sürüme geri dönme veya paralel iki dal üretme merkezi bir kayıt sistemi olmadan engellenmez. Geçmişin eksiksizliği veya güvenilir zaman damgası garantisi yoktur. Önceki sürümleri harici denetim kaydında saklayın.
- En fazla 10.000 değerlendirme olayı ve 32 MiB değerlendirme dosyası desteklenir. `LoadAnalysis` sınırı 128 MiB'dır; çok büyük analizler değerlendirme akışına sığmayabilir.
- HTML içerikleri escape edilir; CSV'de formül başlangıçları etkisizleştirilir. Görsel tarayıcı/erişilebilirlik testi yapılmadı.
- Bu sürüm CLI iş akışıdır; rapor tarayıcıdan düzenlenmez. Vaka sunucusu, eşzamanlı çok kullanıcı, rol yönetimi ve bağımsız ikinci onay zorunluluğu henüz yoktur.
- 0.1/0.2 analiz JSON'ları için kimlik migrasyonu yoktur; delil paketi 0.3 ile yeniden analiz edilmelidir. v1/v2 delil okuma desteği korunur.
- Aktif 0.2 checkpoint'i 0.3 ile devam ettirilemez: edinimi 0.2 binary'siyle tamamlayın, final paketi 0.3 ile analiz edin. Eski checkpoint'i elle düzenlemeyin.
