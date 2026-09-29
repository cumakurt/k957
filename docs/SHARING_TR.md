# Maskelenmiş paylaşım raporu — v0.8.0

`share`, doğrulanmış bir delil paketini yeniden analiz ederek **ayrı bir paylaşım raporu** üretir. Ham delili, özgün raporu, analist kararlarını veya devir kayıtlarını değiştirmez. HTML, JSON ve CSV aynı daraltılmış veri modelinden üretilir; özgün `analysis.json` üzerinde metin değiştirme yapılmaz.

## Varsayılan kullanım

```sh
k957 share --in /delil/vaka.k957 --out /paylasim/vaka-001 \
  --rules /kurallar/rules.json --trusted-key /guvenli/edinim.pub
```

`--trusted-key` ve `--rules` isteğe bağlıdır. Delil nesnelerinin hash'leri her zaman doğrulanır; kaynak imzasının güvenilir anahtarla doğrulanması için `--trusted-key` gerekir. Şifreli zarf önce yetkili ortamda `unseal` ile açılmalıdır.

Politika verilmezse vaka adı, kişi/kullanıcı, cihaz, IP, yol ve konumlar takma değerlerle gösterilir. Kaynak zamanları çıkarılır. Örneğin aynı kaynak yolu, bu raporun tüm tablolarında `[PATHS-000001]` olarak gösterilir. Bir kategori içindeki aynı değer aynı takma adı alır; farklı kategoriler arasında kişi/kimlik birleştirmesi yapılmaz.

Her paylaşım raporu yeni bir kimlik alır. Delil, kural ve bulgu kimlikleri rapor içinde yeniden numaralandırılır. Özgün hashler, imzalar, paket/çalıştırma kimlikleri ve geri eşleme tablosu paylaşım dizinine yazılmaz. Bu nedenle paylaşım dosyası özgün delili bağımsız doğrulamak veya `review` komutuna dayanak olmak için kullanılamaz.

## Açık bırakılacak alanları seçme

```json
{
  "schema": "k957-share-policy/1",
  "keep": ["timestamps"],
  "literals": ["Müşteri A", "GizliProje"]
}
```

```sh
k957 share --in /delil/vaka.k957 --out /paylasim/vaka-002 \
  --rules /kurallar/rules.json --policy /guvenli/paylasim.json
```

| keep değeri | Açık bırakılması istenen alanlar |
|---|---|
| case | Vaka adı |
| users | Yapılandırılmış kayıtlardaki kullanıcı alanları |
| hosts | Toplama cihazı ve yapılandırılmış kayıtlardaki cihaz alanları |
| ips | Ayrıştırılmış kaynak/hedef IP ve ilgili ortak değerler |
| paths | Kaynak yolları ve kaynak referansları |
| actors | Operatör, analist ve devir tarafları |
| locations | Devir kayıtlarındaki konum |
| timestamps | Yapılandırılmış kaynak, olay, değerlendirme ve devir zamanları |

Boş `keep` tüm bu kategorileri maskeler/çıkarır. Seçenek adları küçük harflidir; bilinmeyen veya yinelenen seçenekler reddedilir.

Açık bırakılan **metin alanlarında**, diğer maskeli kategorilerdeki bilinen değerler ve `literals` ifadeleri `[MASKED]` ile değiştirilir. Örneğin paths açık, users kapalıysa ayrıştırılmış kullanıcı adının kaynak yolunda geçen yazımı da temizlenir. Bir kullanıcı değeri aynı zamanda kapalı actors kategorisindeki bir değer ise users açık olsa bile maskelenir. Çakışmada daha uzun eşleşme kullanılır; büyük/küçük harf duyarsız Unicode basit harf eşleştirmesi uygulanır. Regex metakarakterleri özel anlam taşımaz. Unicode normalizasyonu, alternatif yazım, URL kodlama veya farklı IP gösterimlerini bulma yapılmaz.

`literals` özgün haliyle rapora kopyalanmaz; yalnızca ifade sayısı gösterilir. İfadeler, açık bırakılan kaynak metinlerine uygulanır. Sabit arayüz metinleri, üretilen takma adlar ve sayısal alanlar taranmaz. Timestamps seçeneği yapılandırılmış zaman alanlarını etkiler; açık bırakılmış dosya adları içinde yer alan tarihleri otomatik tanımaz.

## Her zaman çıkarılan içerikler

Bu sürümde serbest metni koruma seçeneği yoktur. Bulgu alıntıları, olay açıklamaları, kural adları/içerikleri/açıklamaları, kaynak kapsamı, analist gerekçeleri, devir notları, hata ayrıntıları ve özgün yöntem notları aktarılmaz. Bir kategori açık bırakılsa da bu içerikler çıkarılır. Böylece ayrıştırılmamış metindeki bilinmeyen kişisel bilgiler rapora taşınmaz.

Dosya boyutları, kayıt/bulgu sayıları, toplama durumu ve sorun sayısı, ayrıştırma sayıları, satır/byte konumları, kaynaklar arası ortaklıklar, karar durumları ve olay sırası korunur. Bunlar yeniden kimliklendirmeye yardımcı olabilir. Ürün anonimlik garantisi vermez. Ayrıntılı yöntem ve eksiklik notları özgün raporda kalır; paylaşım raporu tek başına kapsamlı uzman değerlendirmesinin yerine geçmez.

## İmzalı değerlendirmeler ve devir geçmişi

```sh
k957 share --in /delil/vaka.k957 --out /paylasim/vaka-003 \
  --rules /kurallar/rules.json \
  --reviews /kayit/reviews.json --review-key /guvenli/analist.pub \
  --custody /kayit/custody.json --custody-trust /guvenli/trust.json \
  --custody-head BAGIMSIZ_SAKLANAN_SON_OZET
```

Önce özgün analiz tekrar üretilir; değerlendirme ve devir dosyaları mevcut doğrulama kurallarıyla kontrol edilir. Başarısız doğrulamada paylaşım dizini üretilmez. Ardından maskelenmiş karar/devir özeti alınır. Orijinal imzalar ve hash zinciri maskelenmiş içerik için geçerli sayılamayacağından paylaşım raporuna aktarılmaz. HTML bu çıktının imzalı delil veya devir kaydı olmadığını açıkça belirtir.

## Çıktılar

- `report.html`: çevrimdışı açılan, aramalı Türkçe paylaşım raporu.
- `shared.json`: `k957-shared-report/1` şemalı türev veri; `analysis.json` değildir.
- `evidence.csv`, `findings.csv`, `timeline.csv`, `correlations.csv`, `reviews.csv`.
- `custody.csv`: devir olayları varsa oluşturulur.

Dizine delil paketi, özgün rapor, kural/politika dosyası, açık/özel anahtar veya imza kaydı eklenmez. Tam proje ZIP'indeki örnek kaynaklar ve normal raporlar maskelenmemiş sentetik veriler de içerir. Gerçek bir paylaşım için yalnızca inceleyip onayladığınız **share çıktı dizinini** kullanın; kaynak dosyaları sonradan bu dizine eklemeyin.

Var olan çıktı dizini üzerine yazılmaz. Oluşturma sırasında hata alınırsa yeni dizin kaldırılmaya çalışılır. Paylaşım çıktıları şifreli değildir; taşıma ve erişim izinleri ayrıca yönetilmelidir.

## Kaynak sınırları ve doğrulama

Politika dosyası en fazla 1 MiB; en fazla 100 literal ve literal başına 512 UTF-8 byte kabul edilir. Açık bırakılmış kaynak metinlerinde çapraz maskeleme için en fazla 20.000 benzersiz ifade ve toplam 1 MiB kaçış uygulanmış ifade metni kullanılır. Limit veya derleyici karmaşıklık sınırı aşılırsa rapor yazılmaz. Tamamen maskelenmiş varsayılan politika bu metin eşleştirme aşamasını gerektirmez.

Birim testleri tüm paylaşım dosyalarında özel değerlerin bulunmamasını, tutarlı takma değerleri, çapraz alan maskelemesini, uzun eşleşme önceliğini, HTML/CSV güvenliğini ve özgün analizin değişmemesini kontrol eder. `python3 scripts/share_integration.py`, imzalı analist/devir girdileriyle sekiz çıktı dosyasını tarar; özgün delil, analiz ve kayıtların byte hash'lerini karşılaştırır. Bilinen sentetik işaretlerin bulunmaması tüm gerçek dünya kişisel verilerinin otomatik tespit edildiği anlamına gelmez.

Açık toplama checkpoint'lerini oluşturuldukları binary ile tamamlayın. v1/v2 final paketleri okunabilir. Analist review kayıtları analiz sürümüne bağlıdır; bu sürümle yeni analiz/değerlendirme üretilmelidir. Devir kayıtlarının formatı sürümden bağımsız kalır.

## v0.9 PCAP alanları

Paylaşım raporuna maskelenmiş PCAP olayları, yönlü akışlar ve kapsam tabloları eklenir. `network.csv` ve `captures.csv` koşullu üretilir. IP/yollar kapalı, kaynak zamanları çıkarılmış olarak başlar. Portlar, TCP bayrakları, çerçeve uzunlukları, sayılar ve paket/byte referansları korunur. Ayrıntılar `PCAP_TR.md`.
