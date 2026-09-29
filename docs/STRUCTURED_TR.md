# k957 0.4.0 — Yapılandırılmış loglar ve kaynaklar arası ilişkiler

`analyze` artık UTF-8 CSV ve JSONL kayıtlarından zaman, kullanıcı, cihaz ve IP alanlarını çıkarır. Ek bağlantı veya ağ servisi gerekmez. Mevcut `collect` ile logları toplayıp `analyze` çalıştırmanız yeterlidir.

```sh
k957 collect --root loglar --out vaka.k957 --case VAKA-004 --operator Analist --scope "Onaylı loglar"
k957 analyze --in vaka.k957 --out rapor
```

## Desteklenen şema

| Anlam | Desteklenen alanlar |
|---|---|
| Zaman | `timestamp`, `time`, `@timestamp` |
| Açıklama | `message`, `event` |
| Kullanıcı | `user`, `username` |
| Cihaz | `host`, `hostname` |
| Kaynak IP | `src_ip`, `source_ip` |
| Hedef IP | `dst_ip`, `destination_ip` |

Zaman zorunludur ve açık saat dilimli RFC3339 biçiminde olmalıdır: `2026-09-27T14:00:00+03:00` veya `2026-09-27T11:00:00Z`. Diğer alanlar isteğe bağlıdır. Tanınan alanlarda metin değerleri beklenir; sayılar/nesneler reddedilir, null boş alan gibi ele alınır. Aynı anlamdaki iki alan farklı dolu değerler taşıyorsa kayıt atlanır. IP dolu ancak geçersizse tüm olay atlanır. JSON anahtarları büyük/küçük harfe duyarlıdır; bilinmeyen alanlar analizde kullanılmaz, orijinal delilde kalır.

CSV örneği:

```csv
timestamp,user,host,src_ip,dst_ip,message
2026-09-27T14:00:00+03:00,alice,workstation,192.0.2.1,198.51.100.2,login
```

JSONL örneği (her fiziksel satır tek JSON nesnesi):

```json
{"timestamp":"2026-09-27T11:01:00Z","username":"alice","hostname":"workstation","destination_ip":"192.0.2.1","message":"access"}
```

- `.csv`: virgül ayırıcı, başlık satırı, çift tırnaklı/çok satırlı alanlar ve CRLF desteklenir. CSV başlıkları küçük harfe çevrilip dış boşluklar kaldırılır. Yinelenen/boş başlık reddedilir; 128 sütun sınırı vardır.
- `.jsonl` / `.ndjson`: satır başına nesne; yinelenen JSON anahtarları reddedilir. CSV'nin çok satırlı alan desteği JSONL için geçerli değildir.
- Diğer UTF-8 dosyalarda açık RFC3339 ile başlayan metin veya JSON nesnesi satırları okunur.
- Noktalı virgül/sekme ayırıcılar, UTF-16, otomatik yıl/saat dilimi tahmini, iç içe ECS alanları ve native EVTX/journal formatları bu sürümde desteklenmez.

## Kaynak izlenebilirliği

Olaylarda delil kimliği, kaynak yolu, fiziksel satır numarası, sıfır tabanlı byte başlangıcı, orijinal zaman ve UTC karşılığı korunur. CSV'de satır ve byte konumu çok satırlı kaydın başlangıcını gösterir; metin içindeki bir alanın ayrı offset'i değildir. CSV CRLF normalizasyonu ayrıştırılmış açıklamayı etkileyebilir; tam byte içeriği orijinal delildedir. Açıklama görüntüsü 400 Unicode karakterle sınırlıdır.

`analysis.json` içindeki `parse_summaries` ve HTML'deki **Ayrıştırma kapsamı** tablosu, incelenen dolu kayıt, üretilen olay ve atlanan kayıt sayılarını gösterir. Boş satırlar sayılmaz. CSV yapısal hata veya yanlış sütun sayısında o dosyanın ayrıştırılması durur; hata ve atlanan kayıt sayısı yazılır. `limited=true` kalan kayıtların olay bütçesi nedeniyle işlenmediğini belirtir; `rows` bu durumda tüm dosyanın kayıt sayısı değildir.

Metin/binary/boyut bütçesi nedeniyle hiç incelenmeyen dosyalar mevcut analiz notlarında belirtilir. Düz metin kuralları satır bazlı çalışmaya devam eder; çok satırlı CSV alanlarının birleştirilmiş içeriğinde ayrı kural motoru uygulanmaz.

## İlişkilendirme

Aynı kullanıcı, cihaz adı veya IP değeri en az iki farklı delil nesnesinde görülürse bir ilişki kaydı üretilir. IP adresleri standartlaştırılır (IPv4-mapped IPv6, IPv4'e dönüştürülür). Cihaz adları küçük harfe çevrilir ve sondaki nokta kaldırılır. Kullanıcı adı büyük/küçük harfe duyarlıdır; dış boşluklar kaldırılır. Kaynak ve hedef IP aynı olayda aynıysa olay bir kez sayılır; iki rol birlikte kaydedilir.

Her ilişkide olay sayısı, farklı delil sayısı, ilk/son zaman ve kaynak kayıt referansları vardır. Çıktılar: HTML tablosu, `analysis.json` ve özet `correlations.csv`. Ayrıntılı referanslar JSON ve HTML'dedir. Sonuç sıralaması belirlenimlidir.

**Ortak değer, aynı kişi/cihazın veya saldırının kanıtı değildir.** NAT, paylaşılan hesap, aynı dosyanın farklı kopyaları, yeniden kullanılan IP'ler ve isim çakışmaları ilişki oluşturabilir. İki delil nesnesi, iki bağımsız kaynak anlamına gelmez. Zaman yakınlığı için otomatik eşik veya nedensellik çıkarımı yoktur; sadece desteklenen kayıtlardaki ortak alanlar listelenir. DNS, WHOIS ve tehdit istihbaratı sorgusu yapılmaz.

## Kaynak sınırları

- Mevcut 8 MiB/dosya ve 128 MiB toplam UTF-8 okuma sınırı korunur.
- En fazla 50.000 ayrıştırılmış log olayı; dosya metadata olayları buna eklenir.
- JSONL satırı ve CSV hücresi en fazla 65.536 byte.
- Kullanıcı/cihaz/IP alanı en fazla 256 byte; limit aşımında olay atlanır.
- En fazla 20.000 farklı varlık anahtarı. Yeni değerler sınırdan sonra atlanır ve analiz notuna yazılır.
- İlişki başına en fazla 200 referans listelenir; olay/delil sayıları işlem gören olaylardan hesaplanmaya devam eder. Referans listesi tüm kaynakları temsil etmeyebilir; `references_truncated` işaretine bakın ve zaman çizelgesini inceleyin.
- Otomatik bulgu sınırına ulaşılması analizi erken bitirebilir; mevcut sınırlama notu korunur.

## Sürüm geçişi

v1/v2 delil paketleri okunur. Eski değerlendirme kayıtları sürüm dayanağı nedeniyle 0.4'e otomatik taşınmaz; eski imzalı raporları koruyun ve yeni analizi yeniden değerlendirin. Önceki sürümle açılmış toplama checkpoint'lerini aynı önceki binary ile tamamlayın; final paketleri 0.4 ile analiz edebilirsiniz.
