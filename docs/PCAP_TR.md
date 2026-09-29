# Klasik PCAP analizi — v0.9.0

`analyze` ve `share`, paket içindeki desteklenen PCAP dosyalarını otomatik tanır. Kaynak dosyanın `.pcap`, `.cap`, `.pcapng` uzantısı veya bilinen PCAP magic byte'ları kullanılır. Dosya uzantısı olmayan klasik PCAP de tanınır. This page documents the classic-PCAP behavior introduced in 0.9.0. Version 0.10.0 adds PCAPNG and Linux SLL/SLL2; see [PCAPNG.md](PCAPNG.md) for the current extension and its limits.

```sh
k957 collect --root /inceleme/ag-kayitlari --out /delil/ag.k957 \
  --case VAKA-001 --operator Analist --scope "Onaylı ağ kayıtları"
k957 analyze --in /delil/ag.k957 --out /rapor/ag-001
k957 share --in /delil/ag.k957 --out /paylasim/ag-001
```

Bu modül mevcut yakalama dosyalarını inceler. Canlı trafik yakalama, arayüz açma, paket gönderme, internet zenginleştirmesi veya DNS çözümleme yapmaz. Hedef makinede libpcap/Npcap kurulumu gerektirmez.

## Desteklenen kapsam

| Katman | Bu sürüm |
|---|---|
| Dosya | Klasik PCAP v2.4; little/big endian; mikro/nanosaniye zaman damgası |
| Bağlantı tipi | Ethernet (`LINKTYPE_ETHERNET=1`), başlıksız IPv4/IPv6 (`LINKTYPE_RAW=101`) |
| VLAN | En fazla iki 802.1Q/802.1ad etiketi üzerinden IP başlığına erişim |
| IPv4 | Başlık uzunluğu, toplam uzunluk, kaynak/hedef adres, protokol |
| IPv6 | Temel başlık; en fazla sekiz Hop-by-Hop, Routing, Destination Options veya AH uzantısı |
| Taşıma | TCP/UDP kaynak/hedef portları; TCP bayrak alanının alt sekiz biti |
| Zaman | UTC; PCAP hassasiyeti nanosaniyeye kadar korunur |
| Kaynak bağı | Delil kimliği, kaynak yolu, paket sıra numarası, PCAP kayıt başlığının byte konumu |

IP fragmentleri yeniden birleştirilmez; IPv4 parçaları ve tüm IPv6 Fragment başlığı taşıyan paketler (atomic fragment dahil) atlanır. IPv6 sıfır payload uzunluğu/jumbogram, ESP, diğer IP protokolleri, ARP, Wi-Fi/radiotap ve ek link/FCS metadata alanları ayrıştırılmaz. PCAPNG and Linux SLL/SLL2 are supported from 0.10.0 as described in [PCAPNG.md](PCAPNG.md). Desteklenmeyen dosya/başlıklar raporda belirtilir. Ayrıştırılan TCP/UDP başlıkları dışındaki içerik incelenmez; DNS, HTTP, TLS, dosya çıkarımı veya payload kuralları yoktur.

Paket checksum'ları, tam protokol geçerliliği ve IPv6 uzantı sırası doğrulanmaz. Dosya bütünlüğü SHA-256 kontrolüyle ayrı bir katmanda doğrulanır; bu, yakalanan trafiğin gerçekliği veya protokol checksum'larının doğruluğu değildir.

## Yönlü akışların anlamı

Her delil dosyasında aynı **protokol + kaynak IP/port + hedef IP/port** birleşimine sahip paketler bir grupta sayılır. Ters yön ayrı gruptur. TCP oturum kurulumu, kapanışı, yeniden gönderim veya sıra takibi yapılmaz. Aynı beşliyle farklı zamanlarda açılmış oturumlar birleşir. MAC adresleri, VLAN kimliği ve yakalama arayüzü gruplama anahtarına dahil değildir; farklı ağlarda aynı adreslerin kullanılması ayrıca değerlendirilmelidir.

Her grupta paket sayısı, yakalanan byte toplamı, PCAP'in bildirdiği orijinal byte toplamı, en erken/en geç zaman ve sınırlı paket referansları bulunur. Byte toplamları PCAP kayıtlarındaki **çerçeve uzunluklarıdır**; uygulama verisi miktarı veya ağda başarıyla teslim edilmiş byte sayısı değildir. Yakalanan uzunluk orijinal uzunluktan küçükse eksik yakalama olarak sayılır. Gerekli IP/TCP/UDP başlıkları tam ise paket özetlenebilir; başlık eksikse atlanır.

PCAP dosyasında zaman sırası bozuk olabilir; ilk/son zaman minimum/maksimum değerden hesaplanır. Zamanlar yakalama sisteminin saatine dayanır. Saat sapması ölçülmez; yerel saat dilimi tahmini uygulanmaz.

## Çıktılar ve ilişkiler

- `analysis.json`: `capture_summaries` ve `network_flows`; zaman çizelgesinde `pcap_packet` olayları.
- `report.html`: PCAP kapsamı, atlama nedenleri, yönlü akışlar ve paket referansları.
- `network.csv`: en az bir ayrıştırılmış akış varsa akış tablosu.
- `captures.csv`: en az bir PCAP adayı varsa kapsam ve sayaçlar.
- `timeline.csv`: paket numarası, protokol, portlar, yakalanan/orijinal uzunluk ve TCP bayrakları için ek sütunlar.

PCAP içindeki IP'ler, yapılandırılmış loglar ve diğer delil nesneleriyle ortak değer ilişkilendirmesine katılır. JSON referansındaki `packet` ve `byte_offset` alanları paket kaydını gösterir. Offset, dosyanın başından itibaren **16 byte'lık PCAP paket kayıt başlığının** başlangıcıdır; IP veya payload başlangıcı değildir. Paket numarası 1'den başlar; atlanan tam kayıtlar da sıra numarasına dahildir. Ortak IP aynı kişi/cihazı veya bağımsız kaynak doğrulamasını kanıtlamaz.

Dosyanın SHA-256 kuralı uygulanabilir. Düz metin kuralları PCAP payload'ını taramaz; aynı metin kuralı ayrı metin/log dosyalarında çalışmaya devam eder.

## Kapsam sayaçları ve sınırlar

- Dosya başına en fazla 64 MiB; PCAP dosyaları için toplam 256 MiB okuma bütçesi. Büyük dosyanın yalnızca ilk kısmı okunmaz, dosya analizi atlanır.
- Dosya başına en fazla 20.000 kayıt. Metin logları ve PCAP için ortak 50.000 birimlik bütçe vardır: metinler üretilen log olayı, PCAP her tam okunan kayıt için bir birim tüketir. Metadata olayları bu bütçenin dışındadır.
- Analiz başına en fazla 10.000 yeni yönlü akış. Limitten sonra yeni akışlara ait paketler `flow_omitted_packets` içinde sayılır; zaman çizelgesinde kalabilir. Daha önce açılmış aynı dosyadaki gruplar sayılmaya devam eder.
- Akış başına ilk 20 paket referansı saklanır; daha fazlası varsa `references_truncated` true olur. Akış sayacı yalnızca bu 20 referansla sınırlı değildir.
- Tek kayıt için en fazla 1 MiB yakalanan veri; uzunluk snaplen veya orijinal uzunluğu aşamaz. Geçersiz kayıt uzunluğu/eksik başlık/gövde varsa dosyanın kalanında yeniden senkronizasyon yapılmaz.

`records`, dosyadan sınırları doğrulanarak tam okunan kayıt sayısıdır. `parsed + skipped = records`. Bozuk/yarım son kaydın geri kalanı bu sayıya dahil değildir; dosya hatası ayrıca gösterilir. `skip_reasons` geçersiz zaman, eksik başlık, desteklenmeyen protokol, fragment gibi nedenleri ayırır. `truncated_packets` bağımsız sayaçtır; hem ayrıştırılan hem atlanan kayıtlarda artabilir. `limited` dosya/byte/kayıt bütçesini, `flow_omitted_packets` ise akış bütçesini gösterir. Bunlar dosyanın tamamının incelendiği varsayımıyla yorumlanmamalıdır.

## Paylaşım raporu

PCAP zaman çizelgesi, akışlar, referanslar ve kapsam tablosu ayrı paylaşım şemasına aktarılır. Varsayılan olarak IP ve kaynak yolları takma değerlere çevrilir, kaynak zamanları çıkarılır. Protokol, portlar, bayraklar, uzunluklar, sayaçlar, kayıt sırası ve konumları korunur; anonimlik garantisi yoktur. `--policy` ile açık bırakılan kategoriler ve çapraz alan maskelemesi mevcut paylaşım kurallarını izler. Ayrıntılar `SHARING_TR.md`.

## Doğrulama

Birim testleri dört zaman/endian varyantını, IPv4/IPv6, VLAN, uzantı başlıkları, fragmentler, bozuk uzunluklar, eksik yakalama, kayıt/akış/referans limitleri ve ters yönleri kapsar. `scripts/pcap_integration.py`, Python struct ile bağımsız sentetik dosyalar üretir, PCAP kayıt byte'larını okuyarak zaman/konum/boyut sonuçlarını karşılaştırır. IPv4 ve taşıma checksum'ları fixture oluşturulurken hesaplanır; k957 bunları doğrulamaz. Fuzz sonucu `pcap-fuzz.txt` ve ayrıntılı test özeti `TEST_REPORT.md` içindedir. Gerçek saha yakalamalarıyla geniş uyumluluk testi yapılmadı.

## Biçim kaynakları

Uygulama üçüncü taraf parser kodu içermeyen sınırlı bir gerçekleştirmedir. Biçim incelemesinde kullanılan birincil kaynaklar:

- [libpcap savefile belgesi](https://github.com/the-tcpdump-group/libpcap/blob/master/pcap-savefile.manfile.in)
- [tcpdump bağlantı tipi kayıtları](https://github.com/the-tcpdump-group/tcpdump-htdocs/blob/master/linktypes.html)
- [IPv4 — RFC 791](https://www.rfc-editor.org/rfc/rfc791.html)
- [IPv6 — RFC 8200](https://www.rfc-editor.org/rfc/rfc8200.html)
- [UDP — RFC 768](https://www.rfc-editor.org/rfc/rfc768.html)
- [TCP — RFC 9293](https://www.rfc-editor.org/rfc/rfc9293.html)

Bütün standardın uygulandığı iddia edilmez; destek ve sınırlar yukarıdaki tablolardır. İnceleme tarihi: 28 Eylül 2026.
