# Sentetik örnekler

[English](README.md) · **Türkçe** · [Uygulama README'si](../README_TR.md)

Bu dizindeki bütün deliller ve kimlikler yapaydır. Paketlenmiş analiz/paylaşım raporları ile değerlendirme geçmişleri tarihsel **0.9.0** örnekleridir; **0.12.0** için yeniden üretilmemiştir. İçlerindeki sürüm alanları, mutlak kaynak yolları ve sınırlamalar güncel ayrıştırıcıyı değil, özgün çalıştırmayı anlatır. Güncel işlevler [uygulama README'sinde](../README_TR.md) ve [sürüm bilgilerinde](../RELEASE.json) açıklanır.

## İçerik

- `demo-source/`, `demo.k957` ve `demo-report/`: yapay metin logları, 0.2.0 ile tek geçişte toplanmış paket ve tarihsel analiz raporu.
- `legacy-v1.k957`: 0.1.0 ile toplanmış, v1 delil şeması uyumluluk örneği.
- `demo-resumable.k957` ve `demo-resumable-report/`: 0.2.0 ile toplanmış v2 delil şemalı paket ve iki edinim dönemini gösteren rapor. İkinci çalıştırma tamamlanmış parçaları kaynakları yeniden okumadan kullanır. Bu örnek zorla kesinti oluşturmaz; gerçek süreç sonlandırma ve kurtarma testi [resume_integration.py](../scripts/resume_integration.py) içindedir.
- `rules.json`: başarısız kimlik doğrulama metni ve PowerShell ifadesi için iki gösterim amaçlı düz metin kuralı. Hiçbir eşleşme tek başına zararlı yazılım hükmü değildir.
- `reviews-v1.json`, `reviews-v2.json`, `demo-review.pub` ve `demo-reviewed-report/`: iki imzalı değerlendirme sürümü, örnek açık anahtar ve değerlendirilmiş rapor. Değerlendirme geçmişleri özgün analiz dayanağına bağlıdır; bu 0.9.0 geçmişlerini yeni üretilmiş 0.12.0 analizine uygulamayın.
- `structured-source/`, `structured.k957`, `structured-report/`: yapay CSV/JSONL girdileri, 0.4.0 edinim paketi ve üç ortak varlık (kullanıcı/cihaz/IP) ile atlanan kayıtları gösteren 0.9.0 raporu. Ortak değerler kimlik veya nedensellik kanıtı değildir.
- `custody-001.json`, `custody-002.json`, `custody-003.json`, `custody-trust.json`, `custody-head.txt` ve `demo-custody-report/`: Alice delili kaydeder, Bob'a devir talep eder, Bob kabul eder. Güven listesi gösterim anahtarları içerir; geçmişin yanında tutulan son kayıt özeti, bağımsız güvenilir bir geçmiş kontrol noktası değildir.
- `demo-shared-report/`: değerlendirme/muhafaza örneğinin ayrı maskelenmiş kopyası. `structured-shared-report/`, yapılandırılabilir açıklama kategorileri arasından yalnızca kaynak zamanlarını açık bırakmak için `share-policy.json` kullanır.
- `network-source/`, `network.k957`, `network-report/` ve `network-shared-report/`: aşağıda açıklanan yapay 0.9.0 ağ edinimi ve raporları.

Örnek açık anahtarlar ve güven listeleri gerçek vakalarda kullanılmamalıdır. Özel imza anahtarları dahil değildir. Paylaşım raporu türev bir sunumdur; delil veya değerlendirmeye dayanak olacak özgün analiz değildir. Depoda maskelenmemiş raporlar ve yapay kaynaklar da vardır; gerçek çalışmalarda yalnızca incelenmiş paylaşım dizinini dağıtın.

## Ağ örneği ve PCAPNG uyumluluğu

`network-source/traffic.pcap`; Ethernet/VLAN, IPv4 UDP, IPv6 TCP ve kesilmiş paket içeriği örnekleri içerir. Dokuz kaydın beşi ayrıştırılır, dördü nedenleriyle atlanır ve dört yönlü akış üretilir. `big-nano.bin`, büyük uçlu (big-endian) byte sıralı, nanosaniye çözünürlüklü ham IPv4 kaydı ve bir akış daha ekler; PCAP olmayan uzantısı, dosya imza byte'larıyla tanımayı gösterir. `observer.jsonl`, farklı deliller arasında ilişki oluşturacak ortak IP değeri içerir.

`network-source/unsupported.pcapng` yalnızca **dört byte'lık PCAPNG imza başlangıcıdır**; tam bir ağ kaydı değildir. Tarihsel 0.9.0 raporu PCAPNG'nin desteklenmediğini söyler. 0.12.0, desteklenen geçerli PCAPNG yapılarını ayrıştırır; bilerek kesilmiş bu örnek ise yapısal hata üretmeye devam eder. Hatası, güncel PCAPNG desteğinin bulunmadığı anlamına gelmez. Ayrıntılar: [PCAPNG desteği](../docs/PCAPNG.md).

Varsayılan paylaşım raporu IP'leri, kaynak yollarını ve kaynak zamanlarını maskeler veya çıkarır; portları, sayaçları ve paket referanslarını korur.

## Güncel rapor oluşturma

Bu dizinden değil, **proje kökünden** çalıştırın. [Uygulama README'sinde](../README_TR.md) açıklandığı gibi `k957` yerine doğru çalıştırılabilir dosyanın yolunu yazın. Yeni çıktı dizinleri seçin; bu komutlar tarihsel raporların üzerine yazmadan mevcut paketi okur:

```sh
k957 verify --in examples/demo.k957
k957 analyze --in examples/demo.k957 --out fresh-demo-report --rules examples/rules.json
k957 analyze --in examples/network.k957 --out fresh-network-report
```

Güncel analizi değerlendirmek için o analiz ve aynı kurallar üzerinde yeni değerlendirme geçmişi oluşturun. Tarihsel imzalı değerlendirmeleri özgün raporlarıyla koruyun; aynı değerlendirme dayanağını yeniden kullanmak için özgün analiz sürümü gerekir. v1/v2 delil şemaları ise 0.12.0 tarafından okunmaya devam eder.

## Yeni örnekler üretme ve doğrulama

Bu betikler `dist/` içindeki çalışan platforma uygun dosyayı veya ayarlanmışsa `K957_TEST_BINARY` değerini kullanır. Geçici yapay vakalar oluşturup güncel CLI'yi doğrular:

```sh
python scripts/pcapng_integration.py
python scripts/windows_xml_integration.py
```

Gerektiğinde `python3` kullanın. Klasik PCAP entegrasyon kontrollerini çalıştırırken yeni üretilen kaynak dizinini ayrıca saklamak için yeni bir hedef seçin:

```sh
python scripts/pcap_integration.py --examples fresh-network-source
```

Son komut yapay kaynak dosyalarını saklar; paketlenmiş tarihsel raporları yeniden üretmez. Bu üç betik Python standart kütüphanesini kullanır; tam doğrulama paketi ayrıca [requirements-test.txt](../scripts/requirements-test.txt) bağımlılığını gerektirir. [Platform testlerine](../docs/PLATFORM_TESTING.md) ve [saklanan test sonuçlarına](../docs/TEST_REPORT.md) bakın.
