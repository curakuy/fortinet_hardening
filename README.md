# 🛡️ FortiOS 7.4 & 7.6 Konfigürasyon Denetim, Sıkılaştırma ve Yükseltme Danışmanı

**Desteklenen Sürümler:** FortiOS **7.4 (7.4.13 GA)** ve **7.6 (7.6.8 GA)**  
**Çalışma Modları:** 🖥️ **Lokal Uygulama Modu** (`Node.js` + `BASLAT.bat`, Antivirüs dostu `.exe`'siz yapı) & ☁️ **Cloudflare Workers Web Modu**

---

## 🚀 Öne Çıkan Özellikler

1. **Çift Sürüm (FortiOS 7.4 & 7.6) Resmi Doküman Uyumluluk Motoru (`25+` Derinlik Duyarlı Kural):**
   - **FortiOS 7.4 (7.4.13):** Best Practices, Administration Guide, CLI Reference, Open Ports ve Troubleshooting Cheat Sheet kontrolleri.
   - **FortiOS 7.6 (7.6.8):**
     - **SSL-VPN Kalkışı:** 7.6.3–7.6.8 sürümlerinde SSL-VPN Tunnel Mode kaldırılması ve 2GB/G-serisi (`40F, 60F, 50G, 70G, 90G, 91G`) modellerde Agentless VPN dönüşümü; **IPsec IKEv2 TCP (`udp-fallback-tcp`)** veya **ZTNA Access Proxy** geçiş adımları.
     - **PBKDF2 Parola Özeti (`ENC PB2...` vs `ENC SH2...`):** 7.6 kriptografik admin parola özeti denetimi ve zorunlu `password-policy` (`reuse-password disable`).
     - **Yönlendirme & Port Güvenliği:** `allow-traffic-redirect disable` (7.6.5+ varsayılanı), WebFilter Override portlarının (`8008/8010/8015/8020`) kapatılması (`set close-ports enable`).
     - **Local-In Virtual Patching & ISDB:** `set virtual-patch enable` ve `Malicious-Malicious.Server`, `Tor-Exit.Node`, `Tor-Relay.Node` engelleme kuralları.
     - **Inline CASB & DLP (7.6):** SaaS kiracı kontrolü (`casb-profile`) ve veri sızıntısı önleme (`dlp-profile`) kontrolleri.
     - **Hardware Acceleration 7.6.8 (NP7 / NP7Lite / SP5 / CP10):** `auto-asic-offload`, IPsec `npu-offload` ve SD-WAN Application Performance Monitoring (`set app-monitor enable`) NPU offload devre dışı bırakma uyarısı.
2. **Olması Gereken Konfigürasyon (`Expected`) vs. Mevcut Durum (`Current`) Karşılaştırması:**
   - Her bulgu için cihazdaki mevcut durumu ve Fortinet dokümanlarına göre olması gereken konfigürasyonu yan yana gösterir.
   - Bulguları açıkça ikiye ayırır:
     - **➕ `EKSİK KONFİGÜRASYON — EKLEME ADIMLARI` (`MISSING`)**: Cihazda hiç tanımlanmamış güvenlik blokları için sıfırdan ekleme reçetesi.
     - **🔧 `HATALI / ZAYIF AYAR — DÜZELTME ADIMLARI` (`MISCONFIGURED`)**: Mevcut ancak zayıf/hatalı yapılandırılmış ayarlar için düzeltme reçetesi.
3. **Cihaz Modeline ve İşletim Sistemi Sürümüne Göre Yükseltme Danışmanı (Artıları & Eksileri):**
   - **Aynı Cihazda FortiOS Yükseltmesi:** Mevcut donanım üzerinde `FortiOS 7.4.13 GA (Mature)` ve `FortiOS 7.6.8 GA` sürümlerine geçiş yollarını (Upgrade Path), artılarını ve eksilerini karşılaştırır.
   - **Yeni Nesil FortiGate Model Önerisi:** Cihaz modeline göre (`60F -> 90G`, `100F -> 120G / 200G` vb.) ASIC, RAM, port ve SSL Deep Inspection kapasite artışlarını artıları ve eksileriyle raporlar.
4. **Canlı FortiGate Cihazına Bağlantı (SSH CLI & HTTPS REST API):**
   - Lokal modda `.conf` dosyası yüklemenin yanı sıra doğrudan FortiGate IP/Hostname adresine **HTTPS REST API Token** veya **SSH CLI** üzerinden bağlanarak çalışan konfigürasyonu çeker, aynı klasöre yedekler (`live-backup-*.conf`) ve otomatik analiz eder.
5. **PDF, HTML ve CLI Çıktıları (`.PDF`, `.HTML`, `.CLI.TXT`):**
   - Raporu tek tıkla **`.PDF`**, **`.HTML`** veya doğrudan FortiGate CLI'a yapıştırılabilir **`.CLI.TXT`** çözüm scripti olarak indirebilir; lokal modda çalışırken çıktılar otomatik olarak proje klasörüne kaydedilir.

---

## 🖥️ Lokal Uygulama Olarak Çalıştırma (`.exe` Gerektirmez)

Bilgisayarınızdaki antivirüs yazılımlarının `.exe` dosyalarını engellememesi için uygulama saf **Node.js ESM (`server-local.mjs`)** mimarisiyle çalışır:

1. Klasör içindeki **`BASLAT.bat`** dosyasına çift tıklayın (veya terminalde çalıştırın):
   ```powershell
   node server-local.mjs
   ```
2. Tarayıcınızda otomatik olarak **`http://localhost:8788`** açılacaktır.

---

## ☁️ Cloudflare Workers Üzerinde Yayınlama

Web sürümünü güncellemek için terminalde şu komutu çalıştırmanız yeterlidir:

```powershell
npx.cmd wrangler deploy
```

---

## 📂 Proje Dosya Yapısı

- `_worker.js` — FortiOS 7.4 & 7.6 derinlik duyarlı konfigürasyon ayrıştırıcısı, 25+ kural motoru, Yükseltme Danışmanı (`buildUpgradeAdvisor`), ağırlıklı uyumluluk skoru (`0-100`) ve Cloudflare Worker API'si.
- `server-local.mjs` — Lokal çalışma sunucusu (`http://localhost:8788`), Canlı FortiGate SSH/REST API istemcisi ve lokal `.PDF` / `.HTML` / `.CLI` rapor üretici.
- `BASLAT.bat` — Tek tıkla lokal uygulama başlatıcı.
- `PUBLIC_ASSETS/index.html` — Modern ve sade kullanıcı arayüzü (4 modüllü: Konfigürasyon Analizi & Rapor, Ekleme/Düzeltme Adımları, Yükseltme Danışmanı, CLI Cheat Sheet & Port Matrisi).
- `sample-fortigate-7.4.conf` / `sample-fortigate-7.6.conf` / `sample-fortigate-7.6-hardened.conf` — Test konfigürasyon dosyaları.
