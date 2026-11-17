# 🛡️ Web Pentest Platform (WeppenTest)

**AI-Free, Deterministic, Evidence-Based Web Application Security Testing Platform**

## 📋 Proje Özeti

WeppenTest, web sitesi sahiplerinin dışarıdan pahalı pentest hizmeti almadan kendi web sitelerini otomatik ve sürekli test edebilecekleri, **yapay zeka içermeyen**, deterministik ve kanıta dayalı bir Web Pentest Platformudur.

### 🎯 Hedef Kullanıcı
- Pentest bilgisi olmayan web sitesi yöneticileri
- Teknik seviyesi düşük KOBİ ve startup sahipleri
- Sürekli güvenlik testi isteyen DevOps ekipleri

### ✨ Temel İlkeler
- ❌ **Yapay Zeka KULLANILMAZ**
- ✅ Klasik pentest metodolojileri
- ✅ Doğrulanabilir ve tekrar üretilebilir çıktılar
- ✅ Minimum false positive
- ✅ Kanıt tabanlı raporlama

---

## 🏗️ Sistem Mimarisi

```
┌─────────────────────────────────────────────────────────────┐
│                     WEB UI (React/HTML)                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │  Dashboard   │  │  New Scan    │  │   Reports    │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────────────────────────────────────────┘
                            │
                    HTTPS REST API
                            │
┌─────────────────────────────────────────────────────────────┐
│                   FASTAPI BACKEND                            │
│                                                               │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              API Routes Layer                         │  │
│  │  /scan  /reports  /tools  /verify-domain             │  │
│  └──────────────────────────────────────────────────────┘  │
│                            │                                 │
│  ┌──────────────────────────────────────────────────────┐  │
│  │            Core Services Layer                        │  │
│  │  • ScanManager  • ToolOrchestrator                   │  │
│  │  • ResultValidator  • ReportGenerator                │  │
│  │  • DomainVerifier  • RateLimiter                     │  │
│  └──────────────────────────────────────────────────────┘  │
│                            │                                 │
│  ┌──────────────────────────────────────────────────────┐  │
│  │           Tool Wrapper Layer                          │  │
│  │  🔍 Discovery  💉 Injection  🔐 Auth  🧱 Config      │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                            │
                    Celery Task Queue
                            │
┌─────────────────────────────────────────────────────────────┐
│                  Background Workers                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │ Worker 1 │  │ Worker 2 │  │ Worker 3 │  │ Worker N │   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │
└─────────────────────────────────────────────────────────────┘
                            │
              ┌─────────────┴─────────────┐
              │                           │
┌─────────────▼─────────┐   ┌─────────────▼─────────┐
│   Redis (Broker)      │   │   SQLite/PostgreSQL   │
│   • Task Queue        │   │   • Scan Results      │
│   • Rate Limiting     │   │   • Reports           │
└───────────────────────┘   │   • Audit Logs        │
                            └───────────────────────┘
```

---

## 📁 Proje Yapısı

```
weppentest/
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py                 # FastAPI uygulaması
│   │   ├── config.py               # Konfigürasyon
│   │   │
│   │   ├── api/                    # API Endpoints
│   │   │   ├── __init__.py
│   │   │   ├── scans.py
│   │   │   ├── reports.py
│   │   │   ├── tools.py
│   │   │   └── verification.py
│   │   │
│   │   ├── core/                   # Core Services
│   │   │   ├── __init__.py
│   │   │   ├── scan_manager.py
│   │   │   ├── tool_orchestrator.py
│   │   │   ├── result_validator.py
│   │   │   ├── report_generator.py
│   │   │   ├── domain_verifier.py
│   │   │   └── rate_limiter.py
│   │   │
│   │   ├── tools/                  # Tool Wrappers
│   │   │   ├── __init__.py
│   │   │   ├── base.py             # Base wrapper class
│   │   │   │
│   │   │   ├── discovery/          # Keşif araçları
│   │   │   │   ├── nmap_wrapper.py
│   │   │   │   ├── httpx_wrapper.py
│   │   │   │   ├── dirsearch_wrapper.py
│   │   │   │   └── subfinder_wrapper.py
│   │   │   │
│   │   │   ├── injection/          # Injection testleri
│   │   │   │   ├── sqlmap_wrapper.py
│   │   │   │   ├── xsstrike_wrapper.py
│   │   │   │   ├── dalfox_wrapper.py
│   │   │   │   └── commix_wrapper.py
│   │   │   │
│   │   │   ├── auth/               # Kimlik doğrulama
│   │   │   │   ├── hydra_wrapper.py
│   │   │   │   └── custom_brute.py
│   │   │   │
│   │   │   ├── misconfiguration/   # Güvenlik yapılandırma
│   │   │   │   ├── nikto_wrapper.py
│   │   │   │   ├── header_checker.py
│   │   │   │   └── tls_checker.py
│   │   │   │
│   │   │   └── cms/                # CMS testleri
│   │   │       ├── whatweb_wrapper.py
│   │   │       └── wpscan_wrapper.py
│   │   │
│   │   ├── models/                 # Database Models
│   │   │   ├── __init__.py
│   │   │   ├── scan.py
│   │   │   ├── finding.py
│   │   │   ├── report.py
│   │   │   └── domain.py
│   │   │
│   │   ├── schemas/                # Pydantic Schemas
│   │   │   ├── __init__.py
│   │   │   ├── scan.py
│   │   │   ├── finding.py
│   │   │   └── report.py
│   │   │
│   │   ├── tasks/                  # Celery Tasks
│   │   │   ├── __init__.py
│   │   │   ├── scan_tasks.py
│   │   │   └── report_tasks.py
│   │   │
│   │   └── utils/                  # Utilities
│   │       ├── __init__.py
│   │       ├── logger.py
│   │       ├── validators.py
│   │       └── helpers.py
│   │
│   ├── tests/                      # Unit & Integration Tests
│   ├── requirements.txt
│   └── alembic/                    # Database migrations
│
├── frontend/
│   ├── public/
│   ├── src/
│   │   ├── components/
│   │   │   ├── Dashboard.jsx
│   │   │   ├── ScanForm.jsx
│   │   │   ├── ReportViewer.jsx
│   │   │   └── FindingCard.jsx
│   │   ├── services/
│   │   │   └── api.js
│   │   ├── App.jsx
│   │   └── main.jsx
│   ├── package.json
│   └── vite.config.js
│
├── docs/
│   ├── ARCHITECTURE.md             # Mimari detayları
│   ├── API_DOCUMENTATION.md        # API dokümantasyonu
│   ├── TOOL_INTEGRATION.md         # Tool ekleme rehberi
│   ├── SECURITY.md                 # Güvenlik politikaları
│   ├── LEGAL.md                    # Yasal uyarılar
│   └── ROADMAP.md                  # Geliştirme yol haritası
│
├── docker/
│   ├── Dockerfile.backend
│   ├── Dockerfile.frontend
│   └── docker-compose.yml
│
├── scripts/
│   ├── setup.sh                    # Kurulum scripti
│   ├── install_tools.sh            # Pentest araçlarını kur
│   └── run_dev.sh                  # Development ortamı
│
├── .env.example
├── .gitignore
└── README.md
```

---

## 🚀 Hızlı Başlangıç

### Gereksinimler
- Python 3.11+
- Nmap (opsiyonel, daha kapsamlı port scanning için)
- Redis (opsiyonel, arka plan işleri için)

### ⚡ Hızlı Kurulum ve Çalıştırma

#### 1. Python Paketlerini Yükleyin
```powershell
cd backend
pip install -r requirements.txt
```

**Yüklenen Pentest Kütüphaneleri:**
```
✅ python-nmap 0.7.1      - Network mapping
✅ requests 2.32.5         - HTTP client
✅ beautifulsoup4 4.14.3   - HTML parsing
✅ whois 1.20240129.2      - Domain info
✅ fastapi 0.128.0         - Web framework
✅ uvicorn 0.40.0          - ASGI server
```

#### 2. Backend API'yi Başlatın
```powershell
cd backend
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

✅ Backend hazır: http://127.0.0.1:8000
- **Ana Sayfa**: http://127.0.0.1:8000
- **Tarama**: http://127.0.0.1:8000/scan
- **Sağlık**: http://127.0.0.1:8000/health

#### 3. Tarama Başlatın
1. http://127.0.0.1:8000/scan adresine gidin
2. Target URL girin (örn: https://www.hackthissite.org/)
3. **"🚀 Taramayı Başlat"** butonuna tıklayın
4. Gerçek zamanlı tarama ilerlemesini izleyin

#### 4. Raporları İnceleyim
- Tarama tamamlandıktan sonra **"Detaylı Raporu Görüntüle"** butonuna tıklayın
- Risk seviyesine göre renk kodlu bulgular:
  - 🔴 **Kritik** - Derhal düzeltilmeli
  - 🟠 **Yüksek** - Kısa vadede düzeltilmeli
  - 🟡 **Orta** - Orta vadede düzeltilmeli
  - 🟢 **Düşük** - Uzun vadede gözlenebilir
  - 🔵 **Bilgi** - Referans bilgisi

---

## 📡 API Endpoints

```bash
# Tarama oluştur
POST /api/v1/scans/
Body: { "target_url": "https://example.com" }
Response: 201 Created { "scan_id": "...", "status": "pending" }

# Tarama durumunu kontrol et
GET /api/v1/scans/{scan_id}
Response: 200 OK { "status": "completed", "progress": 100, "findings": [...] }

# Detaylı rapor al
GET /api/v1/reports/{scan_id}/detailed
Response: 200 OK { "summary": {...}, "findings": [...], "executive_summary": "..." }

# HTML rapor sayfası
GET /report/{scan_id}
Response: 200 OK { HTML page with formatted report }
```

---

## 🔒 Güvenlik & Hukuk

### ⚠️ Yasal Uyarı
Bu platform **yalnızca yasal ve yetkili güvenlik testleri** için kullanılmalıdır.

- ✅ Sahip olduğunuz web sitelerini test edin
- ✅ Yazılı izin aldığınız sistemleri test edin
- ❌ Yetkisiz sistemlere karşı test etmeyin
- ❌ Başkasının izni olmadan kullanmayın

**Sorumluluğunuz!** Yetkisiz kullanım yasal sonuçlar doğurabilir.

Detaylar: [LEGAL.md](docs/LEGAL.md)

---

## 🛠️ Sorun Giderme

### Server başlamıyor
```powershell
# Python'un yüklü olduğunu kontrol et
python --version

# Virtual environment'i sıfırla
Remove-Item -Recurse -Force .\.venv
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r backend/requirements.txt
```

### "ModuleNotFoundError: No module named 'nmap'"
```powershell
# Kütüphaneleri yeniden yükle
pip install python-nmap requests beautifulsoup4 whois --force-reinstall
```

### Port 8000 kullanımda
```powershell
# Port 8000'i kullanan işlemi bul ve kapat
netstat -ano | findstr :8000
taskkill /PID <PID> /F
```

---

## 📈 Geliştirme Yol Haritası

### ✅ v1.0 (Tamamlandı)
- [x] 9 tarama aracı entegrasyonu
- [x] Turkish UI (Ana sayfa, Tarama, Rapor)
- [x] Gerçek zamanlı tarama ilerlemesi
- [x] Risk bazlı bulgu sıralaması
- [x] Responsive design

### 🚧 v1.1 (Yakında)
- [ ] PDF rapor export
- [ ] Email bildirimleri
- [ ] Zamanlanmış taramalar
- [ ] Scan history ve karşılaştırma
- [ ] Custom filter ve search

### 🔮 v2.0 (2026)
- [ ] Multi-user sistem
- [ ] API key & webhook yönetimi
- [ ] PostgreSQL desteği
- [ ] Advanced compliance raporları
- [ ] CI/CD integrasyonu

Detaylar: [ROADMAP.md](docs/ROADMAP.md)

---

## 📞 İletişim & Destek

- 🏠 **Yerel Geliştirme**: http://127.0.0.1:8000
- 📧 **Email**: support@weppentest.com
- 📚 **Dokümantasyon**: [docs/](docs/)
- 🐛 **Bug Report**: GitHub Issues
- 💬 **Forum**: Yakında eklenecek

---

## 📄 Lisans

MIT Lisansı - Detaylar için [LICENSE](LICENSE) dosyasına bakın

---

**Made with ❤️ for Web Security Community**

*Pentest yapın. Güvenli olun. Geliştirin.*

---

## 📊 Dahil Edilen Pentest Araçları

### 🎯 9 Entegre Tarama Motoru

| # | Araç | Tespit Alanı | CVSS Skorları |
|---|------|-------------|--------------|
| 1️⃣ | **Basic Info Scanner** | HTTP/HTTPS, Server bilgisi | 5.0 - 7.5 |
| 2️⃣ | **Security Headers** | Missing HSTS, CSP, X-Frame | 3.5 - 7.5 |
| 3️⃣ | **SSL/TLS Scanner** | Certificate, Cipher suites | 4.3 - 9.1 |
| 4️⃣ | **Ports Scanner** | Açık portlar, servisler | 3.5 - 9.8 |
| 5️⃣ | **NMAP** | Network mapping, servis versiyonları | 5.0 - 9.8 |
| 6️⃣ | **NIKTO** | Web sunucusu zaafiyetleri | 4.3 - 9.8 |
| 7️⃣ | **SQLMap** | SQL injection zaafiyetleri | 5.3 - 9.8 |
| 8️⃣ | **DIRB** | Directory brute-force | 3.5 - 9.1 |
| 9️⃣ | **WhatWeb** | Teknoloji & framework tespiti | 3.7 - 5.3 |

### 🔍 Keşif & Haritalama
```python
# Nmap - Port scanning & service detection
- Fast port enumeration (-F flag)
- Service/version detection (-sV flag)
- Open port classification
- Service-based risk assessment
```

### 💉 Injection Testleri
```python
# SQLMap - SQL Injection Detection
- Vulnerable parameter identification
- Test URL pattern analysis
- Prepared statements recommendation
- CWE-89 Mapping
```

### 🧱 Güvenlik Yapılandırma
```python
# NIKTO - Web Server Configuration
- Eski Apache/IIS versiyonları
- HTTP TRACE method kontrolü
- Server banner information
- Default file tespiti

# TLS/SSL - Certificate & Cipher Analysis
- Certificate validation
- Weak cipher suite detection
- TLS version analysis
```

### 📁 Directory & File Discovery
```python
# DIRB - Directory Brute-Force
- Admin panels: /admin, /administrator
- Config files: .env, .git, .htaccess, web.config
- Upload directories: /upload, /uploads
- API endpoints: /api, /v1, /v2
- Debug consoles: /console, /debug

Tespit edilen:
🔴 CRITICAL: Admin panels, .env, .git
🟠 HIGH: Database files, backup folders
🟡 MEDIUM: Upload directories
```

### 🔎 Technology & CMS Detection
```python
# WhatWeb - Web Technology Fingerprinting
- WordPress installation & plugins
- Drupal, Joomla, Magento CMS
- Framework tespiti: PHP, ASP.NET, Node.js
- Library versions: jQuery, Bootstrap
- Version disclosure information
```

### 📊 Tespit Edilen Bulgular Örneği
```
🔴 CRITICAL (CVSS 9.8)
   ├─ SQL Injection in parameter 'id'
   │  └─ Recommendation: Use prepared statements
   ├─ Open Admin Panel (/admin)
   │  └─ Recommendation: Implement authentication
   └─ Exposed .git Directory
      └─ Recommendation: Remove or restrict access

🟠 HIGH (CVSS 7.5)
   ├─ Eski Apache 2.0 sürümü
   ├─ Missing Security Headers (CSP, HSTS)
   └─ Weak TLS 1.0 Configuration

🟡 MEDIUM (CVSS 5.3)
   ├─ Open Database Port (3306)
   ├─ Directory Listing Enabled
   └─ Weak Cipher Suites

🟢 LOW (CVSS 3.7)
   ├─ Open SSH Port (22)
   └─ Server Banner Disclosed

🔵 INFO
   └─ WordPress 6.1 + vulnerable plugins detected
```

---

## 🚀 Hızlı Başlangıç

### Gereksinimler
- Python 3.11+
- Nmap (opsiyonel, daha kapsamlı port scanning için)
- Redis (opsiyonel, arka plan işleri için)

### ⚡ Hızlı Kurulum ve Çalıştırma

#### 1. Python Paketlerini Yükleyin
```powershell
cd backend
pip install -r requirements.txt
```

**Yüklenen Pentest Kütüphaneleri:**
```
✅ python-nmap 0.7.1      - Network mapping
✅ requests 2.32.5         - HTTP client
✅ beautifulsoup4 4.14.3   - HTML parsing
✅ whois 1.20240129.2      - Domain info
✅ fastapi 0.128.0         - Web framework
✅ uvicorn 0.40.0          - ASGI server
```

#### 2. Backend API'yi Başlatın
```powershell
cd backend
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

✅ Backend hazır: http://127.0.0.1:8000
- **Ana Sayfa**: http://127.0.0.1:8000
- **Tarama**: http://127.0.0.1:8000/scan
- **Sağlık**: http://127.0.0.1:8000/health

#### 3. Tarama Başlatın
1. http://127.0.0.1:8000/scan adresine gidin
2. Target URL girin (örn: https://www.hackthissite.org/)
3. **"🚀 Taramayı Başlat"** butonuna tıklayın
4. Gerçek zamanlı tarama ilerlemesini izleyin

#### 4. Raporları İnceleyim
- Tarama tamamlandıktan sonra **"Detaylı Raporu Görüntüle"** butonuna tıklayın
- Risk seviyesine göre renk kodlu bulgular:
  - 🔴 **Kritik** - Derhal düzeltilmeli
  - 🟠 **Yüksek** - Kısa vadede düzeltilmeli
  - 🟡 **Orta** - Orta vadede düzeltilmeli
  - 🟢 **Düşük** - Uzun vadede gözlenebilir
  - 🔵 **Bilgi** - Referans bilgisi

---

## 📡 API Endpoints

```bash
# Tarama oluştur
POST /api/v1/scans/
Body: { "target_url": "https://example.com" }
Response: 201 Created { "scan_id": "...", "status": "pending" }

# Tarama durumunu kontrol et
GET /api/v1/scans/{scan_id}
Response: 200 OK { "status": "completed", "progress": 100, "findings": [...] }

# Detaylı rapor al
GET /api/v1/reports/{scan_id}/detailed
Response: 200 OK { "summary": {...}, "findings": [...], "executive_summary": "..." }

# HTML rapor sayfası
GET /report/{scan_id}
Response: 200 OK { HTML page with formatted report }
```

---

## 🔒 Güvenlik & Hukuk

### ⚠️ Yasal Uyarı
Bu platform **yalnızca yasal ve yetkili güvenlik testleri** için kullanılmalıdır.

- ✅ Sahip olduğunuz web sitelerini test edin
- ✅ Yazılı izin aldığınız sistemleri test edin
- ❌ Yetkisiz sistemlere karşı test etmeyin
- ❌ Başkasının izni olmadan kullanmayın

**Sorumluluğunuz!** Yetkisiz kullanım yasal sonuçlar doğurabilir.

Detaylar: [LEGAL.md](docs/LEGAL.md)

---

## 🛠️ Sorun Giderme

### Server başlamıyor
```powershell
# Python'un yüklü olduğunu kontrol et
python --version

# Virtual environment'i sıfırla
Remove-Item -Recurse -Force .\.venv
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r backend/requirements.txt
```

### "ModuleNotFoundError: No module named 'nmap'"
```powershell
# Kütüphaneleri yeniden yükle
pip install python-nmap requests beautifulsoup4 whois --force-reinstall
```

### Port 8001 kullanımda
```powershell
# Port 8001'i kullanan işlemi bul ve kapat
netstat -ano | findstr :8001
taskkill /PID <PID> /F
```

---

## 📈 Geliştirme Yol Haritası

### ✅ v1.0 (Tamamlandı)
- [x] 9 tarama aracı entegrasyonu
- [x] Turkish UI (Ana sayfa, Tarama, Rapor)
- [x] Gerçek zamanlı tarama ilerlemesi
- [x] Risk bazlı bulgu sıralaması
- [x] Responsive design

### 🚧 v1.1 (Yakında)
- [ ] PDF rapor export
- [ ] Email bildirimleri
- [ ] Zamanlanmış taramalar
- [ ] Scan history ve karşılaştırma
- [ ] Custom filter ve search

### 🔮 v2.0 (2026)
- [ ] Multi-user sistem
- [ ] API key & webhook yönetimi
- [ ] PostgreSQL desteği
- [ ] Advanced compliance raporları
- [ ] CI/CD integrasyonu

Detaylar: [ROADMAP.md](docs/ROADMAP.md)

---

## 📞 İletişim & Destek

- 🏠 **Yerel Geliştirme**: http://127.0.0.1:8000
- 📧 **Email**: support@weppentest.com
- 📚 **Dokümantasyon**: [docs/](docs/)
- 🐛 **Bug Report**: GitHub Issues
- 💬 **Forum**: Yakında eklenecek

---

## 📄 Lisans

MIT Lisansı - Detaylar için [LICENSE](LICENSE) dosyasına bakın

---

**Made with ❤️ for Web Security Community**

*Pentest yapın. Güvenli olun. Geliştirin.*
