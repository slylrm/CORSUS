# WeppenTest Proje Analiz Raporu

Tarih: 2026-04-17
Ortam: Windows 11, Python 3.13.2 (.venv)
Calisma dizini: `<project-root>`

---

## 1) Analiz Metodolojisi

Bu rapor asagidaki kanit kaynaklari birlestirilerek hazirlandi:

1. Kod envanteri ve mimari inceleme
2. Test suite calistirma
3. Canli API endpoint dogrulama (lokal sunucu uzerinden)
4. Uygulama log incelemesi
5. Veritabani tutarlilik kontrolu

Calistirilan ana dogrulamalar:
- pytest backend/tests
- health, scans, reports, tools, verification, recon endpoint kontrolleri
- Tool self-test kontrolleri (nmap/sqlmap)
- Veritabani tablo sayim sorgulari

---

## 2) Mimari Ozeti

### Backend
- FastAPI girisi: backend/app/main.py
- Routerlar:
  - backend/app/api/scans.py
  - backend/app/api/reports.py
  - backend/app/api/tools.py
  - backend/app/api/verification.py
  - backend/app/api/recon.py
- Tarama motoru: backend/app/core/scanner.py
- Tool registry: backend/app/tools/registry.py
- Migration: backend/app/core/migration_runner.py

### Frontend
- Backend templates + static:
  - backend/app/templates/*.html
  - backend/app/static/app.js
  - backend/app/static/style.css
- Ayrica bagimsiz frontend/index.html mevcut

### Scriptler
- Kurulum: setup.ps1, setup.sh
- Baslatma: start.ps1
- Tool kurulum/path yardimcilari:
  - install_pentest_tools.ps1
  - install_pentest_tools_auto.ps1
  - fix_tool_paths.ps1
  - download_nuclei_gitleaks.ps1

---

## 3) Test Sonucu (Objektif Durum)

Komut:
- .venv/Scripts/python.exe -m pytest backend/tests -q

Sonuc:
- 86 testten 85 PASS
- 1 FAIL

Fail eden test:
- backend/tests/test_registry_and_zap.py::test_build_tool_options_tunes_dir_brute_for_deep_scan

Beklenen:
- concurrency = 28
- max_paths = 32

Mevcut kod sonucu:
- concurrency = 24
- max_paths = 24

Kaynak:
- backend/app/tools/registry.py icindeki build_tool_options("dir_brute", "deep")

Not:
- Bu fail, fonksiyonel bir crash degil; test beklentisi ile ayar degeri arasinda drift oldugunu gosteriyor.

---

## 4) Canli Calisma Durumu (Runtime Dogrulandi)

## 4.1 Sunucu Baslatma ve cekirdek endpointler

Dogrulandi:
- start.ps1 ile sunucu basliyor
- Migrationlar startup'ta calisiyor
- Route cevaplari:
  - GET /health -> 200
  - GET / -> 200
  - GET /scan -> 200
  - GET /recon -> 200
  - GET /docs -> 200

## 4.2 Scan API

Dogrulandi:
- POST /api/v1/scans/ calisiyor (auth/scope zorunlulugu var)
- authorization_acknowledged=false durumunda 422 donuyor (validator nedeniyle)
- Ayni hedefte ikinci aktif scan denemesinde 409 donuyor (active-target lock)
- Gercek scan akisi (demo disi hedefte) calisiyor:
  - hedef: https://httpbin.org
  - tools: basic + headers
  - status: completed
  - bulgu sayisi: 6

Onemli:
- example.com ve localhost hedeflerinde otomatik showcase/demo modu aciliyor.
- Bu durumda gercek tool calisma yerine demo finding uretiliyor.
- Demo davranisi: backend/app/core/showcase_mode.py

## 4.3 Recon API

Dogrulandi:
- POST /api/v1/recon/start calisiyor
- GET /api/v1/recon/status/{job_id} calisiyor
- GET /api/v1/recon/result/{job_id} calisiyor
- GET /api/v1/recon/export/{job_id} JSON indiriyor
- GET /api/v1/recon/export/pdf/{job_id} endpoint cevap veriyor

Kritik not:
- recon export/pdf endpointi bu ortamda PDF degil JSON dondu (Content-Type: application/json)
- Neden: reportlab import fallback'i tetikleniyor
- Kod reportlab bekliyor ama dependency setinde esasen weasyprint var
- Bu bir dependency/uygulama uyumsuzlugu

## 4.4 Reports API

Dogrulandi:
- GET /api/v1/reports/{scan_id}/summary -> 200
- GET /api/v1/reports/{scan_id}/detailed -> 200
- GET /api/v1/reports/{scan_id}/export?format=md -> 200

Eksik:
- GET /api/v1/reports/{scan_id}/export?format=pdf -> 501 (Not implemented)
- GET /api/v1/reports/{scan_id}/findings/{risk_level} -> TODO/placeholder response

## 4.5 Tools API

Dogrulandi:
- GET /api/v1/tools/ calisiyor
- POST /api/v1/tools/{tool}/test calisiyor

Bu makinede installed=true olanlar:
- amass
- nmap
- nuclei
- nikto
- gitleaks
- trivy

Bu makinede eksik olanlar (installed=false):
- owasp_zap
- wapiti
- sqlmap
- semgrep
- metasploit
- defectdojo
- faraday

## 4.6 Verification API

Dogrulandi:
- POST /api/v1/verification/request token uretiyor
- POST /api/v1/verification/verify DNS/HTML/meta kontrolu yapiyor

Eksik/kismi:
- Token kaliciligi TODO (DB'ye kayit yok)
- verify oncesi token expiry/varlik kontrolu TODO
- GET /api/v1/verification/status/{domain} placeholder donuyor

---

## 5) Kalicilik ve Veri Tutarliligi

Scan durumunun ana kaynagi su an bellek (in-memory):
- scanner_engine.active_scans
- scans_db gecici map (api/scans.py)

Gozlem:
- scans endpointinin listeleme versiyonu mock data donuyor (scan_1)
- cancel endpointi 204 donuyor ama gercek iptal/celery revoke yok
- retry endpointi 501

DB kontrolu (runtime sorgu):
- scans: 0
- findings: 3
- tool_executions: 0

Yorum:
- API tarafinda scan lifecycle DB odakli degil, in-memory odakli
- scans tablosunun migration ile olusmasina ragmen aktif yazma akisi tamamlanmamis

---

## 6) Kodda Acik Teknik Borc ve TODO Alanlari

Toplu TODO taramasinda one cikanlar:

- backend/app/api/scans.py
  - list endpoint DB'den cekmiyor, mock donuyor
  - cancel endpoint TODO
  - retry endpoint TODO + 501

- backend/app/api/reports.py
  - PDF export TODO + 501
  - findings_by_risk TODO

- backend/app/api/verification.py
  - token persistence TODO
  - token validation TODO
  - status endpoint TODO

- backend/app/tasks/scan_tasks.py
  - Celery tabanli akis parcali/legacy durumda
  - birden cok TODO (DB yazim, cross-validation, report, cleanup)

- backend/app/core/report_generator.py
  - PDF NotImplemented

---

## 7) Log Tabanli Operasyonel Bulgular

Son loglarda gorulen teknik davranislar:

- Nuclei tarafinda timeout/instability retry mekanizmasi devrede
- Bazi amass buildlerinde -json destegi yok, -oA fallback devreye giriyor
- Nmap bazen non-zero cikis verebiliyor ama parse/fallback akisi var
- WhatWeb timeout ve baglanti hatalari loglanmis

Bu bulgular, tool wrapperlarin belirli olgunlukta resiliency ekledigini ama dis araclara bagli degiskenligin halen oldugunu gosteriyor.

---

## 8) Ne Tam Olarak Calisiyor?

Calisanlar (dogrulandi):

1. Ortam kurulumu ve app startup
2. FastAPI ana routelar ve docs
3. Scan olusturma + status takip + active-target lock
4. Demo disi hedefte basic/header tabanli gercek scan
5. Recon start/status/result/export (JSON)
6. Report summary + detailed + markdown export
7. Tool envanter ve self-test endpointleri
8. Verification request/verify deneme akisi
9. Test altyapisi genel olarak saglam (85/86)

---

## 9) Neler Eksik / Tamamlanmamis?

1. Scan lifecycle persistence (DB kayit/list/retry/cancel)
2. Reports PDF export (reports API tarafinda)
3. Verification persistence + status kaliciligi
4. Scan listing endpointi gercek veri yerine mock donuyor
5. Recon PDF export icin dependency uyumu (reportlab vs weasyprint)
6. Test beklentisi ve runtime ayarlari arasinda drift (dir_brute deep)

---

## 10) Oncelikli Iyilestirme Plani

P0 (hemen):
1. backend/app/api/scans.py list/cancel/retry endpointlerini gercek hale getir
2. Scan sonuclarini DB'ye yazan net bir persistence katmani ekle
3. Test failini cozecek sekilde dir_brute deep optionlarinda kod-test hizalamasi yap

P1:
1. verification token lifecycle (olusturma, expiry, status) DB tabanli hale getir
2. reports PDF exportu tek yaklasima sabitle (weasyprint veya reportlab)
3. recon export/pdf fallback davranisini API seviyesinde acik ve tutarli yap

P2:
1. Legacy Celery task dosyalarini ya devreye al ya sadeleştir
2. frontend/index.html ile backend template akislari arasinda tek kaynak stratejisi belirle
3. .vscode interpreter secimi ile .venv kullanimini hizala

---

## 11) Son Degerlendirme

Proje cekirdegi calisiyor ve ciddi miktarda islev uretiyor.
Ozellikle scanner orchestration, recon pipeline ve tool registry tarafi islevsel.

Ancak sistem su an "uretimde tam lifecycle tamamlama" seviyesinde degil:
- persistence katmani parca parca
- bazi endpointler placeholder/TODO
- PDF/raporlama tarafinda parca uyumsuzluklar var
- test paketi genel olarak iyi olsa da bir konfig drift'i var

Kisa ozet:
- Teknik temel guclu
- Operasyonel tamamlama icin 1-2 sprintlik odakli kapatma calismasi gerekli
