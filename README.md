# 🛡️ Python Web Security Scanner 12-in-1
**Passive Reconnaissance & Automated Security Risk Assessment Tool**

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Type](https://img.shields.io/badge/type-Passive%20Scanner-orange.svg)

Alat pemindai keamanan web (*web security scanner*) berbasis Python yang dirancang untuk melakukan **Passive Reconnaissance** dan **Automated Risk Scoring**. Alat ini mengaudit 12 aspek keamanan infrastruktur web tanpa melakukan serangan invasif (*non-intrusive*), serta menghasilkan laporan audit interaktif dalam format **HTML**, **JSON**, dan **TXT**.

---

## ✨ Fitur Utama (12 Modul Audit)

1. **🔒 SSL/TLS Check**: Memeriksa validitas sertifikat, penerbit (*issuer*), dan sisa masa aktif.
2. **🌐 DNS & IP Lookup**: Identifikasi IP utama dan resolusi *multi-IP*.
3. **🔌 Light Port Scanner**: Memeriksa status port web utama (`80`, `443`, `8080`, `8443`).
4. **🖥️ Server Banner Leak**: Deteksi kebocoran informasi versi web server (Nginx, Apache, IIS).
5. **🛡️ Security Headers Audit**: Evaluasi 5 header keamanan utama (`CSP`, `HSTS`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`).
6. **🍪 Cookie Security Analysis**: Audit flag keamanan cookie (`HttpOnly`, `Secure`, `SameSite`).
7. **🤖 Robots.txt Parser**: Deteksi dan analisis direktori tersembunyi/sensitif yang dilarang (*disallow*).
8. **🗺️ Sitemap.xml Checker**: Pemetaan struktur halaman web publik.
9. **📜 Security.txt Checker**: Pengecekan standar publikasi kebijakan *Vulnerability Disclosure*.
10. **🧰 Tech Stack Identification**: Deteksi penggunaan framework & library (*WordPress*, *React*, *Bootstrap*, *jQuery*, *Laravel*).
11. **🔍 HTML Scraping**: Ekstraksi total tautan internal/eksternal dan jumlah form input.
12. **📊 Auto-Risk Scoring Engine**: Penilaian skor otomatis (0–100) beserta sistem pembagian kelas (*Grade A+ s.d. F*) dan panduan *defensive coding*.

---

## ⚡ Fitur Performa & Eksekusi

* **Multi-threading (`concurrent.futures`)**: Eksekusi pemindaian paralel yang cepat dan efisien.
* **Batch Scanning (`-f / --file`)**: Pemindaian massal puluhan target URL secara otomatis dari file teks.
* **CLI Flexible (`argparse`)**: Antarmuka baris perintah berbasis argument dengan indikator warna (*Colorama*).
* **Multi-Format Report**: Output otomatis tersimpan dalam 3 format sekaligus (`.html`, `.json`, `.txt`).

---

## 🚀 Instalasi

1. **Clone repository ini**:
   ```bash
   git clone [https://github.com/username-kamu/web-security-scanner.git](https://github.com/username-kamu/web-security-scanner.git)
   cd web-security-scanner