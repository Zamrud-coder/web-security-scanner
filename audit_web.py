import argparse
import os
import requests
import socket
import ssl
import json
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from datetime import datetime
from colorama import Fore, Style, init
import concurrent.futures

# Inisialisasi Colorama
init(autoreset=True)

# ==========================================
# 12. MESIN PENILAIAN RISIKO OTOMATIS
# ==========================================
def hitung_analisis_risiko(modul_data):
    skor_awal = 100
    temuan_risiko = []
    rekomendasi = []

    # Evaluasi HTTP Error
    if "http_error" in modul_data:
        skor_awal -= 20
        temuan_risiko.append(f"[HIGH] Gagal Terhubung ke HTTP/HTTPS Server: {modul_data['http_error']}")
        rekomendasi.append("Pastikan server web aktif, port terbuka, dan tidak memblokir koneksi scanner.")

    # Evaluasi 1: SSL/TLS
    ssl_info = modul_data.get("ssl_tls", {})
    if "error" in ssl_info:
        skor_awal -= 25
        temuan_risiko.append("[HIGH] Koneksi SSL/TLS Bermasalah atau Tidak Tersedia.")
        rekomendasi.append("Aktifkan sertifikat SSL/TLS (HTTPS) yang valid pada server.")
    else:
        sisa_hari = ssl_info.get("sisa_hari", 0)
        if sisa_hari < 30:
            skor_awal -= 10
            temuan_risiko.append(f"[MEDIUM] Masa Aktif SSL Segera Habis ({sisa_hari} hari lagi).")
            rekomendasi.append("Perbarui sertifikat SSL/TLS sebelum masa berlaku habis.")

    # Evaluasi 2: Security Headers
    expected_headers = ["X-Frame-Options", "Content-Security-Policy", "Strict-Transport-Security", "X-Content-Type-Options", "Referrer-Policy"]
    headers = modul_data.get("security_headers", {})
    
    missing_headers = [h for h in expected_headers if headers.get(h) != "PRESENT"]
    if missing_headers:
        skor_awal -= len(missing_headers) * 5
        temuan_risiko.append(f"[MEDIUM] Hilang {len(missing_headers)} Security Header: {', '.join(missing_headers)}")
        rekomendasi.append("Konfigurasikan Security Headers (CSP, HSTS, X-Frame-Options, dll.) pada web server.")

    # Evaluasi 3: Cookie Security
    cookie_info = modul_data.get("cookies")
    if cookie_info:
        if not cookie_info.get("httponly"):
            skor_awal -= 5
            temuan_risiko.append("[LOW] Flag Cookie HttpOnly Tidak Ditemukan (Rentan XSS/Cookie Theft).")
            rekomendasi.append("Tambahkan flag 'HttpOnly' pada header Set-Cookie.")
        if not cookie_info.get("secure"):
            skor_awal -= 5
            temuan_risiko.append("[LOW] Flag Cookie Secure Tidak Ditemukan (Cookie dikirim via plain HTTP).")
            rekomendasi.append("Tambahkan flag 'Secure' pada header Set-Cookie.")

    # Evaluasi 4: Server Banner
    banner = modul_data.get("server_banner", {})
    server_tech = banner.get("server", "")
    if server_tech and server_tech != "Sembunyi/Tidak Ada":
        skor_awal -= 5
        temuan_risiko.append(f"[LOW] Informasi Server Terekspos: {server_tech}")
        rekomendasi.append("Sembunyikan informasi banner server pada konfigurasi Nginx/Apache.")

    skor_akhir = max(0, skor_awal)

    if skor_akhir >= 90:
        grade, status = "A+", "SANGAT AMAN (LOW RISK)"
    elif skor_akhir >= 80:
        grade, status = "A", "AMAN (LOW RISK)"
    elif skor_akhir >= 70:
        grade, status = "B", "CUKUP (MEDIUM RISK)"
    elif skor_akhir >= 50:
        grade, status = "C", "WASPADA (MEDIUM RISK)"
    elif skor_akhir >= 30:
        grade, status = "D", "RENTAN (HIGH RISK)"
    else:
        grade, status = "F", "SANGAT RENTAN (CRITICAL RISK)"

    return {
        "skor": skor_akhir,
        "grade": grade,
        "status_risiko": status,
        "temuan": temuan_risiko,
        "rekomendasi": rekomendasi
    }

# ==========================================
# GENERATOR LAPORAN HTML INTERAKTIF
# ==========================================
def generate_html_report(hasil_json, output_name):
    target = hasil_json["target"]
    waktu = hasil_json["waktu_audit"]
    analisis = hasil_json["penilaian_risiko"]
    
    color_map = {
        "A+": "#2ecc71", "A": "#27ae60", "B": "#f1c40f", 
        "C": "#e67e22", "D": "#e74c3c", "F": "#c0392b"
    }
    badge_color = color_map.get(analisis['grade'], '#34495e')

    html_content = f"""<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <title>Laporan Audit Keamanan - {target}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f6f9; color: #333; margin: 0; padding: 20px; }}
        .container {{ max-width: 900px; margin: auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); }}
        h1 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
        .score-box {{ text-align: center; background: #f8f9fa; border-radius: 8px; padding: 20px; margin: 20px 0; border: 1px solid #e9ecef; }}
        .grade-badge {{ display: inline-block; font-size: 48px; font-weight: bold; color: white; background-color: {badge_color}; width: 90px; height: 90px; line-height: 90px; border-radius: 50%; margin: 10px 0; }}
        .section {{ margin-top: 25px; }}
        .section-title {{ font-size: 18px; font-weight: bold; color: #2c3e50; margin-bottom: 10px; border-left: 4px solid #3498db; padding-left: 10px; }}
        ul {{ background: #fdfdfd; padding: 15px 30px; border-radius: 5px; border: 1px solid #eee; }}
        li {{ margin-bottom: 8px; }}
        .footer {{ margin-top: 30px; text-align: center; font-size: 12px; color: #888; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Laporan Audit Keamanan Web</h1>
        <p><strong>Target:</strong> {target}<br><strong>Waktu Audit:</strong> {waktu}</p>
        
        <div class="score-box">
            <h2>Skor Keamanan</h2>
            <div class="grade-badge">{analisis['grade']}</div>
            <h3>{analisis['skor']} / 100 — {analisis['status_risiko']}</h3>
        </div>

        <div class="section">
            <div class="section-title">Temuan Risiko Keamanan</div>
            <ul>
                {"".join([f"<li>{t}</li>" for t in analisis['temuan']]) if analisis['temuan'] else "<li>Tidak ditemukan masalah keamanan kritis/menengah.</li>"}
            </ul>
        </div>

        <div class="section">
            <div class="section-title">Rekomendasi Perbaikan</div>
            <ul>
                {"".join([f"<li>{r}</li>" for r in analisis['rekomendasi']]) if analisis['rekomendasi'] else "<li>Konfigurasi keamanan web sudah optimal.</li>"}
            </ul>
        </div>

        <div class="footer">Dibuat otomatis oleh Python Web Security Scanner</div>
    </div>
</body>
</html>"""
    
    with open(f"{output_name}.html", "w", encoding="utf-8") as f:
        f.write(html_content)

# ==========================================
# MODUL-MODUL AUDIT PASIF
# ==========================================
def check_ssl(hostname):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=4) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                expiry_date = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                sisa_hari = (expiry_date - datetime.now()).days
                issuer_info = dict(x[0] for x in cert['issuer'])
                return {"issuer": issuer_info.get('organizationName', 'Tidak Diketahui'), "expiry": expiry_date.strftime('%Y-%m-%d'), "sisa_hari": sisa_hari}
    except Exception as e:
        return {"error": str(e)}

def check_dns(hostname):
    try:
        ip_utama = socket.gethostbyname(hostname)
        addr_info = socket.getaddrinfo(hostname, None)
        all_ips = list(set(item[4][0] for item in addr_info))
        return {"ip_utama": ip_utama, "semua_ip": all_ips}
    except Exception as e:
        return {"error": str(e)}

def check_ports(hostname):
    web_ports = {80: "HTTP", 443: "HTTPS", 8080: "HTTP-Proxy/Alt", 8443: "HTTPS-Alt"}
    port_status = {}
    try:
        target_ip = socket.gethostbyname(hostname)
        for port, service in web_ports.items():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.5)
            res = sock.connect_ex((target_ip, port))
            port_status[port] = {"service": service, "status": "OPEN" if res == 0 else "CLOSED"}
            sock.close()
        return port_status
    except Exception as e:
        return {"error": str(e)}

def check_http_base(url, headers_custom):
    try:
        r = requests.get(url, headers=headers_custom, allow_redirects=False, timeout=5)
        server_tech = r.headers.get('Server', 'Sembunyi/Tidak Ada')
        powered_by = r.headers.get('X-Powered-By', 'Sembunyi/Tidak Ada')
        
        security_headers = ["X-Frame-Options", "Content-Security-Policy", "Strict-Transport-Security", "X-Content-Type-Options", "Referrer-Policy"]
        headers_status = {h: ("PRESENT" if h in r.headers else "MISSING") for h in security_headers}
        
        set_cookie = r.headers.get("Set-Cookie", "")
        cookie_data = None
        if set_cookie:
            c_lower = set_cookie.lower()
            cookie_data = {
                "httponly": "httponly" in c_lower,
                "secure": "secure" in c_lower,
                "samesite": "samesite" in c_lower
            }

        return {
            "status_code": r.status_code,
            "server": server_tech,
            "powered_by": powered_by,
            "headers": headers_status,
            "cookies": cookie_data
        }
    except Exception as e:
        return {"error": str(e)}

def check_robots(url, headers_custom):
    try:
        r = requests.get(urljoin(url, "/robots.txt"), headers=headers_custom, timeout=4)
        if r.status_code == 200:
            disallowed = [line.split(":", 1)[1].strip() for line in r.text.splitlines() if line.strip().lower().startswith("disallow:") and line.split(":", 1)[1].strip()]
            return {"found": True, "disallowed": disallowed}
        return {"found": False}
    except Exception as e:
        return {"found": False, "error": str(e)}

def check_sitemap(url, headers_custom):
    try:
        r = requests.get(urljoin(url, "/sitemap.xml"), headers=headers_custom, timeout=4)
        return {"found": r.status_code == 200}
    except Exception as e:
        return {"found": False, "error": str(e)}

def check_security_txt(url, headers_custom):
    for path in ["/.well-known/security.txt", "/security.txt"]:
        try:
            r = requests.get(urljoin(url, path), headers=headers_custom, timeout=3)
            if r.status_code == 200 and ("contact:" in r.text.lower() or "expires:" in r.text.lower()):
                return {"found": True, "path": path}
        except Exception:
            pass
    return {"found": False}

def check_tech_stack(url, headers_custom):
    try:
        r = requests.get(url, headers=headers_custom, timeout=5)
        html_lower = r.text.lower()
        tech_detected = []
        signatures = {"jQuery": "jquery", "Bootstrap": "bootstrap", "React": "react", "WordPress": "wp-content", "Laravel": "laravel"}
        for tech, key in signatures.items():
            if key in html_lower:
                tech_detected.append(tech)
        return tech_detected
    except Exception as e:
        return []

def check_links_forms(url, headers_custom):
    try:
        r = requests.get(url, headers=headers_custom, timeout=5)
        soup = BeautifulSoup(r.text, "html.parser")
        return {
            "total_links": len(soup.find_all("a", href=True)),
            "forms_count": len(soup.find_all("form"))
        }
    except Exception as e:
        return {"total_links": 0, "forms_count": 0, "error": str(e)}

# ==========================================
# FUNGSI UTAMA AUDIT (SINGLE TARGET)
# ==========================================
def audit_target(url, output_prefix=None, max_workers=10):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    headers_custom = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"}
    parsed = urlparse(url)
    hostname = parsed.netloc.split(":")[0]

    if not output_prefix or output_prefix == "laporan_audit":
        clean_name = hostname.replace(".", "_")
        output_prefix = f"laporan_{clean_name}"

    laporan_txt = []

    def log(teks):
        laporan_txt.append(teks)
        teks_cli = teks
        teks_cli = teks_cli.replace("[OK]", f"{Fore.GREEN}[OK]{Style.RESET_ALL}")
        teks_cli = teks_cli.replace("[OPEN]", f"{Fore.GREEN}[OPEN]{Style.RESET_ALL}")
        teks_cli = teks_cli.replace("[CLOSED]", f"{Fore.RED}[CLOSED]{Style.RESET_ALL}")
        teks_cli = teks_cli.replace("[MISSING]", f"{Fore.RED}[MISSING]{Style.RESET_ALL}")
        teks_cli = teks_cli.replace("[HIGH]", f"{Fore.RED}[HIGH]{Style.RESET_ALL}")
        teks_cli = teks_cli.replace("[MEDIUM]", f"{Fore.YELLOW}[MEDIUM]{Style.RESET_ALL}")
        teks_cli = teks_cli.replace("[LOW]", f"{Fore.CYAN}[LOW]{Style.RESET_ALL}")
        teks_cli = teks_cli.replace("[!]", f"{Fore.YELLOW}[!]{Style.RESET_ALL}")
        teks_cli = teks_cli.replace("[+]", f"{Fore.GREEN}[+]{Style.RESET_ALL}")
        teks_cli = teks_cli.replace("[-]", f"{Fore.RED}[-]{Style.RESET_ALL}")
        print(teks_cli)

    log("=" * 60)
    log("     HASIL AUDIT KEAMANAN WEB (12-IN-1 CLI SCANNER)")
    log(f" Target        : {url}")
    log(f" Threads       : {max_workers}")
    log(f" Output File   : {output_prefix}.*")
    log(f" Waktu         : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log("=" * 60 + "\n")

    hasil_json = {
        "target": url,
        "waktu_audit": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "modul": {}
    }

    # PEMINDAIAN PARALEL
    log("[*] Memproses pemindaian paralel...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        f_ssl = executor.submit(check_ssl, hostname)
        f_dns = executor.submit(check_dns, hostname)
        f_ports = executor.submit(check_ports, hostname)
        f_http = executor.submit(check_http_base, url, headers_custom)
        f_robots = executor.submit(check_robots, url, headers_custom)
        f_sitemap = executor.submit(check_sitemap, url, headers_custom)
        f_security_txt = executor.submit(check_security_txt, url, headers_custom)
        f_tech = executor.submit(check_tech_stack, url, headers_custom)
        f_forms = executor.submit(check_links_forms, url, headers_custom)

        ssl_res = f_ssl.result()
        dns_res = f_dns.result()
        ports_res = f_ports.result()
        http_res = f_http.result()
        robots_res = f_robots.result()
        sitemap_res = f_sitemap.result()
        sec_txt_res = f_security_txt.result()
        tech_res = f_tech.result()
        forms_res = f_forms.result()

    # Menyusun Laporan + Penanganan Error HTTP
    hasil_json["modul"]["ssl_tls"] = ssl_res
    hasil_json["modul"]["dns_ip"] = dns_res
    hasil_json["modul"]["ports"] = ports_res
    
    expected_sec_headers = ["X-Frame-Options", "Content-Security-Policy", "Strict-Transport-Security", "X-Content-Type-Options", "Referrer-Policy"]

    if "error" in http_res:
        hasil_json["modul"]["http_error"] = http_res["error"]
        hasil_json["modul"]["server_banner"] = {}
        hasil_json["modul"]["security_headers"] = {h: "MISSING" for h in expected_sec_headers}
        hasil_json["modul"]["cookies"] = None
    else:
        hasil_json["modul"]["server_banner"] = {"server": http_res.get("server", "Sembunyi/Tidak Ada")}
        hasil_json["modul"]["security_headers"] = http_res.get("headers", {})
        hasil_json["modul"]["cookies"] = http_res.get("cookies")

    hasil_json["modul"]["robots_txt"] = robots_res
    hasil_json["modul"]["sitemap_xml"] = sitemap_res
    hasil_json["modul"]["security_txt"] = sec_txt_res
    hasil_json["modul"]["tech_stack"] = tech_res
    hasil_json["modul"]["links_and_forms"] = forms_res

    # MENAMPILKAN RINGKASAN
    log("\n--- 1. SSL/TLS ---")
    log(f" Issuer : {ssl_res.get('issuer', 'Tidak Ada / Error')}")
    
    log("\n--- 2. DNS & IP ---")
    log(f" IP Utama : {dns_res.get('ip_utama', 'Gagal')}")
    
    log("\n--- 3. Port Web Utama ---")
    if isinstance(ports_res, dict):
        for p, d in ports_res.items():
            log(f" [{d['status']}] Port {p} ({d['service']})")

    log("\n--- 4, 5, 6. Server, Headers & Cookies ---")
    if "error" not in http_res:
        log(f" [+] Server Tech : {http_res['server']}")
        for h, st in http_res['headers'].items():
            log(f" [{st}] {h}")
    else:
        log(f" [-] Gagal terhubung ke HTTP: {http_res['error']}")

    log("\n--- 7, 8, 9. Informasi File Publik ---")
    log(f" Robots.txt   : {'[OK] Ditemukan' if robots_res.get('found') else '[INFO] Tidak Ada'}")
    log(f" Sitemap.xml  : {'[OK] Ditemukan' if sitemap_res.get('found') else '[INFO] Tidak Ada'}")
    log(f" Security.txt : {'[OK] Ditemukan' if sec_txt_res.get('found') else '[INFO] Tidak Ada'}")

    log("\n--- 10 & 11. Tech Stack & Scraping ---")
    log(f" [+] Tech Stack Terdeteksi : {', '.join(tech_res) if tech_res else 'Tidak Ada'}")
    log(f" [+] Total Link: {forms_res.get('total_links', 0)} | Form Input: {forms_res.get('forms_count', 0)}")

    # 12. AUTO-RISK SCORING
    analisis = hitung_analisis_risiko(hasil_json["modul"])
    hasil_json["penilaian_risiko"] = analisis

    log("\n" + "=" * 60)
    log("             HASIL PENILAIAN RISIKO OTOMATIS")
    log("=" * 60)
    log(f" Skor Keamanan   : {analisis['skor']} / 100")
    log(f" Grade Keamanan  : {analisis['grade']}")
    log(f" Status Risiko   : {analisis['status_risiko']}\n")

    log(" [!] Ringkasan Temuan Risiko:")
    for t in (analisis["temuan"] or ["[+] Tidak ada temuan risiko tinggi."]):
        log(f"     {t}")

    log("\n [+] Rekomendasi Perbaikan:")
    for r in (analisis["rekomendasi"] or ["[+] Konfigurasi web sudah optimal."]):
        log(f"     {r}")

    log("=" * 60)

    # MEMBUAT LAPORAN
    with open(f"{output_prefix}.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(laporan_txt))

    with open(f"{output_prefix}.json", "w", encoding="utf-8") as f:
        json.dump(hasil_json, f, indent=4, ensure_ascii=False)

    generate_html_report(hasil_json, output_prefix)

    print(f"\n{Fore.GREEN}[V] Selesai memindai {url}!{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[V] File tersimpan: {output_prefix}.txt, {output_prefix}.json, {output_prefix}.html{Style.RESET_ALL}\n")

# ==========================================
# FUNGSI PEMINDAIAN MASSAL (BATCH SCAN)
# ==========================================
def batch_scan(file_path, max_workers=10):
    if not os.path.exists(file_path):
        print(f"{Fore.RED}[-] File '{file_path}' tidak ditemukan!{Style.RESET_ALL}")
        return

    with open(file_path, "r", encoding="utf-8") as f:
        targets = [line.strip() for line in f.readlines() if line.strip() and not line.startswith("#")]

    if not targets:
        print(f"{Fore.YELLOW}[!] File '{file_path}' kosong atau hanya berisi komentar.{Style.RESET_ALL}")
        return

    print(f"\n{Fore.GREEN}=== MEMULAI BATCH SCANNING ({len(targets)} TARGET) ==={Style.RESET_ALL}\n")
    
    for idx, target in enumerate(targets, 1):
        print(f"{Fore.YELLOW}[>>>] Processing Target {idx}/{len(targets)}: {target}{Style.RESET_ALL}")
        audit_target(url=target, max_workers=max_workers)

    print(f"{Fore.GREEN}=== BATCH SCANNING SELESAI ({len(targets)} Target Terproses) ==={Style.RESET_ALL}")

# ==========================================
# PARSER PARAMETER TERMINAL (ARGPARSE)
# ==========================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Python Web Security Scanner 12-in-1 (Passive Reconnaissance & Auto-Risk Scoring)",
        epilog="Contoh BATCH: python audit_web.py -f targets.txt -w 5"
    )
    
    parser.add_argument("-u", "--url", type=str, help="URL single target (Contoh: https://httpbin.org)")
    parser.add_argument("-f", "--file", type=str, help="File teks berisi daftar URL target (1 URL per baris)")
    parser.add_argument("-o", "--output", type=str, default=None, help="Nama dasar file laporan (Khusus single target)")
    parser.add_argument("-w", "--workers", type=int, default=10, help="Jumlah thread maksimum (Default: 10)")

    args = parser.parse_args()

    if args.file:
        batch_scan(file_path=args.file, max_workers=args.workers)
    elif args.url:
        audit_target(url=args.url, output_prefix=args.output, max_workers=args.workers)
    else:
        print(f"{Fore.YELLOW}[!] Tidak ada parameter URL (-u) atau File (-f). Mode interaktif dipanggil.{Style.RESET_ALL}")
        target_input = input("Masukkan URL Target (atau ketik 'python audit_web.py -h' untuk bantuan): ").strip()
        if target_input:
            audit_target(url=target_input, output_prefix=args.output, max_workers=args.workers)
        else:
            print("URL tidak boleh kosong.")