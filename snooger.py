#!/usr/bin/env python3
import os
import sys
import argparse
import yaml
import json
from datetime import datetime

sys.path.insert(0, os.path.dirname(__file__))

from core.logger import setup_logger
from core.dependency_checker import check_dependencies, print_dependency_report
from core.ai_engine import AIEngine
from core import interactive

from modules.reconnaissance.subdomain import run_subfinder
from modules.reconnaissance.filter_alive import filter_alive
from modules.reconnaissance.tech_detect import detect_technologies
from modules.reconnaissance.content_discovery import discover_content

from modules.scanning.port_scan import scan_ports

from modules.vulnerability.nuclei_runner import run_nuclei

from modules.exploitation.exploit_selector import select_vulnerabilities
from modules.exploitation.sqlmap_wrapper import run_sqlmap

from modules.reporting.json_builder import build_final_report
from modules.reporting.ai_summary import generate_summary

from modules.auth_handler import AuthManager
from modules.business_logic.idor import scan_idor

BANNER = r"""
 ░▒▓███████▓▒░▒▓███████▓▒░ ░▒▓██████▓▒░ ░▒▓██████▓▒░ ░▒▓██████▓▒░░▒▓████████▓▒░▒▓███████▓▒░  
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ 
 ░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒▒▓███▓▒░▒▓██████▓▒░ ░▒▓███████▓▒░  
       ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ 
       ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░ ░▒▓██████▓▒░ ░▒▓██████▓▒░░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░ 
                                                                                             
                                                                                             
"""

def main():
    print(BANNER)
    print("Snooger - All-in-One AI-Powered Pentesting Tool")
    print("Versi 1.0 (Riset/Skripsi)")
    print("-" * 60)

    parser = argparse.ArgumentParser(description='Snooger Pentesting Framework')
    parser.add_argument('domain', help='Target domain (contoh: example.com)')
    parser.add_argument('--scope', help='Scope tambahan (IP/CIDR, pisahkan koma)', default='')
    parser.add_argument('--config', default='config.yaml', help='File konfigurasi')
    parser.add_argument('--skip-recon', action='store_true', help='Lewati fase reconnaissance')
    parser.add_argument('--skip-scan', action='store_true', help='Lewati fase scanning')
    parser.add_argument('--skip-vuln', action='store_true', help='Lewati fase vulnerability analysis')
    parser.add_argument('--skip-exploit', action='store_true', help='Lewati fase exploitation')
    args = parser.parse_args()

    with open(args.config, 'r') as f:
        config = yaml.safe_load(f)

    workspace_base = config['workspace']
    target_dir = os.path.join(workspace_base, args.domain.replace('/', '_'))
    os.makedirs(target_dir, exist_ok=True)
    os.makedirs(os.path.join(target_dir, 'raw_logs'), exist_ok=True)

    logger = setup_logger(target_dir)
    logger.info(f"Memulai Snooger untuk target: {args.domain}")
    logger.info(f"Workspace: {target_dir}")

    missing = check_dependencies(args.config)
    print_dependency_report(missing)
    if missing:
        logger.warning("Beberapa tool tidak ditemukan. Beberapa modul mungkin tidak berfungsi.")
        if not interactive.confirm_action("Lanjutkan tetap menjalankan Snooger?"):
            sys.exit(1)

    ai = AIEngine(config)

    if config['ai']['mode'] == 'auto':
        mode_choice = interactive.get_user_choice(
            "Pilih mode AI:",
            ["Cerdas (Llama 3.2, rekomendasi RAM 8GB+)", "Hemat (Phi-3/TinyLlama)", "Non-AI (hanya rule-based)"],
            default=1
        )
        if mode_choice == "Cerdas (Llama 3.2, rekomendasi RAM 8GB+)":
            config['ai']['mode'] = 'smart'
        elif mode_choice == "Hemat (Phi-3/TinyLlama)":
            config['ai']['mode'] = 'light'
        else:
            config['ai']['mode'] = 'off'
        ai.mode = config['ai']['mode']

    logger.info(f"Mode AI: {config['ai']['mode']}")

    # ==================== AUTHENTICATION HANDLER ====================
    auth = AuthManager(target_dir)
    auth.set_base_url(f"https://{args.domain}")  # asumsi https

    cookies_file = os.path.join(target_dir, 'cookies.txt')
    if interactive.confirm_action("Apakah target memerlukan autentikasi?"):
        print("\n[Auth] Pilih metode autentikasi:")
        auth_choice = interactive.get_user_choice(
            "Metode:",
            ["Form-based login", "HTTP Basic Auth", "Token (Bearer/JWT)", "Cookies", "Load saved session"],
            default=1
        )
        if auth_choice == "Form-based login":
            login_url = input("Masukkan URL login (contoh: https://example.com/login): ").strip()
            username = input("Username: ").strip()
            password = input("Password: ").strip()
            username_field = input("Nama field username (default: username): ").strip() or "username"
            password_field = input("Nama field password (default: password): ").strip() or "password"
            csrf_field = input("Nama field CSRF token (jika ada, kosongkan jika tidak): ").strip() or None
            if auth.login_form(login_url, username, password, username_field, password_field, csrf_field=csrf_field):
                print("[Auth] Berhasil login")
            else:
                print("[Auth] Gagal login, lanjut tanpa autentikasi")
        elif auth_choice == "HTTP Basic Auth":
            username = input("Username: ").strip()
            password = input("Password: ").strip()
            auth.login_basic(username, password)
        elif auth_choice == "Token (Bearer/JWT)":
            token = input("Token: ").strip()
            header = input("Header name (default: Authorization): ").strip() or "Authorization"
            scheme = input("Scheme (default: Bearer): ").strip() or "Bearer"
            auth.set_token(token, header, scheme)
        elif auth_choice == "Cookies":
            print("Masukkan cookies dalam format name=value, pisahkan dengan koma (contoh: sessionid=abc, csrftoken=xyz):")
            cookie_str = input().strip()
            cookies = {}
            for item in cookie_str.split(','):
                if '=' in item:
                    k, v = item.split('=', 1)
                    cookies[k.strip()] = v.strip()
            auth.set_cookies(cookies)
        elif auth_choice == "Load saved session":
            if auth.load_session():
                print("[Auth] Session dimuat dari workspace")
            else:
                print("[Auth] Tidak ada session tersimpan")
    else:
        auth.load_session()  # Coba muat session jika ada

    # Ekspor cookies untuk tool eksternal jika login berhasil
    if auth.is_logged_in():
        auth.export_cookies_netscape(cookies_file)
        print(f"[Auth] Cookies disimpan ke {cookies_file}")
    else:
        cookies_file = None

    # ==================== FASE RECONNAISSANCE ====================
    if not args.skip_recon:
        print("\n[FASE 1] Reconnaissance dimulai...")
        subdomains = run_subfinder(args.domain, target_dir)
        alive = filter_alive(subdomains, target_dir)
        all_targets = [args.domain] + alive
        max_targets = 20
        tech_targets = all_targets[:max_targets]
        tech_results = detect_technologies(tech_targets, target_dir)
        content_results = discover_content(args.domain, target_dir, cookies_file=cookies_file)
        recon_summary = {
            'subdomains': subdomains,
            'alive_subdomains': alive,
            'technologies': tech_results,
            'content_discovery': content_results
        }
        with open(os.path.join(target_dir, 'recon_summary.json'), 'w') as f:
            json.dump(recon_summary, f, indent=2)
        print("[+] Fase Reconnaissance selesai.")
    else:
        print("\n[SKIP] Fase Reconnaissance dilewati.")
        recon_file = os.path.join(target_dir, 'recon_summary.json')
        if os.path.exists(recon_file):
            with open(recon_file, 'r') as f:
                recon_summary = json.load(f)
            alive = recon_summary.get('alive_subdomains', [])
        else:
            alive = []

    # ==================== BUSINESS LOGIC TESTING (IDOR) ====================
    if not args.skip_recon:  # Lakukan IDOR setelah recon jika ada autentikasi
        if auth.is_logged_in():
            # Kumpulkan URL dari content discovery
            all_urls = []
            if os.path.exists(os.path.join(target_dir, 'content_discovery.json')):
                with open(os.path.join(target_dir, 'content_discovery.json'), 'r') as f:
                    cd_data = json.load(f)
                    for item in cd_data:
                        all_urls.append(item['url'])
            all_urls.append(f"https://{args.domain}")  # tambahkan domain utama
            idor_findings = scan_idor(auth, all_urls, target_dir)
        else:
            print("[IDOR] Tidak ada autentikasi, lewati IDOR scan.")

    # ==================== FASE SCANNING ====================
    if not args.skip_scan:
        print("\n[FASE 2] Scanning dimulai...")
        scan_targets = [args.domain] + alive
        port_results = scan_ports(scan_targets, target_dir)
        with open(os.path.join(target_dir, 'port_scan.json'), 'w') as f:
            json.dump(port_results, f, indent=2)
        print("[+] Fase Scanning selesai.")
    else:
        print("\n[SKIP] Fase Scanning dilewati.")

    # ==================== FASE VULNERABILITY ANALYSIS ====================
    if not args.skip_vuln:
        print("\n[FASE 3] Vulnerability Analysis dimulai...")
        vuln_targets = [args.domain] + alive
        vuln_results = run_nuclei(vuln_targets, target_dir, cookies_file=cookies_file)
        print(f"[+] Ditemukan {len(vuln_results)} potensi kerentanan.")
        severities = {}
        for v in vuln_results:
            sev = v.get('info', {}).get('severity', 'unknown')
            severities[sev] = severities.get(sev, 0) + 1
        print("Severity breakdown:")
        for sev, count in severities.items():
            print(f"  {sev}: {count}")
        print("[+] Fase Vulnerability Analysis selesai.")
    else:
        print("\n[SKIP] Fase Vulnerability Analysis dilewati.")

    # ==================== FASE EXPLOITATION ====================
    if not args.skip_exploit:
        print("\n[FASE 4] Exploitation dimulai...")
        if interactive.confirm_action("Apakah Anda ingin mencoba eksploitasi kerentanan?"):
            selected = select_vulnerabilities(target_dir)
            if selected:
                for vuln in selected:
                    name = vuln.get('info', {}).get('name', '').lower()
                    if 'sql injection' in name or 'sqli' in name:
                        url = vuln.get('host', vuln.get('matched-at', ''))
                        if url:
                            print(f"[*] Menjalankan sqlmap untuk {url}")
                            if interactive.confirm_action("Setujui menjalankan sqlmap?"):
                                run_sqlmap(url, target_dir)
            else:
                print("[*] Tidak ada kerentanan dipilih.")
        else:
            print("[*] Eksploitasi dilewati.")
        print("[+] Fase Exploitation selesai.")

    # ==================== FASE REPORTING ====================
    print("\n[FASE 5] Reporting dimulai...")
    final_report = build_final_report(target_dir, args.domain)
    if ai.mode != 'off':
        summary = generate_summary(ai, final_report)
        print("\n[AI SUMMARY]")
        print(summary)
        with open(os.path.join(target_dir, 'ai_summary.txt'), 'w') as f:
            f.write(summary)
    else:
        print("[*] AI summary tidak dihasilkan (mode non-AI).")
    print("[+] Laporan selesai.")

    print("\n[SELESAI] Semua fase telah dijalankan.")
    logger.info("Snooger selesai.")

if __name__ == '__main__':
    main()