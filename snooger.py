#!/usr/bin/env python3
import os
import sys
import argparse
import yaml
from datetime import datetime

# Tambahkan path core ke sys.path
sys.path.insert(0, os.path.dirname(__file__))

from core.logger import setup_logger
from core.dependency_checker import check_dependencies, print_dependency_report
from core.ai_engine import AIEngine
from core import interactive
from modules.reconnaissance.subdomain import run_subfinder

# ASCII Art
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
    args = parser.parse_args()

    # Load config
    with open(args.config, 'r') as f:
        config = yaml.safe_load(f)

    # Setup workspace
    workspace_base = config['workspace']
    target_dir = os.path.join(workspace_base, args.domain.replace('/', '_'))
    os.makedirs(target_dir, exist_ok=True)
    os.makedirs(os.path.join(target_dir, 'raw_logs'), exist_ok=True)

    # Setup logger
    logger = setup_logger(target_dir)
    logger.info(f"Memulai Snooger untuk target: {args.domain}")
    logger.info(f"Workspace: {target_dir}")

    # Dependency check
    missing = check_dependencies(args.config)
    print_dependency_report(missing)
    if missing:
        logger.warning("Beberapa tool tidak ditemukan. Beberapa modul mungkin tidak berfungsi.")
        if not interactive.confirm_action("Lanjutkan tetap menjalankan Snooger?"):
            sys.exit(1)

    # Inisialisasi AI
    ai = AIEngine(config)

    # Tanyakan mode AI jika belum di set
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
        # Update engine mode
        ai.mode = config['ai']['mode']

    logger.info(f"Mode AI: {config['ai']['mode']}")

    # Mulai fase Reconnaissance
    print("\n[FASE 1] Reconnaissance dimulai...")
    
    # Panggil modul subfinder
    print("[*] Menjalankan subfinder untuk enumerasi subdomain...")
    subdomains = run_subfinder(args.domain, target_dir)
    print(f"[+] Ditemukan {len(subdomains)} subdomain.")
    
    # Simpan hasil subdomain ke file JSON di workspace
    import json
    with open(os.path.join(target_dir, 'subdomains.json'), 'w') as f:
        json.dump(subdomains, f, indent=2)
    
    # TODO: Lanjutkan modul recon lainnya (tech_detect, content_discovery, dll)
    print("[*] Fase Reconnaissance selesai (sementara baru subfinder).")
    logger.info("Fase Reconnaissance selesai.")

    # Untuk sekarang, hentikan dulu (nanti akan lanjut ke fase berikutnya)
    print("\n[SELESAI] Proses Snooger berakhir setelah fase reconnaissance.")
    logger.info("Snooger selesai.")

if __name__ == '__main__':
    main()