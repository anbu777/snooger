import os
import json
from core.utils import run_command, save_raw_output

def discover_content(domain, workspace_dir, wordlist=None):
    print("[*] Menjalankan content discovery...")
    if wordlist is None:
        wordlist = "/usr/share/wordlists/dirb/common.txt"
    if not os.path.exists(wordlist):
        print(f"[!] Wordlist {wordlist} tidak ditemukan. Gunakan wordlist bawaan.")
        wordlist = "/usr/share/wordlists/dirb/common.txt"
    output_file = os.path.join(workspace_dir, 'raw_logs/recon/ffuf.json')
    cmd = f"ffuf -u https://{domain}/FUZZ -w {wordlist} -ac -of json -o {output_file} -s"
    stdout, stderr, rc = run_command(cmd)
    save_raw_output(workspace_dir, 'recon', 'ffuf_raw', stdout + stderr, 'txt')
    found = []
    if os.path.exists(output_file):
        with open(output_file, 'r') as f:
            try:
                data = json.load(f)
                for r in data.get('results', []):
                    found.append({
                        'url': r.get('url'),
                        'status': r.get('status'),
                        'length': r.get('length')
                    })
            except:
                pass
    with open(os.path.join(workspace_dir, 'content_discovery.json'), 'w') as f:
        json.dump(found, f, indent=2)
    print(f"[+] Ditemukan {len(found)} endpoint/direktori.")
    return found