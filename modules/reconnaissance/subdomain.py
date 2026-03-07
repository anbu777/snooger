import os
import json
from core.utils import run_command, save_raw_output

def run_subfinder(domain, workspace_dir):
    print("[*] Menjalankan subfinder...")
    cmd = f"subfinder -d {domain} -oJ -silent"
    stdout, stderr, rc = run_command(cmd)
    save_raw_output(workspace_dir, 'recon', 'subfinder', stdout, 'json')
    if rc != 0:
        print(f"[!] subfinder error: {stderr}")
        return []
    # Parse JSON lines
    subdomains = []
    for line in stdout.splitlines():
        if line.strip():
            try:
                data = json.loads(line)
                if 'host' in data:
                    subdomains.append(data['host'])
            except:
                continue
    return subdomains