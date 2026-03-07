import os
import json
from core.utils import run_command, save_raw_output

def filter_alive(subdomains, workspace_dir):
    print("[*] Memfilter subdomain yang hidup...")
    if not subdomains:
        return []
    input_file = os.path.join(workspace_dir, 'temp_subdomains.txt')
    with open(input_file, 'w') as f:
        for s in subdomains:
            f.write(s + '\n')
    output_file = os.path.join(workspace_dir, 'alive_subdomains.json')
    cmd = f"httpx -l {input_file} -json -silent -o {output_file}"
    stdout, stderr, rc = run_command(cmd)
    save_raw_output(workspace_dir, 'recon', 'httpx_alive', stdout, 'json')
    alive = []
    if os.path.exists(output_file):
        with open(output_file, 'r') as f:
            for line in f:
                try:
                    data = json.loads(line)
                    url = data.get('url', '').replace('http://', '').replace('https://', '')
                    alive.append(url)
                except:
                    pass
    os.remove(input_file)
    print(f"[+] Ditemukan {len(alive)} subdomain hidup.")
    return alive