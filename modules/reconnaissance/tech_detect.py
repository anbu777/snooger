import os
import json
from core.utils import run_command, save_raw_output

def detect_technologies(targets, workspace_dir):
    print("[*] Mendeteksi teknologi web...")
    input_file = os.path.join(workspace_dir, 'temp_tech_targets.txt')
    with open(input_file, 'w') as f:
        for t in targets:
            f.write(f"http://{t}\n")
            f.write(f"https://{t}\n")
    output_file = os.path.join(workspace_dir, 'raw_logs/recon/httpx_tech.json')
    cmd = f"httpx -l {input_file} -tech-detect -json -silent -o {output_file}"
    stdout, stderr, rc = run_command(cmd)
    save_raw_output(workspace_dir, 'recon', 'httpx_tech', stdout, 'json')
    results = {}
    if os.path.exists(output_file):
        with open(output_file, 'r') as f:
            for line in f:
                try:
                    data = json.loads(line)
                    url = data.get('url')
                    results[url] = {
                        'technologies': data.get('tech', []),
                        'status_code': data.get('status_code'),
                        'title': data.get('title'),
                        'webserver': data.get('webserver')
                    }
                except:
                    pass
    os.remove(input_file)
    print(f"[+] Teknologi terdeteksi untuk {len(results)} URL.")
    return results