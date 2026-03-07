import os
import json
from core.utils import run_command, save_raw_output

def scan_ports(targets, workspace_dir, ports="top1000"):
    print("[*] Melakukan port scanning...")
    input_file = os.path.join(workspace_dir, 'temp_nmap_targets.txt')
    with open(input_file, 'w') as f:
        for t in targets:
            f.write(t + '\n')
    output_file = os.path.join(workspace_dir, 'nmap_results.json')
    cmd = f"sudo nmap -sS -T4 --top-ports 1000 -iL {input_file} -oJ {output_file}"
    stdout, stderr, rc = run_command(cmd)
    save_raw_output(workspace_dir, 'scan', 'nmap_raw', stdout + stderr, 'txt')
    results = {}
    if os.path.exists(output_file):
        with open(output_file, 'r') as f:
            try:
                data = json.load(f)
                for host in data:
                    ip = host.get('addresses', {}).get('ipv4')
                    hostname = host.get('hostnames', [{}])[0].get('name') if host.get('hostnames') else ip
                    ports_info = []
                    for port in host.get('ports', []):
                        if port.get('state', {}).get('state') == 'open':
                            ports_info.append({
                                'port': port.get('portid'),
                                'protocol': port.get('protocol'),
                                'service': port.get('service', {}).get('name')
                            })
                    results[hostname] = ports_info
            except:
                pass
    os.remove(input_file)
    print("[+] Port scanning selesai.")
    return results