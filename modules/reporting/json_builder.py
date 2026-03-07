import os
import json
from datetime import datetime

def build_final_report(workspace_dir, target_domain):
    report = {
        "metadata": {
            "target": target_domain,
            "start_time": None,
            "end_time": datetime.now().isoformat(),
            "tool_version": "snooger-v1.0"
        },
        "recon": {},
        "vulnerabilities": [],
        "validated_findings": [],
        "idor_findings": [],
        "exploitation": [],
        "post_exploitation": {}
    }
    # Recon summary
    recon_file = os.path.join(workspace_dir, 'recon_summary.json')
    if os.path.exists(recon_file):
        with open(recon_file, 'r') as f:
            report['recon'] = json.load(f)
    # Nuclei vulnerabilities (file berupa array JSON)
    vuln_file = os.path.join(workspace_dir, 'nuclei_results.json')
    if os.path.exists(vuln_file):
        with open(vuln_file, 'r') as f:
            try:
                data = json.load(f)
                if isinstance(data, list):
                    report['vulnerabilities'] = data
                else:
                    report['vulnerabilities'] = [data]
            except json.JSONDecodeError:
                # Fallback jika format JSONL (satu baris satu JSON)
                vulns = []
                with open(vuln_file, 'r') as f2:
                    for line in f2:
                        try:
                            vulns.append(json.loads(line))
                        except:
                            pass
                report['vulnerabilities'] = vulns
    # Validated findings
    validated_file = os.path.join(workspace_dir, 'validated_findings.json')
    if os.path.exists(validated_file):
        with open(validated_file, 'r') as f:
            report['validated_findings'] = json.load(f)
    # IDOR findings
    idor_file = os.path.join(workspace_dir, 'idor_findings.json')
    if os.path.exists(idor_file):
        with open(idor_file, 'r') as f:
            report['idor_findings'] = json.load(f)
    # Port scan results
    port_file = os.path.join(workspace_dir, 'port_scan.json')
    if os.path.exists(port_file):
        with open(port_file, 'r') as f:
            report['port_scan'] = json.load(f)
    # Write final report
    final_file = os.path.join(workspace_dir, 'final_report.json')
    with open(final_file, 'w') as f:
        json.dump(report, f, indent=2)
    print(f"[+] Laporan akhir disimpan di {final_file}")
    return report