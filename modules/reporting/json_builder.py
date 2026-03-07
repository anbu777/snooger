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
        "exploitation": [],
        "post_exploitation": {}
    }
    recon_file = os.path.join(workspace_dir, 'recon_summary.json')
    if os.path.exists(recon_file):
        with open(recon_file, 'r') as f:
            report['recon'] = json.load(f)
    vuln_file = os.path.join(workspace_dir, 'nuclei_results.json')
    if os.path.exists(vuln_file):
        vulns = []
        with open(vuln_file, 'r') as f:
            for line in f:
                try:
                    vulns.append(json.loads(line))
                except:
                    pass
        report['vulnerabilities'] = vulns
    final_file = os.path.join(workspace_dir, 'final_report.json')
    with open(final_file, 'w') as f:
        json.dump(report, f, indent=2)
    print(f"[+] Laporan akhir disimpan di {final_file}")
    return report