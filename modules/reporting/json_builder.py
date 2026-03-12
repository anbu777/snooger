"""
Report builder: aggregates all findings into structured final_report.json
with CVSS scores, CWE mapping, deduplication, and delta comparison.
"""
import os
import json
import logging
from datetime import datetime
from typing import Optional
from core.utils import load_json_file, load_jsonl_file, write_json

logger = logging.getLogger('snooger')

def build_final_report(workspace_dir: str, target: str,
                        state_manager=None,
                        start_time: Optional[str] = None) -> dict:
    """Aggregate all scan results into final_report.json."""
    end_time = datetime.utcnow().isoformat()

    # Try to get start_time from state_manager metadata if not provided
    if not start_time and state_manager and hasattr(state_manager, 'get_metadata'):
        start_time = state_manager.get_metadata('scan_start_time', '')

    report = {
        'metadata': {
            'target': target,
            'start_time': start_time or 'unknown',
            'end_time': end_time,
            'tool': 'Snooger v3.0',
            'generated_at': end_time,
        },
        'summary': {},
        'vulnerabilities': [],
        'subdomains': {},
        'port_scan': {},
        'ssl_tls': {},
        'javascript_analysis': {},
        'parameter_discovery': {},
        'subdomain_takeovers': [],
        'exploit_chains': [],
        'idor_findings': [],
        'active_findings': {},
        'sqli_findings': {},
        'xss_findings': {},
        'graphql_findings': {},
        'smuggling_findings': {},
        'upload_findings': {},
        'content_discovery': {},
    }

    # Load recon summary
    recon = load_json_file(os.path.join(workspace_dir, 'recon_summary.json'))
    if recon:
        report['subdomains'] = {
            'total': len(recon.get('subdomains', [])),
            'alive': len(recon.get('alive_subdomains', [])),
            'technologies': recon.get('technologies', {}),
        }

    # Load port scan
    port_scan = load_json_file(os.path.join(workspace_dir, 'nmap_results.json'))
    if port_scan:
        report['port_scan'] = port_scan

    # Load SSL/TLS findings
    ssl_results = load_json_file(os.path.join(workspace_dir, 'testssl_results.json'))
    if ssl_results:
        report['ssl_tls'] = ssl_results

    # Load nuclei findings (primary)
    nuclei_vulns = []
    validated = load_json_file(os.path.join(workspace_dir, 'validated_findings.json'))
    if validated and isinstance(validated, list):
        nuclei_vulns.extend(validated)
    else:
        raw_nuclei = load_json_file(os.path.join(workspace_dir, 'nuclei_results.json'))
        if raw_nuclei is None:
            raw_nuclei = load_jsonl_file(os.path.join(workspace_dir, 'nuclei_results.json'))
        if raw_nuclei:
            nuclei_vulns.extend(raw_nuclei if isinstance(raw_nuclei, list) else [raw_nuclei])

    # Load active vuln findings
    active_findings = load_json_file(os.path.join(workspace_dir, 'active_vuln_findings.json'))
    if active_findings:
        report['active_findings'] = active_findings
        for category, items in active_findings.items():
            if isinstance(items, list):
                nuclei_vulns.extend(items)

    # Load IDOR findings
    idor = load_json_file(os.path.join(workspace_dir, 'idor_findings.json'))
    if idor and isinstance(idor, list):
        report['idor_findings'] = idor
        nuclei_vulns.extend(idor)

    # Load SQLi custom findings
    sqli = load_json_file(os.path.join(workspace_dir, 'sqli_findings.json'))
    if sqli and isinstance(sqli, dict):
        report['sqli_findings'] = sqli
        for category, items in sqli.items():
            if isinstance(items, list):
                nuclei_vulns.extend(items)

    # Load XSS custom findings
    xss = load_json_file(os.path.join(workspace_dir, 'xss_findings.json'))
    if xss and isinstance(xss, dict):
        report['xss_findings'] = xss
        for category, items in xss.items():
            if isinstance(items, list):
                nuclei_vulns.extend(items)

    # Load GraphQL findings
    graphql = load_json_file(os.path.join(workspace_dir, 'graphql_findings.json'))
    if graphql and isinstance(graphql, dict):
        report['graphql_findings'] = graphql
        for category, items in graphql.items():
            if isinstance(items, list):
                nuclei_vulns.extend([i for i in items if isinstance(i, dict) and 'type' in i])

    # Load HTTP smuggling findings
    smuggling = load_json_file(os.path.join(workspace_dir, 'smuggling_findings.json'))
    if smuggling and isinstance(smuggling, dict):
        report['smuggling_findings'] = smuggling
        for category, items in smuggling.items():
            if isinstance(items, list):
                nuclei_vulns.extend(items)

    # Load file upload findings
    upload = load_json_file(os.path.join(workspace_dir, 'upload_findings.json'))
    if upload and isinstance(upload, dict):
        report['upload_findings'] = upload
        for category, items in upload.items():
            if isinstance(items, list):
                nuclei_vulns.extend(items)

    # Load subdomain takeovers
    takeovers = load_json_file(os.path.join(workspace_dir, 'subdomain_takeover.json'))
    if takeovers and isinstance(takeovers, list):
        report['subdomain_takeovers'] = takeovers
        nuclei_vulns.extend(takeovers)

    # Load JS analysis
    js_analysis = load_json_file(os.path.join(workspace_dir, 'js_analysis.json'))
    if js_analysis:
        report['javascript_analysis'] = js_analysis
        for secret in js_analysis.get('secrets', []):
            nuclei_vulns.append({
                'type': 'secret_exposure',
                'subtype': secret.get('type', ''),
                'url': secret.get('file', ''),
                'severity': secret.get('severity', 'high'),
                'info': {'name': f"Secret Exposure: {secret.get('type', '')}",
                         'severity': secret.get('severity', 'high')},
                'evidence': secret.get('context', '')[:200]
            })

    # Load parameter discovery
    param_disc = load_json_file(os.path.join(workspace_dir, 'parameter_discovery.json'))
    if param_disc:
        report['parameter_discovery'] = param_disc
        for finding in param_disc.get('header_bypass_findings', []):
            nuclei_vulns.append(finding)

    # Load sensitive files
    sensitive = load_json_file(os.path.join(workspace_dir, 'sensitive_files.json'))
    if sensitive and isinstance(sensitive, list):
        for item in sensitive:
            if item.get('status_code') == 200:
                nuclei_vulns.append({
                    'type': 'information_disclosure',
                    'url': item.get('url', ''),
                    'severity': 'high',
                    'info': {'name': f"Sensitive File Exposed: {item.get('path', '')}",
                             'severity': 'high'},
                    'evidence': f"HTTP {item.get('status_code')} - {item.get('content_length')} bytes"
                })

    # Load content discovery
    content = load_json_file(os.path.join(workspace_dir, 'ffuf_output.json'))
    if content and isinstance(content, dict):
        report['content_discovery'] = {
            'paths_found': len(content.get('results', []))
        }

    # Deduplicate vulnerabilities
    nuclei_vulns = _deduplicate_findings(nuclei_vulns)

    # Enrich with CVSS and CWE
    from modules.post_exploitation.linux_pe import _estimate_cvss, _map_to_cwe
    for v in nuclei_vulns:
        if 'cvss_score' not in v:
            v['cvss_score'] = _estimate_cvss(v)
        if 'cwe_id' not in v:
            v['cwe_id'] = _map_to_cwe(v.get('type', v.get('info', {}).get('name', '')))

    report['vulnerabilities'] = nuclei_vulns

    # Exploit chains
    from modules.exploitation.chain_engine import detect_chains
    chains = detect_chains(nuclei_vulns)
    report['exploit_chains'] = chains

    # Build summary
    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for v in nuclei_vulns:
        sev = v.get('severity', v.get('info', {}).get('severity', 'info')).lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    summary_data = {
        'total_findings': len(nuclei_vulns),
        'by_severity': severity_counts,
        'subdomains_found': len(recon.get('subdomains', [])) if recon and isinstance(recon, dict) else 0,
        'alive_hosts': len(recon.get('alive_subdomains', [])) if recon and isinstance(recon, dict) else 0,
        'exploit_chains': len(chains) if isinstance(chains, list) else 0,
        'idor_findings': len(report.get('idor_findings', [])),
        'subdomain_takeovers': len(report.get('subdomain_takeovers', [])),
        'js_secrets': len(js_analysis.get('secrets', [])) if js_analysis and isinstance(js_analysis, dict) else 0,
    }
    report['summary'] = summary_data

    write_json(os.path.join(workspace_dir, 'final_report.json'), report)
    logger.info(f"Final report: {len(nuclei_vulns)} findings "
                f"({severity_counts.get('critical',0)} critical, "
                f"{severity_counts.get('high',0)} high)")
    return report

def _deduplicate_findings(vulns: list) -> list:
    """Deduplicate findings by type+URL combination."""
    seen = set()
    unique = []
    for v in vulns:
        if not isinstance(v, dict):
            continue
        url_raw = v.get('url', v.get('matched-at', v.get('host', '')))
        url = str(url_raw) if url_raw else ''
        ftype_raw = v.get('type', v.get('info', {}).get('name', ''))
        ftype = str(ftype_raw) if ftype_raw else ''
        key = (ftype.lower()[:50], url[:100])
        if key not in seen:
            seen.add(key)
            unique.append(v)
    return unique
