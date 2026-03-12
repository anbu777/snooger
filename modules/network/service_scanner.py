"""
Service Scanner — service fingerprinting and CVE matching for discovered ports.
Wraps nmap with enhanced service version detection and known CVE lookups.
"""
import os
import re
import logging
import json
from typing import List, Dict, Optional
from core.utils import run_command, write_json
from core.config_loader import get_tool_path

logger = logging.getLogger('snooger')

# Known vulnerable service versions (commonly exploitable)
KNOWN_VULNS = {
    'openssh': {
        '7.2': ['CVE-2016-6210', 'CVE-2016-10009'],
        '7.6': ['CVE-2018-15473'],
        '7.7': ['CVE-2018-15473'],
        '8.0': ['CVE-2019-6111'],
    },
    'apache': {
        '2.4.49': ['CVE-2021-41773', 'CVE-2021-42013'],
        '2.4.50': ['CVE-2021-42013'],
    },
    'nginx': {
        '1.17': ['CVE-2019-20372'],
    },
    'vsftpd': {
        '2.3.4': ['CVE-2011-2523'],
    },
    'proftpd': {
        '1.3.5': ['CVE-2015-3306'],
    },
    'exim': {
        '4.87': ['CVE-2019-10149'],
        '4.89': ['CVE-2019-10149'],
        '4.90': ['CVE-2019-10149'],
        '4.91': ['CVE-2019-10149'],
    },
    'mysql': {
        '5.5': ['CVE-2012-2122'],
    },
    'redis': {
        '4.': ['CVE-2022-0543'],
        '5.': ['CVE-2022-0543'],
    },
    'tomcat': {
        '8.5.19': ['CVE-2017-12617'],
        '9.0.1': ['CVE-2019-0232'],
    },
    'elasticsearch': {
        '1.': ['CVE-2015-1427'],
        '6.': ['CVE-2018-17246'],
    },
    'jenkins': {
        '2.': ['CVE-2019-1003000', 'CVE-2018-1000861'],
    },
}


def match_known_cves(service: str, version: str) -> List[dict]:
    """Match service version against known CVE database."""
    findings = []
    service_lower = service.lower()

    for svc_name, versions in KNOWN_VULNS.items():
        if svc_name in service_lower:
            for ver_prefix, cves in versions.items():
                if version.startswith(ver_prefix):
                    for cve in cves:
                        findings.append({
                            'type': 'known_cve',
                            'service': service,
                            'version': version,
                            'cve': cve,
                            'severity': 'high',
                            'evidence': f"{service} {version} is vulnerable to {cve}",
                            'reference': f"https://nvd.nist.gov/vuln/detail/{cve}",
                        })
    return findings


def parse_nmap_service_output(output: str) -> List[dict]:
    """Parse nmap -sV output into structured service data."""
    services = []
    for line in output.split('\n'):
        # Match: PORT/PROTO STATE SERVICE VERSION
        match = re.match(
            r'(\d+)/(tcp|udp)\s+(open|filtered)\s+(\S+)\s*(.*)', line.strip()
        )
        if match:
            port, proto, state, service, version_info = match.groups()
            services.append({
                'port': int(port),
                'protocol': proto,
                'state': state,
                'service': service,
                'version': version_info.strip(),
            })
    return services


def scan_services(targets: List[str], workspace_dir: str,
                  config = None) -> dict:
    """Run service version detection and CVE matching."""
    config = config or {}
    nmap_path = get_tool_path(config, 'nmap')
    results = {'services': [], 'findings': [], 'raw_output': ''}

    target_str = ' '.join(targets[:20])  # Limit targets

    # Service version scan
    logger.info(f"Running service version detection on {len(targets)} targets...")
    cmd = f"{nmap_path} -sV -sC --version-intensity 5 -T4 {target_str}"
    stdout, stderr, code = run_command(cmd, timeout=600)

    if code != 0:
        logger.warning(f"Nmap service scan returned code {code}")
        if stderr:
            logger.debug(f"Nmap stderr: {stderr[:200]}")

    results['raw_output'] = stdout

    # Parse services
    services = parse_nmap_service_output(stdout)
    results['services'] = services
    logger.info(f"Discovered {len(services)} services")

    # CVE matching
    for svc in services:
        if svc.get('version'):
            cves = match_known_cves(svc['service'], svc['version'])
            if cves:
                results['findings'].extend(cves)
                for cve_finding in cves:
                    logger.warning(
                        f"Known CVE: {svc['service']} {svc['version']} "
                        f"on port {svc['port']} — {cve_finding['cve']}"
                    )

    # Check for interesting services
    interesting = {'redis': 6379, 'mongodb': 27017, 'elasticsearch': 9200,
                   'docker': 2375, 'kubernetes': 10250, 'jenkins': 8080}
    for svc in services:
        svc_lower = svc['service'].lower()
        for name in interesting:
            if name in svc_lower:
                results['findings'].append({
                    'type': 'interesting_service',
                    'service': svc['service'],
                    'port': svc['port'],
                    'version': svc.get('version', ''),
                    'severity': 'medium',
                    'evidence': f"Potentially sensitive service: {svc['service']} on port {svc['port']}",
                })

    # Banner grabbing for services without version
    for svc in services:
        if not svc.get('version') and svc['state'] == 'open':
            banner = grab_banner(targets[0] if targets else '', svc['port'])
            if banner:
                svc['banner'] = banner

    write_json(os.path.join(workspace_dir, 'service_scan.json'), results)
    return results


def grab_banner(host: str, port: int, timeout: int = 5) -> str:
    """Grab banner from a service port."""
    import socket
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
        banner = sock.recv(1024).decode('utf-8', errors='replace')
        sock.close()
        return banner.strip()
    except Exception:
        return ''


def run_service_scan(targets: List[str], workspace_dir: str,
                     config = None) -> dict:
    """Entry point for service scanning."""
    return scan_services(targets, workspace_dir, config)
