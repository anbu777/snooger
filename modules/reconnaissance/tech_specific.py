"""
Context-aware tech-specific scanning: WordPress, Drupal, Spring Boot, etc.
"""
import logging
from typing import List
from core.utils import run_command, save_raw_output, write_json
from core.rate_limiter import get_rate_limiter
import os, requests

logger = logging.getLogger('snooger')

def run_wpscan(target: str, workspace_dir: str, api_token: str = None) -> dict:
    """Run WPScan for WordPress-specific vulnerabilities."""
    logger.info(f"Running WPScan on {target}")
    output_file = os.path.join(workspace_dir, 'wpscan_results.json')
    cmd = f"wpscan --url {target} --output {output_file} --format json --no-update"
    if api_token:
        cmd += f" --api-token {api_token}"
    else:
        cmd += " --enumerate vp,vt,u,m --plugins-detection mixed"
    stdout, stderr, rc = run_command(cmd, timeout=600)
    save_raw_output(workspace_dir, 'vuln', 'wpscan', stdout + stderr, 'txt')
    if os.path.exists(output_file):
        from core.utils import load_json_file
        return load_json_file(output_file) or {}
    return {}

def check_spring_actuators(base_url: str, auth=None) -> List[dict]:
    """Check for exposed Spring Boot Actuator endpoints."""
    session = auth.session if auth else requests.Session()
    rl = get_rate_limiter()
    findings = []
    actuator_endpoints = [
        '/actuator', '/actuator/health', '/actuator/env',
        '/actuator/mappings', '/actuator/beans', '/actuator/heapdump',
        '/actuator/logfile', '/actuator/threaddump', '/actuator/dump',
        '/actuator/trace', '/actuator/info', '/actuator/metrics',
        '/manage/health', '/management/health',
    ]
    sensitive = ['env', 'heapdump', 'dump', 'logfile', 'threaddump', 'mappings', 'beans']
    for path in actuator_endpoints:
        url = f"{base_url.rstrip('/')}{path}"
        try:
            rl.wait(base_url)
            resp = session.get(url, timeout=8, verify=False)
            if resp.status_code in (200, 204):
                sev = 'high' if any(s in path for s in sensitive) else 'medium'
                findings.append({
                    'type': 'spring_actuator_exposed',
                    'url': url,
                    'severity': sev,
                    'evidence': f"Actuator endpoint {path} accessible (HTTP {resp.status_code})"
                })
                logger.warning(f"Spring actuator exposed: {url}")
        except Exception:
            pass
    return findings

def check_laravel_debug(base_url: str, auth=None) -> List[dict]:
    """Check for Laravel debug mode and .env exposure."""
    session = auth.session if auth else requests.Session()
    rl = get_rate_limiter()
    findings = []
    paths = ['/.env', '/.env.local', '/.env.production', '/.env.backup',
             '/vendor/autoload.php', '/storage/logs/laravel.log']
    for path in paths:
        url = f"{base_url.rstrip('/')}{path}"
        try:
            rl.wait(base_url)
            resp = session.get(url, timeout=8, verify=False)
            if resp.status_code == 200 and len(resp.content) > 50:
                sev = 'critical' if '.env' in path else 'medium'
                findings.append({
                    'type': 'laravel_file_exposed',
                    'url': url,
                    'severity': sev,
                    'evidence': f"File {path} accessible ({len(resp.content)} bytes)"
                })
        except Exception:
            pass
    # Trigger 500 for debug mode
    try:
        rl.wait(base_url)
        resp = session.get(f"{base_url.rstrip('/')}/this-does-not-exist-12345", timeout=8, verify=False)
        if 'laravel' in resp.text.lower() and 'whoops' in resp.text.lower():
            findings.append({
                'type': 'laravel_debug_mode',
                'url': base_url,
                'severity': 'high',
                'evidence': 'Laravel debug mode enabled (Whoops error page)'
            })
    except Exception:
        pass
    return findings

def run_tech_specific_scans(targets: List[str], tech_results: dict,
                              workspace_dir: str, auth=None) -> dict:
    """Run tech-specific scans based on detected technologies."""
    results = {}
    for url, tech_data in tech_results.items():
        techs = [t.lower() for t in tech_data.get('technologies', [])]
        url_findings = []
        if 'wordpress' in ' '.join(techs):
            wpscan = run_wpscan(url, workspace_dir)
            if wpscan:
                results['wordpress'] = wpscan
        if any(t in ' '.join(techs) for t in ['spring', 'java', 'tomcat']):
            spring_findings = check_spring_actuators(url, auth)
            url_findings.extend(spring_findings)
        if any(t in ' '.join(techs) for t in ['laravel', 'php']):
            laravel_findings = check_laravel_debug(url, auth)
            url_findings.extend(laravel_findings)
        if url_findings:
            results[url] = url_findings
    write_json(os.path.join(workspace_dir, 'tech_specific_findings.json'), results)
    return results
