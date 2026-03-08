"""
Parameter discovery using arjun + header fuzzing + parameter pollution testing.
"""
import os
import json
import logging
from typing import List, Dict, Optional
from core.utils import run_command, save_raw_output, write_json
from core.rate_limiter import get_rate_limiter

logger = logging.getLogger('snooger')

INTERESTING_HEADERS = [
    'X-Forwarded-For', 'X-Real-IP', 'X-Originating-IP', 'X-Remote-IP',
    'X-Custom-IP-Authorization', 'X-Original-URL', 'X-Rewrite-URL',
    'X-Override-URL', 'X-Forwarded-Host', 'X-Host', 'X-HTTP-Host-Override',
    'X-ProxyUser-Ip', 'X-Forwarded-Port', 'X-Forwarded-Proto',
    'X-Forwarded-Scheme', 'Forwarded', 'Via', 'Content-Length',
    'Transfer-Encoding', 'X-Frame-Options', 'X-Content-Type-Options',
]

def run_arjun(url: str, workspace_dir: str,
              method: str = 'GET', cookies_file: Optional[str] = None) -> List[str]:
    """Discover hidden parameters using arjun."""
    logger.info(f"Running arjun parameter discovery on {url}")
    out_file = os.path.join(workspace_dir, 'arjun_output.json')
    cmd = f"arjun -u {url} --method {method} -oJ {out_file} --rate-limit 3 --timeout 10"
    if cookies_file and os.path.exists(cookies_file):
        cmd += f" --headers-file {cookies_file}"
    stdout, stderr, rc = run_command(cmd, timeout=300)
    save_raw_output(workspace_dir, 'recon', f'arjun_{method}', stdout + stderr, 'txt')
    if rc < 0:
        logger.warning("arjun not available")
        return []
    params = []
    if os.path.exists(out_file):
        try:
            with open(out_file, 'r') as f:
                data = json.load(f)
            if isinstance(data, dict):
                params = data.get('params', [])
            elif isinstance(data, list):
                params = data
        except Exception as e:
            logger.warning(f"arjun output parse error: {e}")
    if params:
        logger.info(f"arjun found {len(params)} hidden parameters")
    return params

def fuzz_headers(url: str, workspace_dir: str, auth=None) -> List[dict]:
    """Fuzz HTTP headers to find access control bypasses."""
    import requests
    logger.info(f"Testing header-based access control bypass on {url}")
    rl = get_rate_limiter()
    session = auth.session if auth else requests.Session()

    # Get baseline
    try:
        rl.wait(url)
        baseline = session.get(url, timeout=10, verify=False)
        baseline_status = baseline.status_code
        baseline_length = len(baseline.content)
    except Exception as e:
        logger.debug(f"Baseline request failed: {e}")
        return []

    findings = []
    test_values = ['127.0.0.1', '0.0.0.0', 'localhost', '::1']

    for header in INTERESTING_HEADERS:
        for value in test_values:
            try:
                rl.wait(url)
                resp = session.get(url, headers={header: value}, timeout=10, verify=False)
                # Look for status code change (especially from 403 to 200)
                if resp.status_code != baseline_status:
                    finding = {
                        'type': 'header_bypass',
                        'header': header,
                        'value': value,
                        'url': url,
                        'baseline_status': baseline_status,
                        'bypass_status': resp.status_code,
                        'severity': 'high' if resp.status_code == 200 and baseline_status in (403, 401) else 'medium'
                    }
                    findings.append(finding)
                    logger.warning(f"  Header bypass: {header}: {value} → HTTP {resp.status_code}")
            except Exception:
                pass

    return findings

def test_parameter_pollution(url: str, param: str, workspace_dir: str, auth=None) -> List[dict]:
    """Test HTTP Parameter Pollution by sending duplicate parameters."""
    import requests
    rl = get_rate_limiter()
    session = auth.session if auth else requests.Session()

    findings = []
    pollution_tests = [
        f"{url}&{param}=INJECTED",
        f"{url}&{param}=1&{param}=2",
        f"{url}%26{param}%3DINJECTED",
    ]

    try:
        rl.wait(url)
        baseline = session.get(url, timeout=10, verify=False)
        baseline_length = len(baseline.content)
    except Exception:
        return []

    for test_url in pollution_tests:
        try:
            rl.wait(url)
            resp = session.get(test_url, timeout=10, verify=False)
            if abs(len(resp.content) - baseline_length) > 50:
                findings.append({
                    'type': 'parameter_pollution',
                    'url': test_url,
                    'param': param,
                    'baseline_length': baseline_length,
                    'test_length': len(resp.content),
                    'severity': 'medium'
                })
        except Exception:
            pass

    return findings

def run_parameter_discovery(urls: List[str], workspace_dir: str,
                             auth=None) -> dict:
    """Run complete parameter discovery across all URLs."""
    all_params = {}
    header_findings = []
    arjun_params = {}

    # Run arjun on top URLs
    for url in urls[:10]:
        try:
            params = run_arjun(url, workspace_dir)
            if params:
                arjun_params[url] = params
        except Exception as e:
            logger.error(f"arjun failed for {url}: {e}")

    # Header fuzzing on URLs returning 403/401
    import requests
    session = auth.session if auth else requests.Session()
    for url in urls[:20]:
        try:
            resp = session.get(url, timeout=8, verify=False)
            if resp.status_code in (403, 401):
                findings = fuzz_headers(url, workspace_dir, auth)
                header_findings.extend(findings)
        except Exception:
            pass

    results = {
        'arjun_params': arjun_params,
        'header_bypass_findings': header_findings,
        'total_params_found': sum(len(p) for p in arjun_params.values()),
        'total_bypass_findings': len(header_findings)
    }

    write_json(os.path.join(workspace_dir, 'parameter_discovery.json'), results)
    logger.info(f"Parameter discovery: {results['total_params_found']} params, {len(header_findings)} header bypasses")
    return results
