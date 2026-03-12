"""
Virtual Host Scanner — discover hidden virtual hosts via Host header fuzzing.
Uses built-in wordlist with fallback to SecLists.
"""
import os
import logging
import requests
from typing import List, Dict, Optional
from urllib.parse import urlparse
from core.utils import write_json, random_user_agent
from core.rate_limiter import get_rate_limiter

logger = logging.getLogger('snooger')

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def load_vhost_wordlist() -> List[str]:
    """Load virtual host names from built-in wordlist."""
    wordlist_path = os.path.join(BASE_DIR, 'data', 'wordlists', 'vhosts.txt')
    if os.path.exists(wordlist_path):
        with open(wordlist_path, 'r') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    return ['dev', 'staging', 'test', 'api', 'admin', 'internal', 'beta', 'portal']


def scan_vhosts(target_ip: str, domain: str, workspace_dir: str,
                config = None, custom_wordlist = None) -> dict:
    """
    Discover virtual hosts by fuzzing the Host header.
    Compares response to baseline to detect different vhosts.
    """
    results = {'target': target_ip, 'domain': domain, 'vhosts': [], 'findings': []}
    rl = get_rate_limiter()

    # Load wordlist
    if custom_wordlist and os.path.exists(custom_wordlist):
        with open(custom_wordlist, 'r') as f:
            names = [l.strip() for l in f if l.strip()]
    else:
        names = load_vhost_wordlist()

    # Get baseline response (with the real domain)
    session = requests.Session()
    session.headers['User-Agent'] = random_user_agent()

    target_url = f"http://{target_ip}" if not target_ip.startswith('http') else target_ip

    try:
        rl.wait(target_ip)
        baseline = session.get(target_url, headers={'Host': domain},
                               timeout=10, verify=False)
        baseline_length = len(baseline.content)
        baseline_status = baseline.status_code
        baseline_title = _extract_title(baseline.text)
    except Exception as e:
        logger.error(f"Cannot get baseline response: {e}")
        return results

    # Get response for a random non-existent host (to detect wildcard)
    try:
        rl.wait(target_ip)
        wildcard = session.get(target_url,
                               headers={'Host': f'zzzrandomxxx123.{domain}'},
                               timeout=10, verify=False)
        wildcard_length = len(wildcard.content)
        wildcard_status = wildcard.status_code
    except Exception:
        wildcard_length = 0
        wildcard_status = 0

    logger.info(f"Baseline: status={baseline_status}, length={baseline_length}")
    logger.info(f"Wildcard: status={wildcard_status}, length={wildcard_length}")

    # Fuzz each vhost name
    for name in names:
        vhost = f"{name}.{domain}"
        try:
            rl.wait(target_ip)
            resp = session.get(target_url, headers={'Host': vhost},
                               timeout=10, verify=False)
            resp_length = len(resp.content)
            resp_status = resp.status_code
            resp_title = _extract_title(resp.text)

            # Detect interesting vhosts:
            # Different from wildcard AND different from baseline
            is_different = (
                abs(resp_length - wildcard_length) > 50 and
                abs(resp_length - baseline_length) > 50 and
                resp_status not in (0, 503)
            )

            if is_different:
                result = {
                    'vhost': vhost,
                    'status_code': resp_status,
                    'content_length': resp_length,
                    'title': resp_title,
                }
                results['vhosts'].append(result)
                logger.warning(f"Vhost found: {vhost} (status={resp_status}, len={resp_length})")

                # Check for sensitive vhosts
                sensitive_names = ['admin', 'internal', 'dev', 'staging', 'debug',
                                   'test', 'api', 'private', 'management']
                if name in sensitive_names:
                    results['findings'].append({
                        'type': 'sensitive_vhost',
                        'vhost': vhost,
                        'severity': 'medium',
                        'evidence': f"Sensitive virtual host discovered: {vhost}",
                        'status_code': resp_status,
                    })

        except Exception as e:
            logger.debug(f"VHost scan error for {vhost}: {e}")

    write_json(os.path.join(workspace_dir, 'vhost_scan.json'), results)

    if results['vhosts']:
        logger.info(f"Discovered {len(results['vhosts'])} virtual hosts")

    return results


def _extract_title(html: str) -> str:
    """Extract page title from HTML."""
    import re
    match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
    return match.group(1).strip() if match else ''


def run_vhost_scan(target_ip: str, domain: str, workspace_dir: str,
                   config = None) -> dict:
    """Entry point for virtual host scanning."""
    return scan_vhosts(target_ip, domain, workspace_dir, config)
