"""
Technology detection module — identifies web servers, CMS, languages, and WAFs.
"""
import logging
import asyncio
from typing import List, Dict, Any
from core.utils import run_command

logger = logging.getLogger('snooger')

TECH_FINGERPRINTS = {
    'CMS': {
        'WordPress': ['wp-content', 'wp-includes', 'wp-json'],
        'Joomla': ['content="Joomla!', 'index.php?option='],
        'Drupal': ['Drupal.settings', 'sites/all'],
        'Ghost': ['ghost-portal'],
    },
    'Language/Platform': {
        'PHP': ['X-Powered-By: PHP', '.php', 'PHPSESSID'],
        'ASP.NET': ['X-Powered-By: ASP.NET', 'X-AspNet-Version', '.aspx', 'VIEWSTATE'],
        'Node.js': ['X-Powered-By: Express', 'io.js'],
        'Python/Django': ['X-Powered-By: Python', 'csrftoken'],
        'Java/Spring': ['X-Application-Context', 'JSESSIONID'],
    },
    'WAF': {
        'Cloudflare': ['__cfduid', 'cf-ray', 'Server: cloudflare'],
        'Akamai': ['Server: Akamai', 'X-Akamai-Transformed'],
        'Imperva': ['X-IWS-ID', 'visid_incap'],
        'Sucuri': ['X-Sucuri-ID', 'Sucuri'],
    },
    'Server': {
        'Nginx': ['Server: nginx'],
        'Apache': ['Server: Apache'],
        'IIS': ['Server: Microsoft-IIS'],
        'LiteSpeed': ['Server: LiteSpeed'],
    }
}

def run_tech_detection(targets: List[str], workspace_dir: str, config: dict) -> dict:
    """Identify technologies used by targets."""
    logger.info(f"Running technology detection on {len(targets)} targets...")
    results = {}

    for target in targets:
        try:
            logger.info(f"  Detecting technology for {target}...")
            # Use httpx if available, fallback to basic detection
            tech = _detect_via_httpx(target)
            if not tech:
                tech = _detect_basic(target)
            
            results[target] = tech
            if tech:
                logger.info(f"    [+] Tech found for {target}: {', '.join(tech)}")
        except Exception as e:
            logger.debug(f"Error detecting tech for {target}: {e}")

    return results

def _detect_via_httpx(target: str) -> List[str]:
    """Use httpx for technology fingerprints."""
    import shutil
    if not shutil.which('httpx'):
        return []

    url = target if target.startswith('http') else f"https://{target}"
    cmd = f"httpx -u {url} -td -json -silent"
    stdout, stderr, rc = run_command(cmd)
    
    found = []
    if stdout:
        try:
            import json
            data = json.loads(stdout)
            if 'tech' in data:
                found.extend(data['tech'])
        except:
            pass
    return found

def _detect_basic(target: str) -> List[str]:
    """Basic header and body analysis for technology detection."""
    import requests
    found = []
    url = target if target.startswith('http') else f"https://{target}"
    
    try:
        resp = requests.get(url, timeout=10, verify=False, allow_redirects=True)
        headers_str = str(resp.headers)
        body_str = resp.text

        for category, techs in TECH_FINGERPRINTS.items():
            for tech, markers in techs.items():
                for marker in markers:
                    if marker in headers_str or marker in body_str:
                        found.append(tech)
                        break
    except:
        pass
    
    return list(set(found))
