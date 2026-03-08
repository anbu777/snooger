"""
JavaScript Analysis Module — poin 8 dari perbaikan.
- Crawl dan ekstrak semua JS files
- Endpoint extraction dari JS
- Secret/API key detection
- Source map (.map) analysis
- Vulnerable JS library detection
"""
import os
import re
import json
import logging
import requests
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.utils import random_user_agent, save_raw_output

logger = logging.getLogger('snooger')

# Regex patterns for finding endpoints in JS
ENDPOINT_PATTERNS = [
    re.compile(r'''['"](\/[a-zA-Z0-9_\-\/\.]+(?:\?[a-zA-Z0-9_\-=&]+)?)['"''', re.M),
    re.compile(r'''fetch\s*\(\s*['"](\/[^'"]+)['"''', re.M),
    re.compile(r'''axios\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*['"](\/[^'"]+)['"''', re.M),
    re.compile(r'''\$http\s*\.\s*(?:get|post|put|delete)\s*\(\s*['"](\/[^'"]+)['"''', re.M),
    re.compile(r'''(?:url|endpoint|path|route)\s*(?:=|:)\s*['"](\/[^'"]{3,100})['"''', re.MI),
    re.compile(r'''https?:\/\/[a-zA-Z0-9\-\.]+\/[a-zA-Z0-9_\-\/\.]+''', re.M),
]

# Secret/API key patterns
SECRET_PATTERNS = {
    'AWS Access Key': re.compile(r'AKIA[0-9A-Z]{16}'),
    'AWS Secret Key': re.compile(r'(?:aws_secret|aws_key|secret_key)\s*[=:]\s*["\']([a-zA-Z0-9/+]{40})["\']', re.I),
    'Google API Key': re.compile(r'AIza[0-9A-Za-z_\-]{35}'),
    'Google OAuth': re.compile(r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com'),
    'GitHub Token': re.compile(r'ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82}'),
    'Slack Token': re.compile(r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{23,32}'),
    'Stripe Secret Key': re.compile(r'sk_live_[0-9a-zA-Z]{24}'),
    'Stripe Publishable Key': re.compile(r'pk_live_[0-9a-zA-Z]{24}'),
    'JWT Token': re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]+'),
    'Generic API Key': re.compile(r'''(?:api[_-]?key|apikey|api[_-]?secret|access[_-]?token|auth[_-]?token)\s*[=:]\s*["\']([a-zA-Z0-9_\-\.]{16,64})["\']''', re.I),
    'Password in Code': re.compile(r'''(?:password|passwd|pwd)\s*[=:]\s*["\']([^"']{6,50})["\']''', re.I),
    'Private Key': re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'),
    'SendGrid Key': re.compile(r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}'),
    'Twilio SID': re.compile(r'AC[a-f0-9]{32}'),
    'Mailgun Key': re.compile(r'key-[0-9a-f]{32}'),
}

# Known vulnerable JS library versions
VULNERABLE_LIBS = {
    'jquery': {
        'pattern': re.compile(r'jquery[.-]v?(\d+\.\d+\.?\d*)(?:\.min)?\.js', re.I),
        'vulnerable_below': '3.5.0',
        'cve_note': 'jQuery < 3.5.0 vulnerable to XSS (CVE-2020-11022, CVE-2020-11023)',
    },
    'angular': {
        'pattern': re.compile(r'angular[.-]v?(\d+\.\d+\.?\d*)(?:\.min)?\.js', re.I),
        'vulnerable_below': '1.8.0',
        'cve_note': 'AngularJS 1.x template injection vulnerabilities',
    },
    'lodash': {
        'pattern': re.compile(r'lodash[.-]v?(\d+\.\d+\.?\d*)(?:\.min)?\.js', re.I),
        'vulnerable_below': '4.17.21',
        'cve_note': 'Lodash < 4.17.21 prototype pollution (CVE-2021-23337)',
    },
    'bootstrap': {
        'pattern': re.compile(r'bootstrap[.-]v?(\d+\.\d+\.?\d*)(?:\.min)?\.js', re.I),
        'vulnerable_below': '4.3.1',
        'cve_note': 'Bootstrap < 4.3.1 XSS via data-template (CVE-2019-8331)',
    },
}


def extract_js_urls(base_url: str, session: requests.Session) -> list:
    """Extract all JS file URLs from a page."""
    js_urls = set()
    try:
        resp = session.get(base_url, timeout=15)
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(resp.text, 'html.parser')
        for tag in soup.find_all('script'):
            src = tag.get('src', '')
            if src:
                abs_url = urljoin(base_url, src)
                js_urls.add(abs_url)
        # Also find inline JS references
        text = resp.text
        for pattern in [
            re.compile(r'''src=['"](.*?\.js(?:\?[^'"]*)?)['"'''),
            re.compile(r'''loadScript\(['"](.*?\.js)['"'''),
        ]:
            for match in pattern.finditer(text):
                abs_url = urljoin(base_url, match.group(1))
                js_urls.add(abs_url)
    except Exception as e:
        logger.debug(f"[JS] Failed to extract JS URLs from {base_url}: {e}")
    return list(js_urls)


def analyze_js_file(url: str, session: requests.Session) -> dict:
    """
    Download and analyze a JS file for endpoints, secrets, and vulnerabilities.
    """
    result = {
        'url': url,
        'endpoints': [],
        'secrets': [],
        'vulnerable_libs': [],
        'source_map': None,
    }

    try:
        resp = session.get(url, timeout=15)
        if resp.status_code != 200:
            return result

        content = resp.text

        # Check for source map
        if '//# sourceMappingURL=' in content:
            map_url = re.search(r'//# sourceMappingURL=([^\s]+)', content)
            if map_url:
                result['source_map'] = urljoin(url, map_url.group(1))

        # Extract endpoints
        endpoints = set()
        for pattern in ENDPOINT_PATTERNS:
            for match in pattern.finditer(content):
                endpoint = match.group(1)
                if len(endpoint) > 3 and not endpoint.endswith(('.js', '.css', '.png', '.jpg')):
                    endpoints.add(endpoint)
        result['endpoints'] = sorted(endpoints)

        # Detect secrets
        for secret_type, pattern in SECRET_PATTERNS.items():
            matches = pattern.findall(content)
            for match in matches:
                match_str = match if isinstance(match, str) else match[0] if match else ''
                if match_str and len(match_str) > 8:
                    # Avoid false positives (placeholder-looking values)
                    if not any(fp in match_str.lower() for fp in ['xxxx', 'your_', 'placeholder', 'example']):
                        result['secrets'].append({
                            'type': secret_type,
                            'value': match_str[:20] + '...' if len(match_str) > 20 else match_str,
                            'severity': 'critical' if secret_type in ('AWS Access Key', 'Stripe Secret Key', 'Private Key') else 'high',
                        })
                        logger.warning(f"[JS] Potential {secret_type} found in {url}")

        # Check for vulnerable libraries
        for lib_name, lib_info in VULNERABLE_LIBS.items():
            version_match = lib_info['pattern'].search(url + content[:5000])
            if version_match:
                version = version_match.group(1)
                try:
                    from packaging import version as pkg_ver
                    if pkg_ver.parse(version) < pkg_ver.parse(lib_info['vulnerable_below']):
                        result['vulnerable_libs'].append({
                            'library': lib_name,
                            'version': version,
                            'vulnerable_below': lib_info['vulnerable_below'],
                            'note': lib_info['cve_note'],
                            'severity': 'high',
                        })
                except Exception:
                    pass

    except Exception as e:
        logger.debug(f"[JS] Analysis error for {url}: {e}")

    return result


def analyze_source_map(map_url: str, session: requests.Session) -> dict:
    """
    Download and analyze a .map file to recover original source code.
    This can reveal original file structure and developer comments.
    """
    result = {'url': map_url, 'sources': [], 'secrets_in_source': []}
    try:
        resp = session.get(map_url, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            result['sources'] = data.get('sources', [])
            # Search source content for secrets
            sources_content = data.get('sourcesContent', [])
            for src_content in sources_content:
                if not src_content:
                    continue
                for secret_type, pattern in SECRET_PATTERNS.items():
                    matches = pattern.findall(src_content)
                    if matches:
                        result['secrets_in_source'].append({
                            'type': secret_type,
                            'count': len(matches),
                        })
            logger.warning(f"[JS] Source map accessible: {map_url} ({len(result['sources'])} source files)")
    except Exception as e:
        logger.debug(f"[JS] Source map error: {e}")
    return result


def run_js_analysis(targets: list, workspace_dir: str, auth=None) -> dict:
    """
    Full JS analysis pipeline for all target URLs.
    """
    logger.info(f"[JS] Starting JavaScript analysis for {len(targets)} targets")
    session = auth.session if auth else requests.Session()
    session.headers['User-Agent'] = random_user_agent()

    all_results = {
        'js_files_analyzed': 0,
        'endpoints_found': set(),
        'secrets_found': [],
        'vulnerable_libs': [],
        'source_maps_exposed': [],
    }

    # Collect all JS URLs from all targets
    all_js_urls = set()
    for target in targets:
        if not target.startswith('http'):
            target = f"http://{target}"
        js_urls = extract_js_urls(target, session)
        all_js_urls.update(js_urls)

    logger.info(f"[JS] Found {len(all_js_urls)} JS files to analyze")

    # Analyze each JS file
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(analyze_js_file, url, session): url for url in all_js_urls}
        for future in as_completed(futures):
            result = future.result()
            all_results['js_files_analyzed'] += 1
            all_results['endpoints_found'].update(result.get('endpoints', []))
            all_results['secrets_found'].extend(result.get('secrets', []))
            all_results['vulnerable_libs'].extend(result.get('vulnerable_libs', []))

            # Check source maps
            if result.get('source_map'):
                map_result = analyze_source_map(result['source_map'], session)
                if map_result.get('sources'):
                    all_results['source_maps_exposed'].append(map_result)

    all_results['endpoints_found'] = sorted(all_results['endpoints_found'])

    # Save results
    out_file = os.path.join(workspace_dir, 'js_analysis.json')
    with open(out_file, 'w') as f:
        json.dump({
            **all_results,
            'endpoints_found': list(all_results['endpoints_found'])
        }, f, indent=2, default=str)

    logger.info(
        f"[JS] Analysis complete: {all_results['js_files_analyzed']} files, "
        f"{len(all_results['endpoints_found'])} endpoints, "
        f"{len(all_results['secrets_found'])} secrets, "
        f"{len(all_results['vulnerable_libs'])} vulnerable libs"
    )

    return all_results
