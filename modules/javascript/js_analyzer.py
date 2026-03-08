"""
JavaScript file analysis: endpoint extraction, secret detection, source map analysis.
"""
import os
import re
import logging
import requests
from typing import List, Dict, Optional
from core.utils import run_command, save_raw_output, write_json
from core.rate_limiter import get_rate_limiter

logger = logging.getLogger('snooger')

# Patterns for secret/credential detection in JS
SECRET_PATTERNS = {
    'aws_access_key': r'AKIA[0-9A-Z]{16}',
    'aws_secret_key': r'(?i)aws_secret_access_key["\s]*[:=]["\s]*([A-Za-z0-9/+=]{40})',
    'google_api_key': r'AIza[0-9A-Za-z\-_]{35}',
    'google_oauth_token': r'ya29\.[0-9A-Za-z\-_]+',
    'github_token': r'ghp_[0-9a-zA-Z]{36}',
    'github_pat': r'github_pat_[0-9a-zA-Z_]{82}',
    'jwt_token': r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*',
    'private_key': r'-----BEGIN (?:RSA |EC )?PRIVATE KEY',
    'slack_token': r'xox[baprs]-[0-9A-Za-z\-]{10,48}',
    'stripe_key': r'(?:r|s)k_(?:live|test)_[0-9a-zA-Z]{24,}',
    'sendgrid_key': r'SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}',
    'mailchimp_key': r'[0-9a-f]{32}-us[0-9]{1,2}',
    'twilio_sid': r'AC[a-z0-9]{32}',
    'firebase_key': r'(?i)firebase[^"\']*["\']([A-Za-z0-9_-]{20,})',
    'heroku_api_key': r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
    'generic_api_key': r'(?i)(?:api_key|apikey|api-key)["\s]*[:=]["\s]*["\']([A-Za-z0-9_\-]{20,})["\']',
    'generic_secret': r'(?i)(?:secret|password|passwd|pwd|token)["\s]*[:=]["\s]*["\']([A-Za-z0-9_@$!%*?&\-]{8,})["\']',
    'internal_url': r'(?:https?://(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)[^"\']*)',
}

ENDPOINT_PATTERNS = [
    r'["\']([/](?:api|v\d+|rest|graphql|endpoint|internal|admin)[/][^"\'?\s]{1,100})["\']',
    r'\.(?:get|post|put|delete|patch|options)\s*\(\s*["\']([/][^"\'?\s]{1,100})["\']',
    r'(?:fetch|axios|http\.\w+)\s*\(\s*["\']([/][^"\'?\s]{1,200})["\']',
    r'url\s*[:=]\s*["\']([/][^"\'?\s]{1,100})["\']',
    r'path\s*[:=]\s*["\']([/][^"\'?\s]{1,100})["\']',
    r'endpoint\s*[:=]\s*["\']([^"\'?\s]{1,100})["\']',
]

def fetch_js_file(url: str, session: requests.Session) -> Optional[str]:
    """Fetch a JavaScript file."""
    rl = get_rate_limiter()
    rl.wait(url)
    try:
        resp = session.get(url, timeout=15, verify=False)
        if resp.status_code == 200:
            content_type = resp.headers.get('content-type', '')
            if 'javascript' in content_type or 'text/' in content_type or url.endswith('.js'):
                return resp.text
    except Exception as e:
        logger.debug(f"Failed to fetch JS {url}: {e}")
    return None

def beautify_js(content: str) -> str:
    """Beautify minified JavaScript for better analysis."""
    try:
        import jsbeautifier
        opts = jsbeautifier.default_options()
        opts.indent_size = 2
        return jsbeautifier.beautify(content, opts)
    except Exception:
        return content

def extract_endpoints(js_content: str, base_url: str) -> List[str]:
    """Extract API endpoints from JavaScript content."""
    from urllib.parse import urljoin
    endpoints = set()
    for pattern in ENDPOINT_PATTERNS:
        matches = re.findall(pattern, js_content, re.IGNORECASE)
        for match in matches:
            if isinstance(match, tuple):
                match = match[0]
            match = match.strip()
            if len(match) > 1 and not match.endswith('.js'):
                if match.startswith('/'):
                    endpoints.add(urljoin(base_url, match))
                elif match.startswith('http'):
                    endpoints.add(match)
    return list(endpoints)

def extract_secrets(js_content: str, file_url: str) -> List[dict]:
    """Extract potential secrets and credentials from JavaScript."""
    findings = []
    for secret_type, pattern in SECRET_PATTERNS.items():
        matches = re.finditer(pattern, js_content)
        for match in matches:
            value = match.group(0) if not match.groups() else match.group(1)
            # Basic false positive reduction
            if len(value) < 8 or value.lower() in ('undefined', 'null', 'example', 'placeholder'):
                continue
            findings.append({
                'type': secret_type,
                'value': value[:80] + ('...' if len(value) > 80 else ''),
                'file': file_url,
                'context': js_content[max(0, match.start()-30):match.end()+30].strip(),
                'severity': _classify_secret_severity(secret_type)
            })
    return findings

def _classify_secret_severity(secret_type: str) -> str:
    critical = ['aws_access_key', 'aws_secret_key', 'private_key', 'stripe_key', 'github_token', 'github_pat']
    high = ['google_api_key', 'jwt_token', 'slack_token', 'sendgrid_key', 'firebase_key']
    if secret_type in critical:
        return 'critical'
    if secret_type in high:
        return 'high'
    return 'medium'

def check_source_maps(js_url: str, session: requests.Session) -> Optional[dict]:
    """Check for exposed source maps (.map files)."""
    map_url = js_url + '.map'
    rl = get_rate_limiter()
    rl.wait(map_url)
    try:
        resp = session.get(map_url, timeout=10, verify=False)
        if resp.status_code == 200:
            try:
                data = resp.json()
                if 'sources' in data or 'mappings' in data:
                    logger.warning(f"Source map exposed: {map_url}")
                    return {
                        'url': map_url,
                        'sources': data.get('sources', [])[:10],
                        'has_source_content': 'sourcesContent' in data,
                        'severity': 'high'
                    }
            except Exception:
                pass
    except Exception:
        pass
    return None

def check_vulnerable_js_libraries(js_content: str) -> List[dict]:
    """Detect known vulnerable JS library versions."""
    findings = []
    lib_patterns = {
        'jquery': (r'jQuery\s+v?([\d.]+)', '3.7.0'),
        'angular': (r'AngularJS\s+v?([\d.]+)', '1.8.3'),
        'react': (r'React\s+v?([\d.]+)', '18.0.0'),
        'bootstrap': (r'Bootstrap\s+v?([\d.]+)', '5.3.0'),
        'lodash': (r'lodash\s+v?([\d.]+)', '4.17.21'),
        'moment': (r'moment\s+v?([\d.]+)', '2.29.4'),
    }
    for lib, (pattern, min_safe) in lib_patterns.items():
        match = re.search(pattern, js_content, re.IGNORECASE)
        if match:
            version = match.group(1)
            findings.append({
                'library': lib,
                'version': version,
                'min_safe_version': min_safe,
                'check_nvd': f"https://nvd.nist.gov/products/cpe/search/results?keyword={lib}+{version}"
            })
    return findings

def analyze_js_files(js_urls: List[str], base_url: str, workspace_dir: str,
                     auth=None) -> dict:
    """Analyze a list of JavaScript files for secrets, endpoints, and vulnerabilities."""
    session = auth.session if auth else requests.Session()
    session.headers.setdefault('User-Agent', 'Mozilla/5.0')

    all_endpoints = set()
    all_secrets = []
    all_source_maps = []
    vulnerable_libs = []
    analyzed = 0

    js_dir = os.path.join(workspace_dir, 'raw_logs', 'javascript')
    os.makedirs(js_dir, exist_ok=True)

    for js_url in js_urls[:50]:  # Limit to avoid excessive requests
        logger.debug(f"Analyzing JS: {js_url}")
        content = fetch_js_file(js_url, session)
        if not content:
            continue

        analyzed += 1
        # Beautify for better regex matching
        content_pretty = beautify_js(content)

        # Save raw JS
        fname = re.sub(r'[^\w]', '_', js_url[-40:]) + '.js'
        with open(os.path.join(js_dir, fname), 'w', errors='replace') as f:
            f.write(content_pretty)

        # Extract endpoints
        endpoints = extract_endpoints(content_pretty, base_url)
        all_endpoints.update(endpoints)

        # Extract secrets
        secrets = extract_secrets(content_pretty, js_url)
        if secrets:
            all_secrets.extend(secrets)
            logger.warning(f"  Found {len(secrets)} potential secrets in {js_url}")

        # Check source maps
        src_map = check_source_maps(js_url, session)
        if src_map:
            all_source_maps.append(src_map)

        # Check for vulnerable libraries
        libs = check_vulnerable_js_libraries(content)
        vulnerable_libs.extend(libs)

    results = {
        'analyzed_files': analyzed,
        'endpoints_found': list(all_endpoints),
        'secrets': all_secrets,
        'source_maps': all_source_maps,
        'vulnerable_libraries': vulnerable_libs,
        'stats': {
            'js_files_analyzed': analyzed,
            'endpoints_extracted': len(all_endpoints),
            'secrets_found': len(all_secrets),
            'source_maps_exposed': len(all_source_maps),
        }
    }

    write_json(os.path.join(workspace_dir, 'js_analysis.json'), results)

    if all_secrets:
        logger.warning(f"JS Analysis: {len(all_secrets)} potential secrets found!")
    logger.info(f"JS Analysis complete: {results['stats']}")
    return results
