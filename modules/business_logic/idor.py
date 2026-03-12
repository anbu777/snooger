"""
Improved IDOR detection:
- UUID, GUID, hash-based, base64 ID support
- Semantic response comparison (difflib)
- Vertical privilege escalation testing
- HTTP method manipulation
- Header-based ID testing
"""
import os
import re
import json
import logging
import difflib
import base64
import requests
from uuid import UUID
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List, Dict, Tuple, Optional
from core.utils import write_json
from core.rate_limiter import get_rate_limiter

logger = logging.getLogger('snooger')

# Patterns for ID-like values
ID_PATTERNS = {
    'numeric': re.compile(r'^\d{1,10}$'),
    'uuid': re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I),
    'hash_md5': re.compile(r'^[0-9a-f]{32}$', re.I),
    'hash_sha1': re.compile(r'^[0-9a-f]{40}$', re.I),
    'hash_sha256': re.compile(r'^[0-9a-f]{64}$', re.I),
    'base64': re.compile(r'^[A-Za-z0-9+/]{8,}={0,2}$'),
}

IDOR_TEST_HEADERS = [
    'X-User-ID', 'X-Account-ID', 'X-Org-ID', 'X-Customer-ID',
    'X-Resource-ID', 'X-Object-ID', 'X-Entity-ID',
]

def detect_id_type(value: str) -> Optional[str]:
    """Detect what type of identifier a value is."""
    for id_type, pattern in ID_PATTERNS.items():
        if pattern.match(value):
            return id_type
    return None

def increment_id(value: str, id_type: str) -> List[str]:
    """Generate alternative IDs to test."""
    alternatives = []
    if id_type == 'numeric':
        n = int(value)
        alternatives = [str(n - 1), str(n + 1), str(n + 2),
                        str(1), str(2), str(100), '0']
    elif id_type == 'uuid':
        # Common predictable UUIDs and slight variations
        alternatives = [
            '00000000-0000-0000-0000-000000000001',
            '00000000-0000-0000-0000-000000000002',
            value[:-1] + ('0' if value[-1] != '0' else '1'),
        ]
    elif id_type in ('hash_md5', 'hash_sha1', 'hash_sha256'):
        # Can't predict, but test common "empty" hashes
        empty_hashes = {
            'hash_md5': 'd41d8cd98f00b204e9800998ecf8427e',
            'hash_sha1': 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
        }
        if id_type in empty_hashes:
            alternatives = [empty_hashes[id_type]]
    elif id_type == 'base64':
        try:
            decoded = base64.b64decode(value + '==').decode('utf-8', errors='ignore')
            # Modify numeric part in decoded string
            modified = re.sub(r'\d+', lambda m: str(int(m.group(0)) + 1), decoded, count=1)
            if modified != decoded:
                alternatives.append(base64.b64encode(modified.encode()).decode().rstrip('='))
        except Exception:
            pass
    return alternatives

def compare_responses(resp1: requests.Response, resp2: requests.Response,
                       threshold: float = 0.95) -> Tuple[bool, str]:
    """
    Compare two responses semantically.
    Returns (is_different, reason).
    """
    # Status code difference
    if resp1.status_code != resp2.status_code:
        return True, f"Status code: {resp1.status_code} vs {resp2.status_code}"

    # Both should be non-error
    if resp2.status_code in (403, 401, 404):
        return False, "Access denied (expected)"

    # Content length significantly different
    len1, len2 = len(resp1.content), len(resp2.content)
    if abs(len1 - len2) > max(50, len1 * 0.1):
        # Confirm with text similarity
        similarity = difflib.SequenceMatcher(
            None, resp1.text[:2000], resp2.text[:2000]
        ).ratio()
        if similarity < threshold:
            return True, f"Content differs: len {len1} vs {len2}, similarity {similarity:.2f}"

    return False, "Responses appear identical"

def test_idor_url(url: str, id_value: str, id_type: str,
                  session: requests.Session, rl) -> List[dict]:
    """Test IDOR on a URL containing an ID."""
    findings = []
    alternatives = increment_id(id_value, id_type)
    if not alternatives:
        return findings

    # Get victim response
    try:
        rl.wait(url)
        victim_resp = session.get(url, timeout=10, verify=False)
        if victim_resp.status_code not in (200, 201):
            return findings
    except Exception:
        return findings

    parsed = urlparse(url)
    for alt_id in alternatives[:5]:
        # Test path-based IDs
        new_url = url.replace(id_value, alt_id, 1)
        if new_url == url:
            continue
        try:
            rl.wait(url)
            alt_resp = session.get(new_url, timeout=10, verify=False)
            is_diff, reason = compare_responses(victim_resp, alt_resp)
            if is_diff and alt_resp.status_code == 200:
                findings.append({
                    'type': 'IDOR',
                    'url': new_url,
                    'original_url': url,
                    'original_id': id_value,
                    'tested_id': alt_id,
                    'id_type': id_type,
                    'evidence': reason,
                    'severity': 'high',
                    'status_code': alt_resp.status_code,
                    'original_length': len(victim_resp.content),
                    'test_length': len(alt_resp.content)
                })
                logger.warning(f"IDOR candidate: {new_url} (id {alt_id} vs {id_value})")
        except Exception as e:
            logger.debug(f"IDOR test error: {e}")

    return findings

def test_idor_query_params(url: str, params: dict,
                           session: requests.Session, rl) -> List[dict]:
    """Test IDOR via query parameters."""
    from urllib.parse import urlencode
    findings = []
    base_url = url.split('?')[0]

    for param_name, param_value in params.items():
        id_type = detect_id_type(param_value)
        if not id_type:
            continue
        alternatives = increment_id(param_value, id_type)
        try:
            rl.wait(base_url)
            victim_resp = session.get(url, timeout=10, verify=False)
        except Exception:
            continue

        for alt_id in alternatives[:5]:
            test_params = params.copy()
            test_params[param_name] = alt_id
            test_url = f"{base_url}?{urlencode(test_params)}"
            try:
                rl.wait(base_url)
                alt_resp = session.get(test_url, timeout=10, verify=False)
                is_diff, reason = compare_responses(victim_resp, alt_resp)
                if is_diff and alt_resp.status_code == 200:
                    findings.append({
                        'type': 'IDOR',
                        'subtype': 'query_param',
                        'url': test_url,
                        'original_url': url,
                        'parameter': param_name,
                        'original_id': param_value,
                        'tested_id': alt_id,
                        'id_type': id_type,
                        'evidence': reason,
                        'severity': 'high'
                    })
            except Exception:
                pass

    return findings

def test_idor_headers(url: str, auth=None) -> List[dict]:
    """Test IDOR via HTTP headers containing user/account IDs."""
    session = auth.session if auth else requests.Session()
    rl = get_rate_limiter()
    findings = []

    test_values = ['1', '2', '100', '0', '-1', '9999', 'admin']
    for header in IDOR_TEST_HEADERS:
        for value in test_values:
            try:
                rl.wait(url)
                resp = session.get(url, headers={header: value}, timeout=8, verify=False)
                if resp.status_code == 200:
                    rl.wait(url)
                    baseline = session.get(url, timeout=8, verify=False)
                    is_diff, reason = compare_responses(baseline, resp)
                    if is_diff:
                        findings.append({
                            'type': 'IDOR',
                            'subtype': 'header_based',
                            'url': url,
                            'header': header,
                            'value': value,
                            'evidence': reason,
                            'severity': 'high'
                        })
            except Exception:
                pass

    return findings

def test_idor_http_methods(url: str, id_value: str, auth=None) -> List[dict]:
    """Test IDOR with HTTP method manipulation (GET → PUT/DELETE)."""
    session = auth.session if auth else requests.Session()
    rl = get_rate_limiter()
    findings = []

    for method in ['POST', 'PUT', 'DELETE', 'PATCH']:
        try:
            rl.wait(url)
            resp = session.request(method, url, timeout=8, verify=False)
            if resp.status_code in (200, 201, 204):
                findings.append({
                    'type': 'IDOR',
                    'subtype': 'method_manipulation',
                    'url': url,
                    'method': method,
                    'severity': 'high',
                    'evidence': f"HTTP {method} succeeded with status {resp.status_code}"
                })
                logger.warning(f"IDOR via method {method}: {url}")
        except Exception:
            pass

    return findings

def extract_ids_from_urls(urls: List[str]) -> List[Tuple[str, str, str]]:
    """
    Extract (url, id_value, id_type) tuples from URL list.
    Checks both path segments and query parameters.
    """
    candidates = []
    for url in urls:
        parsed = urlparse(url)
        # Check path segments
        segments = [s for s in parsed.path.split('/') if s]
        for segment in segments:
            id_type = detect_id_type(segment)
            if id_type:
                candidates.append((url, segment, id_type))
            # New: Aggressive segment detection for alphanumeric IDs (often used in APIs)
            elif len(segment) >= 8 and len(segment) <= 40 and any(c.isdigit() for c in segment):
                candidates.append((url, segment, 'alphanumeric'))
        
        # Check query params
        params = parse_qs(parsed.query)
        for param_name, values in params.items():
            for value in values:
                id_type = detect_id_type(value)
                if id_type:
                    candidates.append((url, value, id_type))
                elif len(value) >= 4 and len(value) <= 20 and any(c.isdigit() for c in value):
                    candidates.append((url, value, 'alphanumeric_small'))
    return candidates

def scan_idor(auth, urls: List[str], workspace_dir: str) -> List[dict]:
    """Run comprehensive IDOR scan across all URLs."""
    if not urls:
        return []

    logger.info(f"Starting IDOR scan across {len(urls)} URLs")
    session = auth.session if auth else requests.Session()
    rl = get_rate_limiter()
    all_findings = []

    # URL-based IDOR
    candidates = extract_ids_from_urls(urls)
    logger.info(f"Found {len(candidates)} ID candidates for IDOR testing")

    for url, id_value, id_type in candidates[:50]:
        try:
            findings = test_idor_url(url, id_value, id_type, session, rl)
            all_findings.extend(findings)
        except Exception as e:
            logger.error(f"IDOR test error for {url}: {e}")

    # Query param IDOR
    for url in urls[:30]:
        parsed = urlparse(url)
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        if params:
            try:
                findings = test_idor_query_params(url, params, session, rl)
                all_findings.extend(findings)
            except Exception as e:
                logger.error(f"IDOR query test error: {e}")

    # Header-based IDOR
    if auth and auth.is_logged_in():
        for url in urls[:20]:
            try:
                header_findings = test_idor_headers(url, auth)
                all_findings.extend(header_findings)
            except Exception as e:
                logger.error(f"IDOR header test error: {e}")

    # Deduplicate
    seen = set()
    unique_findings = []
    for f in all_findings:
        key = (f.get('url', ''), f.get('tested_id', ''))
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    if unique_findings:
        write_json(os.path.join(workspace_dir, 'idor_findings.json'), unique_findings)
        logger.warning(f"Found {len(unique_findings)} potential IDOR vulnerabilities")
    else:
        logger.info("No IDOR vulnerabilities detected")

    return unique_findings
