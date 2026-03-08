"""
Information disclosure testing:
HTTP security headers, error message analysis, response header analysis,
session management, cookie flags.
"""
import re
import logging
import requests
from typing import List, Dict
from core.utils import random_user_agent, write_json
from core.rate_limiter import get_rate_limiter

logger = logging.getLogger('snooger')

SECURITY_HEADERS = {
    'Strict-Transport-Security': 'missing_hsts',
    'Content-Security-Policy': 'missing_csp',
    'X-Frame-Options': 'missing_x_frame_options',
    'X-Content-Type-Options': 'missing_x_content_type_options',
    'X-XSS-Protection': 'missing_xss_protection',
    'Referrer-Policy': 'missing_referrer_policy',
    'Permissions-Policy': 'missing_permissions_policy',
    'Cross-Origin-Opener-Policy': 'missing_coop',
    'Cross-Origin-Resource-Policy': 'missing_corp',
}

ERROR_INFO_PATTERNS = {
    'stack_trace': r'(?:Traceback|at .+\(.+:\d+\)|Exception in thread|java\.lang\.|System\.Web\.)',
    'file_path_windows': r'[A-Z]:\\[^<"\s]+',
    'file_path_unix': r'(?:/home/|/var/www/|/usr/share/|/etc/)[^\s<"\']+',
    'sql_error': r'(?:MySQL|PostgreSQL|ORA-|MSSQL|SQLite)\s+(?:error|exception)',
    'php_version': r'PHP/[\d.]+',
    'server_version': r'(?:Apache|nginx|IIS)/[\d.]+',
    'internal_ip': r'(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)',
    'email_address': r'[\w.-]+@[\w.-]+\.[a-z]{2,6}',
    'debug_mode': r'(?:DEBUG\s*=\s*True|debug:true|APP_DEBUG=true)',
    'aws_key_hint': r'(?:aws_access|amazon_key|S3_KEY)',
}

def analyze_security_headers(url: str, auth=None) -> List[dict]:
    """Check for missing or misconfigured security headers."""
    session = auth.session if auth else requests.Session()
    session.headers.setdefault('User-Agent', random_user_agent())
    rl = get_rate_limiter()
    findings = []

    try:
        rl.wait(url)
        resp = session.get(url, timeout=10, verify=False)
        headers = {k.lower(): v for k, v in resp.headers.items()}

        for header, finding_type in SECURITY_HEADERS.items():
            if header.lower() not in headers:
                findings.append({
                    'type': 'missing_security_header',
                    'header': header,
                    'url': url,
                    'severity': 'low',
                    'finding_type': finding_type,
                    'evidence': f"Header '{header}' not present in response"
                })

        # Check for verbose server info
        server = resp.headers.get('Server', '')
        if server and re.search(r'[\d.]{3,}', server):
            findings.append({
                'type': 'server_version_disclosure',
                'url': url,
                'severity': 'low',
                'evidence': f"Server header exposes version: {server}"
            })

        # X-Powered-By header
        powered = resp.headers.get('X-Powered-By', '')
        if powered:
            findings.append({
                'type': 'technology_disclosure',
                'url': url,
                'severity': 'info',
                'evidence': f"X-Powered-By: {powered}"
            })

    except Exception as e:
        logger.debug(f"Header analysis error {url}: {e}")

    return findings

def analyze_cookie_security(url: str, auth=None) -> List[dict]:
    """Analyze cookie security flags."""
    session = auth.session if auth else requests.Session()
    rl = get_rate_limiter()
    findings = []

    try:
        rl.wait(url)
        resp = session.get(url, timeout=10, verify=False)
        is_https = url.startswith('https')

        for cookie in resp.cookies:
            issues = []
            if not cookie.has_nonstandard_attr('httponly') and not cookie.has_nonstandard_attr('HttpOnly'):
                if any(sess in cookie.name.lower() for sess in ['session', 'sess', 'auth', 'token']):
                    issues.append('missing HttpOnly flag')
            if is_https and not cookie.secure:
                issues.append('missing Secure flag')
            if not cookie.has_nonstandard_attr('samesite') and not cookie.has_nonstandard_attr('SameSite'):
                issues.append('missing SameSite attribute')

            if issues:
                findings.append({
                    'type': 'insecure_cookie',
                    'url': url,
                    'cookie_name': cookie.name,
                    'issues': issues,
                    'severity': 'medium' if 'HttpOnly' in str(issues) else 'low',
                    'evidence': f"Cookie '{cookie.name}': {', '.join(issues)}"
                })

    except Exception as e:
        logger.debug(f"Cookie analysis error: {e}")

    return findings

def analyze_error_messages(url: str, auth=None) -> List[dict]:
    """Trigger error conditions to detect information leakage."""
    session = auth.session if auth else requests.Session()
    rl = get_rate_limiter()
    findings = []

    # Error-triggering requests
    error_urls = [
        url + "' ",
        url + "/../../../etc/passwd",
        url.rstrip('/') + "/nonexistent_path_12345",
        url + "?id=<invalid>",
        url + "?debug=1&trace=1",
    ]

    for test_url in error_urls:
        try:
            rl.wait(url)
            resp = session.get(test_url, timeout=8, verify=False)
            if resp.status_code >= 400 or 'error' in resp.text.lower():
                for pattern_name, pattern in ERROR_INFO_PATTERNS.items():
                    match = re.search(pattern, resp.text, re.IGNORECASE)
                    if match:
                        findings.append({
                            'type': 'information_disclosure_error',
                            'subtype': pattern_name,
                            'url': test_url,
                            'severity': 'medium' if 'trace' in pattern_name else 'low',
                            'evidence': match.group(0)[:200],
                            'status_code': resp.status_code
                        })
        except Exception:
            pass

    return findings

def test_session_management(base_url: str, auth=None) -> List[dict]:
    """Test session token entropy and security properties."""
    session = auth.session if auth else requests.Session()
    rl = get_rate_limiter()
    findings = []

    # Collect multiple session tokens
    tokens = []
    for _ in range(3):
        try:
            rl.wait(base_url)
            resp = requests.get(base_url, timeout=8, verify=False)
            for cookie in resp.cookies:
                if any(s in cookie.name.lower() for s in ['session', 'sess', 'sid', 'auth']):
                    tokens.append(cookie.value)
        except Exception:
            pass

    if len(tokens) >= 2:
        # Check entropy - tokens should be highly random
        import difflib
        for i in range(len(tokens)-1):
            sim = difflib.SequenceMatcher(None, tokens[i], tokens[i+1]).ratio()
            if sim > 0.8:
                findings.append({
                    'type': 'predictable_session_token',
                    'url': base_url,
                    'severity': 'high',
                    'evidence': f"Session tokens appear similar (similarity: {sim:.2f})",
                    'note': 'Session tokens should be cryptographically random'
                })
                break

        # Check token length (should be >= 128 bits = 16 bytes = 32 hex chars)
        for token in tokens:
            if len(token) < 16:
                findings.append({
                    'type': 'short_session_token',
                    'url': base_url,
                    'severity': 'high',
                    'evidence': f"Session token is only {len(token)} characters (should be 32+)"
                })
                break

    return findings

def run_info_disclosure_tests(targets: List[str], workspace_dir: str,
                               auth=None) -> dict:
    """Run all information disclosure checks."""
    logger.info(f"Running information disclosure tests on {len(targets)} targets")
    all_findings = {
        'security_headers': [],
        'cookie_issues': [],
        'error_disclosure': [],
        'session_management': [],
    }

    for url in targets[:20]:
        for test_name, test_fn, result_key in [
            ('security headers', analyze_security_headers, 'security_headers'),
            ('cookie security', analyze_cookie_security, 'cookie_issues'),
            ('error messages', analyze_error_messages, 'error_disclosure'),
        ]:
            try:
                results = test_fn(url, auth)
                all_findings[result_key].extend(results)
            except Exception as e:
                logger.debug(f"{test_name} test error for {url}: {e}")

    # Session management (test on base target only)
    if targets:
        try:
            session_findings = test_session_management(targets[0], auth)
            all_findings['session_management'].extend(session_findings)
        except Exception as e:
            logger.debug(f"Session test error: {e}")

    total = sum(len(v) for v in all_findings.values())
    logger.info(f"Information disclosure: {total} findings")
    write_json(os.path.join(workspace_dir, 'info_disclosure.json'), all_findings)
    return all_findings
