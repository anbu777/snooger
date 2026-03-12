"""
Authentication & Authorization Testing — Point 16/29 dari perbaikan.
Tests: brute force protection, OAuth misconfig, 2FA bypass, JWT attacks,
session fixation, token reuse, forceful browsing.
"""
import re
import time
import logging
import requests
import base64
import hmac
import hashlib
import json
from typing import List, Optional, Dict
from urllib.parse import urlparse, urljoin, urlencode
from core.utils import write_json, random_user_agent
from core.rate_limiter import get_rate_limiter

logger = logging.getLogger('snooger')

# ─── Brute Force Protection Testing ─────────────────────────────────────────

COMMON_PASSWORDS = ['password', '123456', 'admin', 'letmein', 'qwerty',
                    'password1', 'test', 'admin123', 'root', '12345678']

def test_brute_force_protection(login_url: str, username: str = 'admin',
                                 user_field: str = 'username',
                                 pass_field: str = 'password') -> dict:
    """
    Test if the application has lockout/rate limiting after N failed attempts.
    Sends 10 requests with wrong passwords and checks for lockout.
    """
    session = requests.Session()
    session.headers['User-Agent'] = random_user_agent()
    rl = get_rate_limiter()
    results = {'attempts': [], 'locked_out': False, 'rate_limited': False}

    for i, password in enumerate(COMMON_PASSWORDS):
        rl.wait(login_url)
        try:
            start = time.time()
            resp = session.post(
                login_url,
                data={user_field: username, pass_field: password},
                timeout=10, verify=False, allow_redirects=True
            )
            elapsed = time.time() - start
            text_lower = resp.text.lower()

            attempt = {
                'attempt': i + 1,
                'status': resp.status_code,
                'length': len(resp.content),
                'time': elapsed
            }

            # Detect lockout
            if any(kw in text_lower for kw in
                   ['locked', 'too many', 'blocked', 'banned', 'suspended',
                    'account locked', 'temporarily disabled', 'captcha']):
                attempt['lockout'] = True
                results['locked_out'] = True
                results['lockout_after'] = i + 1
                results['attempts'].append(attempt)
                break

            # Detect rate limiting
            if resp.status_code in (429, 503) or elapsed > 3.0:
                attempt['rate_limited'] = True
                results['rate_limited'] = True
                results['rate_limit_after'] = i + 1
                results['attempts'].append(attempt)
                break

            results['attempts'].append(attempt)
        except Exception as e:
            logger.debug(f"Brute force test error: {e}")
            break

    finding = {
        'type': 'brute_force_protection_test',
        'url': login_url,
        'locked_out': results['locked_out'],
        'rate_limited': results['rate_limited'],
        'attempts_made': len(results['attempts']),
    }

    if not results['locked_out'] and not results['rate_limited']:
        finding['vulnerable'] = True
        finding['severity'] = 'high'
        finding['evidence'] = (f"No lockout detected after {len(results['attempts'])} "
                              f"failed login attempts")
        logger.warning(f"[AUTH] No brute force protection: {login_url}")
    else:
        finding['vulnerable'] = False
        finding['severity'] = 'info'
        trigger = results.get('lockout_after', results.get('rate_limit_after', '?'))
        finding['evidence'] = f"Protection triggered after {trigger} attempts"

    return finding

# ─── JWT Vulnerability Testing ───────────────────────────────────────────────

JWT_WEAK_SECRETS = [
    'secret', 'password', '123456', 'admin', 'key', 'jwt', 'token',
    'qwerty', '', 'null', 'undefined', 'development', 'test', 'change-me'
]

def _decode_jwt_part(part: str) -> dict:
    """Base64url decode a JWT part."""
    padding = 4 - len(part) % 4
    padded = part + ('=' * (padding % 4))
    try:
        return json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        return {}

def _encode_jwt_part(data: dict) -> str:
    """Base64url encode a JWT part."""
    return base64.urlsafe_b64encode(
        json.dumps(data, separators=(',', ':')).encode()
    ).rstrip(b'=').decode()

def test_jwt_vulnerabilities(token: str) -> List[dict]:
    """Test JWT for none algorithm, weak secret, and RS256→HS256 confusion."""
    if not token or token.count('.') != 2:
        return []

    header_b64, payload_b64, signature = token.split('.')
    header = _decode_jwt_part(header_b64)
    payload = _decode_jwt_part(payload_b64)
    findings = []

    # Test 1: None algorithm attack
    none_variants = ['none', 'None', 'NONE', 'nOnE']
    for alg in none_variants:
        fake_header = dict(header)
        fake_header['alg'] = alg
        forged = f"{_encode_jwt_part(fake_header)}.{payload_b64}."
        findings.append({
            'type': 'jwt_none_algorithm',
            'severity': 'critical',
            'token_to_try': forged,
            'original_alg': header.get('alg'),
            'evidence': f"JWT forged with alg={alg}, empty signature",
            'note': 'If server accepts this token, none algorithm is vulnerable'
        })

    # Test 2: Weak secret brute force (HS256/HS384/HS512)
    alg = header.get('alg', '').upper()
    if alg.startswith('HS'):
        hash_alg = {'HS256': hashlib.sha256, 'HS384': hashlib.sha384,
                    'HS512': hashlib.sha512}.get(alg, hashlib.sha256)
        signing_input = f"{header_b64}.{payload_b64}".encode()
        for secret in JWT_WEAK_SECRETS:
            sig = hmac.new(secret.encode(), signing_input, hash_alg).digest()
            expected = base64.urlsafe_b64encode(sig).rstrip(b'=').decode()
            if expected == signature:
                findings.append({
                    'type': 'jwt_weak_secret',
                    'severity': 'critical',
                    'secret': secret,
                    'algorithm': alg,
                    'evidence': f"JWT secret cracked: '{secret}'",
                    'impact': 'Attacker can forge arbitrary JWT tokens'
                })
                logger.warning(f"[JWT] Weak secret cracked: '{secret}'")
                break

    # Test 3: RS256 → HS256 algorithm confusion
    if alg == 'RS256':
        confused_header = dict(header)
        confused_header['alg'] = 'HS256'
        confused_token = (
            f"{_encode_jwt_part(confused_header)}.{payload_b64}."
            "CONFUSED_SIGNATURE_REPLACE_WITH_PUBLIC_KEY_HMAC"
        )
        findings.append({
            'type': 'jwt_alg_confusion_candidate',
            'severity': 'high',
            'algorithm': 'RS256→HS256',
            'evidence': 'RS256 token detected — test HS256 confusion with public key as secret',
            'note': 'Sign with server public key as HMAC secret to forge tokens',
            'candidate_token': confused_token
        })

    # Test 4: Check for admin/elevated claims to modify
    sensitive_claims = ['role', 'admin', 'is_admin', 'privilege', 'scope',
                        'permissions', 'user_type', 'group']
    found_claims = {k: v for k, v in payload.items()
                    if any(s in k.lower() for s in sensitive_claims)}
    if found_claims:
        findings.append({
            'type': 'jwt_privilege_claims',
            'severity': 'info',
            'claims': found_claims,
            'evidence': f"JWT contains privilege claims: {list(found_claims.keys())}",
            'note': 'If weak secret found, modify these claims to escalate privileges'
        })

    return findings

# ─── OAuth Misconfiguration Testing ─────────────────────────────────────────

def test_oauth_misconfigurations(base_url: str, auth=None) -> List[dict]:
    """Test OAuth 2.0 flow for common misconfigurations."""
    session = auth.session if auth else requests.Session()
    rl = get_rate_limiter()
    findings = []

    # Discover OAuth endpoints
    oauth_paths = [
        '/.well-known/openid-configuration',
        '/.well-known/oauth-authorization-server',
        '/oauth/authorize', '/oauth2/authorize', '/auth/authorize',
        '/connect/authorize', '/api/oauth/authorize',
    ]

    discovered = []
    for path in oauth_paths:
        url = f"{base_url.rstrip('/')}{path}"
        try:
            rl.wait(url)
            resp = session.get(url, timeout=8, verify=False)
            if resp.status_code in (200, 302, 400):
                discovered.append({'url': url, 'status': resp.status_code})
        except Exception:
            pass

    if not discovered:
        return []

    for endpoint in discovered:
        url = endpoint['url']
        # Test 1: State parameter CSRF
        try:
            rl.wait(url)
            resp = session.get(
                url + "?response_type=code&client_id=test&redirect_uri=https://attacker.com",
                timeout=8, verify=False
            )
            if resp.status_code in (200, 302):
                redirect = resp.headers.get('Location', '')
                if 'code=' in redirect and 'state=' not in redirect:
                    findings.append({
                        'type': 'oauth_missing_state',
                        'url': url,
                        'severity': 'medium',
                        'evidence': 'OAuth authorization without state parameter (CSRF risk)',
                    })
        except Exception:
            pass

        # Test 2: Open redirect in redirect_uri
        evil_redirects = [
            'https://evil.com', 'https://attacker.com',
            f'https://evil.{base_url.split("//")[-1].split("/")[0]}',
        ]
        for evil_uri in evil_redirects[:2]:
            try:
                rl.wait(url)
                resp = session.get(
                    url + f"?response_type=token&client_id=test&redirect_uri={evil_uri}",
                    timeout=8, verify=False, allow_redirects=False
                )
                location = resp.headers.get('Location', '')
                if evil_uri in location or 'access_token=' in location:
                    findings.append({
                        'type': 'oauth_open_redirect',
                        'url': url,
                        'severity': 'high',
                        'redirect_uri': evil_uri,
                        'evidence': f"OAuth accepts arbitrary redirect_uri: {evil_uri}",
                        'impact': 'Token theft via malicious redirect'
                    })
            except Exception:
                pass

    return findings

# ─── Session Fixation & Forceful Browsing ───────────────────────────────────

def test_forceful_browsing(base_url: str, crawler_results: dict,
                            auth=None) -> List[dict]:
    """
    Test authenticated pages for forceful browsing (access without session).
    Compares logged-in vs unauthenticated responses.
    """
    if not auth or not auth.is_logged_in():
        return []

    session_no_auth = requests.Session()
    session_no_auth.headers['User-Agent'] = random_user_agent()
    rl = get_rate_limiter()
    findings = []

    # Get pages discovered while authenticated
    auth_pages = [url for url in crawler_results.get('visited_urls', [])
                  if any(kw in url.lower() for kw in
                         ['admin', 'dashboard', 'profile', 'account', 'settings',
                          'manage', 'user', 'edit', 'delete', 'api'])]

    for url in auth_pages[:20]:
        try:
            # Auth request
            rl.wait(url)
            auth_resp = auth.session.get(url, timeout=8, verify=False)

            # Unauth request
            rl.wait(url)
            unauth_resp = session_no_auth.get(url, timeout=8, verify=False)

            # If both 200 and similar content → broken access control
            if (auth_resp.status_code == 200 and
                unauth_resp.status_code == 200 and
                len(unauth_resp.content) > 200):
                # Check content similarity
                import difflib
                sim = difflib.SequenceMatcher(
                    None, auth_resp.text[:500], unauth_resp.text[:500]
                ).ratio()
                if sim > 0.7:
                    findings.append({
                        'type': 'forceful_browsing',
                        'url': url,
                        'severity': 'high',
                        'similarity': round(sim, 2),
                        'evidence': (f"Authenticated page accessible without session "
                                    f"(similarity: {sim:.0%})")
                    })
                    logger.warning(f"[AUTH] Forceful browsing: {url}")
        except Exception:
            pass

    return findings

# ─── Session Security & Fixation ─────────────────────────────────────────────

def test_session_fixation(login_url: str, user_field: str = 'username', 
                         pass_field: str = 'password', auth=None) -> dict:
    """
    Test if the session ID changes after authentication.
    """
    session = requests.Session()
    session.headers['User-Agent'] = random_user_agent()
    rl = get_rate_limiter()
    
    finding = {}
    try:
        # Step 1: Get pre-login session
        rl.wait(login_url)
        resp1 = session.get(login_url, timeout=10, verify=False)
        pre_login_cookies = session.cookies.get_dict()
        
        # Step 2: Login attempt
        rl.wait(login_url)
        resp2 = session.post(login_url, data={user_field: 'test', pass_field: 'test'}, 
                            timeout=10, verify=False)
        post_login_cookies = session.cookies.get_dict()
        
        for name, value in pre_login_cookies.items():
            if name in post_login_cookies and post_login_cookies[name] == value:
                if any(k in name.lower() for k in ['sess', 'auth', 'id', 'token']):
                    finding = {
                        'type': 'session_fixation_risk',
                        'severity': 'medium',
                        'cookie_name': name,
                        'evidence': f"Session cookie '{name}' did not change after login attempt",
                        'impact': 'Attacker can pre-set a session ID for a victim'
                    }
    except Exception as e:
        logger.debug(f"Session fixation test error: {e}")
        
    return finding

def analyze_form_security(url: str, form_html: str) -> List[dict]:
    """Analyze form HTML for security issues (CSRF, sensitive fields over GET)."""
    findings = []
    if 'method="get"' in form_html.lower() or "method='get'" in form_html.lower():
        if any(p in form_html.lower() for p in ['password', 'token', 'secret', 'key']):
            findings.append({
                'type': 'sensitive_data_in_get_form',
                'severity': 'high',
                'url': url,
                'evidence': 'Sensitive fields found in a GET form'
            })
            
    if 'type="hidden"' in form_html.lower():
        if not any(kw in form_html.lower() for kw in ['csrf', 'token', 'xsrf', '_token']):
            findings.append({
                'type': 'potential_missing_csrf_protection',
                'severity': 'medium',
                'url': url,
                'evidence': 'Form contains hidden fields but no obvious CSRF token'
            })
            
    return findings

def run_auth_tests(base_url: str, workspace_dir: str,
                   auth=None, crawler_results = None,
                   login_url = None, jwt_token = None) -> dict:
    """Run all authentication and authorization tests."""
    results = {
        'brute_force': {},
        'jwt_findings': [],
        'oauth_findings': [],
        'forceful_browsing': []
    }

    # Brute force protection
    if login_url:
        bf_result = test_brute_force_protection(login_url)
        results['brute_force'] = bf_result

    # JWT analysis
    if jwt_token:
        jwt_findings = test_jwt_vulnerabilities(jwt_token)
        results['jwt_findings'] = jwt_findings

    # OAuth testing
    oauth_findings = test_oauth_misconfigurations(base_url, auth)
    results['oauth_findings'] = oauth_findings

    # Forceful browsing
    if crawler_results and auth:
        fb_findings = test_forceful_browsing(base_url, crawler_results, auth)
        results['forceful_browsing'] = fb_findings

    # Session fixation
    if login_url:
        fixation = test_session_fixation(login_url)
        if fixation:
            results['session_fixation'] = fixation

    # Cookie security attributes (if we have an active session)
    if auth and auth.session.cookies:
        cookies_jar = auth.session.cookies
        for cookie in cookies_jar:
            if any(k in cookie.name.lower() for k in ['sess', 'auth', 'id', 'token']):
                missing = []
                if not cookie.secure: missing.append('Secure')
                if not cookie.has_nonstandard_attr('httponly') and not getattr(cookie, 'httponly', False):
                    # Requests cookiejar handling for httponly is tricky, check _rest
                    if 'httponly' not in [k.lower() for k in cookie._rest.keys()] and not getattr(cookie, 'httponly', False):
                        missing.append('HttpOnly')
                
                if missing:
                    results['oauth_findings'].append({ # Reusing a list or adding new category
                        'type': 'insecure_cookie_attributes',
                        'severity': 'low',
                        'cookie': cookie.name,
                        'missing_attributes': missing,
                        'evidence': f"Cookie '{cookie.name}' missing flags: {', '.join(missing)}"
                    })

    total = (len(results['jwt_findings']) + len(results['oauth_findings']) +
             len(results['forceful_browsing']) + (1 if results.get('session_fixation') else 0))
    if results.get('brute_force', {}).get('vulnerable'):
        total += 1

    if total > 0:
        logger.warning(f"Auth testing: {total} issues found")
    write_json(f"{workspace_dir}/auth_test_results.json", results)
    return results
