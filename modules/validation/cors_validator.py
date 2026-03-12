"""CORS Misconfiguration Validator"""
import logging
import requests

logger = logging.getLogger('snooger')


from typing import Optional
def check_cors_misconfiguration(url: str, session: Optional[requests.Session] = None) -> dict:
    """Check for CORS misconfiguration."""
    if not session:
        session = requests.Session()

    test_origins = ['https://evil.com', 'null', 'https://attacker.evil.com']
    result = {'vulnerable': False, 'url': url, 'issues': []}

    for origin in test_origins:
        try:
            resp = session.get(url, headers={'Origin': origin}, timeout=10)
            acao = resp.headers.get('Access-Control-Allow-Origin', '')
            acac = resp.headers.get('Access-Control-Allow-Credentials', '').lower()

            if acao in (origin, '*'):
                result['vulnerable'] = True
                result['issues'].append({
                    'origin_tested': origin,
                    'acao': acao,
                    'credentials_allowed': acac == 'true',
                    'severity': 'critical' if (acao == origin and acac == 'true') else 'medium',
                })
                logger.warning(f"[CORS] Vulnerable: {url} → ACAO={acao}, Credentials={acac}")
        except Exception:
            continue

    return result
