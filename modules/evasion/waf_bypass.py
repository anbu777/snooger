"""
Advanced WAF evasion: fingerprinting, multi-technique bypass, proxy support.
"""
import random
import time
import logging
import re
from urllib.parse import quote, quote_plus
import base64
from typing import Optional, List, Dict

logger = logging.getLogger('snooger')

# Large realistic user-agent pool
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.2277.128",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.90 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "PostmanRuntime/7.36.3",
    "python-requests/2.31.0",
    "curl/8.5.0",
]

WAF_SIGNATURES = {
    'cloudflare': ['__cfduid', 'cf-ray', 'cloudflare', 'cf-cache-status'],
    'akamai': ['akamai', 'x-check-cacheable', 'x-akamai-transformed'],
    'aws_waf': ['x-amzn-requestid', 'x-amz-cf-id', 'awselb'],
    'incapsula': ['incap_ses', 'visid_incap', 'x-iinfo'],
    'sucuri': ['x-sucuri-id', 'x-sucuri-cache'],
    'f5_big_ip': ['bigipserver', 'f5-ltm', 'ts=', 'BIGipServer'],
    'fortiwaf': ['fortigate', 'fortiwafsid'],
    'barracuda': ['barra_counter_session'],
    'modsecurity': ['mod_security', 'modsec'],
    'wordfence': ['wordfence'],
}

def fingerprint_waf(response_headers: dict, response_body: str = '') -> Optional[str]:
    """Detect WAF from response headers and body."""
    headers_str = ' '.join(f"{k}: {v}" for k, v in response_headers.items()).lower()
    body_lower = response_body.lower()
    for waf_name, signatures in WAF_SIGNATURES.items():
        for sig in signatures:
            if sig.lower() in headers_str or sig.lower() in body_lower:
                logger.info(f"WAF detected: {waf_name}")
                return waf_name
    return None

def get_evasion_headers(waf_type: Optional[str] = None) -> Dict[str, str]:
    """Get headers designed to evade detection."""
    ua = _get_user_agent()
    headers = {
        'User-Agent': ua,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': random.choice([
            'en-US,en;q=0.9',
            'en-GB,en;q=0.9',
            'en-US,en;q=0.5',
        ]),
        'Accept-Encoding': 'gzip, deflate, br',
        'DNT': '1',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Cache-Control': 'max-age=0',
    }
    # Cloudflare-specific evasion
    if waf_type == 'cloudflare':
        headers['CF-Connecting-IP'] = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
    return headers

def _get_user_agent() -> str:
    try:
        from fake_useragent import UserAgent
        return UserAgent().random
    except Exception:
        return random.choice(USER_AGENTS)

def obfuscate_payload(payload: str, techniques: Optional[List[str]] = None) -> List[str]:
    """
    Return multiple obfuscated versions of a payload.
    Returns list of (technique_name, obfuscated_payload) tuples.
    """
    if techniques is None:
        techniques = ['urlencode', 'double_urlencode', 'case_random',
                      'html_entity', 'unicode_escape', 'null_byte', 'comment_insertion']

    results = []
    for tech in techniques:
        try:
            obf = _apply_technique(payload, tech)
            if obf and obf != payload:
                results.append((tech, obf))
        except Exception as e:
            logger.debug(f"Obfuscation {tech} failed: {e}")
    # Always include original
    results.insert(0, ('original', payload))
    return results

def _apply_technique(payload: str, technique: str) -> str:
    if technique == 'urlencode':
        return quote(payload, safe='')
    elif technique == 'double_urlencode':
        return quote(quote(payload, safe=''), safe='')
    elif technique == 'base64':
        return base64.b64encode(payload.encode()).decode()
    elif technique == 'case_random':
        return ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in payload)
    elif technique == 'html_entity':
        return ''.join(f'&#{ord(c)};' for c in payload)
    elif technique == 'unicode_escape':
        return ''.join(f'\\u{ord(c):04x}' if c.isalpha() else c for c in payload)
    elif technique == 'null_byte':
        parts = payload.split('<')
        return '%00'.join(parts) if len(parts) > 1 else payload + '%00'
    elif technique == 'comment_insertion':
        # Insert /* */ comments into SQL/script payloads
        return re.sub(r'(\s+)', r'/*\1*/', payload)
    elif technique == 'chunked_encoding':
        # For use in HTTP chunked transfer evasion
        chunks = [payload[i:i+3] for i in range(0, len(payload), 3)]
        return quote(''.join(chunks))
    return payload

def get_bypass_headers_for_ip(fake_ip: Optional[str] = None) -> Dict[str, str]:
    """Headers to spoof IP address / bypass IP restrictions."""
    ip = fake_ip or f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
    return {
        'X-Forwarded-For': ip,
        'X-Real-IP': ip,
        'X-Originating-IP': ip,
        'X-Remote-IP': ip,
        'X-Remote-Addr': ip,
        'True-Client-IP': ip,
        'CF-Connecting-IP': ip,
    }

def build_proxy_config(config: dict) -> Optional[dict]:
    """Build requests proxy dict from config."""
    proxy_cfg = config.get('proxy', {})
    if not proxy_cfg.get('enabled', False):
        return None
    proxies = {}
    if proxy_cfg.get('http'):
        proxies['http'] = proxy_cfg['http']
    if proxy_cfg.get('https'):
        proxies['https'] = proxy_cfg['https']
    if proxy_cfg.get('socks5'):
        proxies['http'] = proxy_cfg['socks5']
        proxies['https'] = proxy_cfg['socks5']
    return proxies if proxies else None

class ProxyRotator:
    """Rotate through a list of proxies."""
    def __init__(self, proxy_list_file: Optional[str] = None):
        self.proxies: List[str] = []
        self._index = 0
        if proxy_list_file:
            self.load_from_file(proxy_list_file)

    def load_from_file(self, filepath: str) -> None:
        try:
            with open(filepath, 'r') as f:
                self.proxies = [l.strip() for l in f if l.strip() and not l.startswith('#')]
            logger.info(f"Loaded {len(self.proxies)} proxies from {filepath}")
        except OSError as e:
            logger.error(f"Cannot load proxy list: {e}")

    def next(self) -> Optional[dict]:
        if not self.proxies:
            return None
        proxy = self.proxies[self._index % len(self.proxies)]
        self._index += 1
        if proxy.startswith('socks5://'):
            return {'http': proxy, 'https': proxy}
        return {'http': proxy, 'https': proxy}

    def get_requests_proxies(self) -> Optional[dict]:
        return self.next()
