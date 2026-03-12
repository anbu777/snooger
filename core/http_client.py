"""
Async HTTP Client — high-performance HTTP client with retry, proxy rotation,
user-agent rotation, rate limiting integration, and cookie management.
"""
import asyncio
import random
import logging
import ssl
import time
from typing import Optional, Dict, List, Any
from urllib.parse import urlparse

logger = logging.getLogger('snooger')

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

import requests
from core.rate_limiter import get_rate_limiter

USER_AGENTS = [
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 OPR/109.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.52 Mobile Safari/537.36",
]


def random_ua() -> str:
    """Get a random user-agent string."""
    try:
        from fake_useragent import UserAgent
        return UserAgent().random
    except Exception:
        return random.choice(USER_AGENTS)


class AsyncHTTPClient:
    """
    Production-grade async HTTP client.
    Features: retry, backoff, proxy rotation, UA rotation, rate limiting.
    """

    def __init__(self, config = None, auth=None):
        self.config = config or {}
        self.auth = auth
        self._session: Optional[aiohttp.ClientSession] = None
        self._proxy_list: List[str] = []
        self._proxy_index = 0

        # Config
        stealth = self.config.get('stealth', {})
        self.rotate_ua = stealth.get('rotate_useragent', True)
        self.jitter_min = stealth.get('random_delay_min', 0.3)
        self.jitter_max = stealth.get('random_delay_max', 1.5)

        rl_cfg = self.config.get('rate_limit', {})
        self.max_retries = rl_cfg.get('max_retries', 3)
        self.backoff_factor = rl_cfg.get('backoff_factor', 2.0)

        # Proxy setup
        proxy_cfg = self.config.get('proxy', {})
        if proxy_cfg.get('enabled'):
            proxy_file = proxy_cfg.get('proxy_list', '')
            if proxy_file:
                self._load_proxies(proxy_file)
            for key in ('http', 'https', 'socks5'):
                if proxy_cfg.get(key):
                    self._proxy_list.append(proxy_cfg[key])

    def _load_proxies(self, filepath: str) -> None:
        try:
            with open(filepath, 'r') as f:
                self._proxy_list = [l.strip() for l in f if l.strip() and not l.startswith('#')]
            logger.info(f"Loaded {len(self._proxy_list)} proxies")
        except OSError as e:
            logger.error(f"Cannot load proxy list: {e}")

    def _get_proxy(self) -> Optional[str]:
        if not self._proxy_list:
            return None
        proxy = self._proxy_list[self._proxy_index % len(self._proxy_list)]
        self._proxy_index += 1
        return proxy

    def _get_headers(self, extra_headers = None) -> dict:
        headers = {
            'User-Agent': random_ua() if self.rotate_ua else USER_AGENTS[0],
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        if self.auth and hasattr(self.auth, 'get_headers'):
            headers.update(self.auth.get_headers())
        if extra_headers:
            headers.update(extra_headers)
        return headers

    async def _get_session(self) -> 'aiohttp.ClientSession':
        if self._session is None or self._session.closed:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

            connector = aiohttp.TCPConnector(
                ssl=ssl_ctx,
                limit=100,
                limit_per_host=10,
                enable_cleanup_closed=True,
            )
            timeout = aiohttp.ClientTimeout(total=30, connect=10)
            self._session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
            )
        return self._session

    async def request(self, method: str, url: str,
                      headers = None, params = None,
                      data: Any = None, json: Any = None,
                      timeout: int = 15, allow_redirects: bool = True,
                      max_retries = None) -> dict:
        """
        Make an HTTP request with retry and rate limiting.
        Returns dict with: status, headers, text, length, elapsed, error
        """
        if not HAS_AIOHTTP:
            return self._sync_request(method, url, headers, params, data, json,
                                      timeout, allow_redirects)

        retries = max_retries if max_retries is not None else self.max_retries
        req_headers = self._get_headers(headers)
        proxy = self._get_proxy()

        rl = get_rate_limiter()
        domain = urlparse(url).netloc

        for attempt in range(retries + 1):
            rl.wait(domain)

            if self.config.get('stealth', {}).get('jitter'):
                await asyncio.sleep(random.uniform(self.jitter_min, self.jitter_max))

            try:
                session = await self._get_session()
                start = time.time()

                async with session.request(
                    method, url,
                    headers=req_headers,
                    params=params,
                    data=data,
                    json=json,
                    proxy=proxy,
                    allow_redirects=allow_redirects,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                ) as resp:
                    body = await resp.text(errors='replace')
                    elapsed = time.time() - start

                    result = {
                        'status': resp.status,
                        'headers': dict(resp.headers),
                        'text': body,
                        'length': len(body),
                        'elapsed': elapsed,
                        'url': str(resp.url),
                        'error': None,
                    }

                    if resp.status in (429, 503):
                        rl.penalize(domain, 5.0)
                        if attempt < retries:
                            wait = self.backoff_factor ** attempt
                            logger.warning(f"Rate limited ({resp.status}), retry in {wait:.1f}s")
                            await asyncio.sleep(wait)
                            continue

                    rl.reset_penalty(domain)
                    return result

            except asyncio.TimeoutError:
                if attempt < retries:
                    await asyncio.sleep(self.backoff_factor ** attempt)
                    continue
                return {'status': 0, 'headers': {}, 'text': '', 'length': 0,
                        'elapsed': timeout, 'url': url, 'error': f'Timeout after {timeout}s'}
            except Exception as e:
                if attempt < retries:
                    await asyncio.sleep(self.backoff_factor ** attempt)
                    continue
                return {'status': 0, 'headers': {}, 'text': '', 'length': 0,
                        'elapsed': 0, 'url': url, 'error': str(e)}

        return {'status': 0, 'headers': {}, 'text': '', 'length': 0,
                'elapsed': 0, 'url': url, 'error': 'Max retries exceeded'}

    async def get(self, url: str, **kwargs) -> dict:
        return await self.request('GET', url, **kwargs)

    async def post(self, url: str, **kwargs) -> dict:
        return await self.request('POST', url, **kwargs)

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()

    def _sync_request(self, method, url, headers, params, data, json_data,
                      timeout, allow_redirects) -> dict:
        """Fallback sync request when aiohttp is not installed."""
        req_headers = self._get_headers(headers)
        rl = get_rate_limiter()
        domain = urlparse(url).netloc
        rl.wait(domain)

        try:
            resp = requests.request(
                method, url,
                headers=req_headers,
                params=params,
                data=data,
                json=json_data,
                timeout=timeout,
                allow_redirects=allow_redirects,
                verify=False,
            )
            return {
                'status': resp.status_code,
                'headers': dict(resp.headers),
                'text': resp.text,
                'length': len(resp.content),
                'elapsed': resp.elapsed.total_seconds(),
                'url': resp.url,
                'error': None,
            }
        except Exception as e:
            return {'status': 0, 'headers': {}, 'text': '', 'length': 0,
                    'elapsed': 0, 'url': url, 'error': str(e)}


class SyncHTTPClient:
    """Simple sync wrapper for use in modules that don't need async."""

    def __init__(self, config = None, auth=None):
        self.config = config or {}
        self.auth = auth
        if auth and hasattr(auth, 'session'):
            self.session = auth.session
        else:
            self.session = requests.Session()
            self.session.headers['User-Agent'] = random_ua()
            self.session.verify = False

    def get(self, url: str, **kwargs) -> requests.Response:
        rl = get_rate_limiter()
        rl.wait(urlparse(url).netloc)
        kwargs.setdefault('timeout', 10)
        kwargs.setdefault('verify', False)
        return self.session.get(url, **kwargs)

    def post(self, url: str, **kwargs) -> requests.Response:
        rl = get_rate_limiter()
        rl.wait(urlparse(url).netloc)
        kwargs.setdefault('timeout', 10)
        kwargs.setdefault('verify', False)
        return self.session.post(url, **kwargs)

    def request(self, method: str, url: str, **kwargs) -> requests.Response:
        rl = get_rate_limiter()
        rl.wait(urlparse(url).netloc)
        kwargs.setdefault('timeout', 10)
        kwargs.setdefault('verify', False)
        return self.session.request(method, url, **kwargs)
