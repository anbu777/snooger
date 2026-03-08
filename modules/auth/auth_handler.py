"""
Authentication handler with secure session storage and token management.
Supports form-based, HTTP Basic, Bearer/JWT, cookies, OAuth detection.
"""
import requests
import os
import json
import re
import logging
from urllib.parse import urlparse
from typing import Optional, Dict
from cryptography.fernet import Fernet

logger = logging.getLogger('snooger')

def _get_or_create_key(workspace_dir: str) -> bytes:
    """Get or create a symmetric encryption key for session storage."""
    key_file = os.path.join(workspace_dir, '.session_key')
    if os.path.exists(key_file):
        with open(key_file, 'rb') as f:
            return f.read()
    key = Fernet.generate_key()
    with open(key_file, 'wb') as f:
        f.write(key)
    os.chmod(key_file, 0o600)
    return key

class AuthManager:
    def __init__(self, workspace_dir: str, config: Optional[dict] = None):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0'
        })
        self.base_url: Optional[str] = None
        self.logged_in: bool = False
        self.workspace_dir = workspace_dir
        self.auth_type: Optional[str] = None
        self.auth_data: Dict = {}
        self.session_file = os.path.join(workspace_dir, 'auth_session.enc')
        self._fernet = Fernet(_get_or_create_key(workspace_dir))

        # Setup proxy if configured
        if config:
            from modules.evasion.waf_bypass import build_proxy_config
            proxies = build_proxy_config(config)
            if proxies:
                self.session.proxies.update(proxies)

    def set_base_url(self, url: str) -> None:
        self.base_url = url.rstrip('/')

    def get(self, url: str, **kwargs) -> requests.Response:
        return self.session.get(url, **kwargs)

    def post(self, url: str, **kwargs) -> requests.Response:
        return self.session.post(url, **kwargs)

    def is_logged_in(self) -> bool:
        return self.logged_in

    def load_session(self) -> bool:
        if not os.path.exists(self.session_file):
            return False
        try:
            with open(self.session_file, 'rb') as f:
                encrypted = f.read()
            decrypted = self._fernet.decrypt(encrypted)
            session_data = json.loads(decrypted)
            for cookie in session_data.get('cookies', []):
                self.session.cookies.set(
                    cookie['name'], cookie['value'],
                    domain=cookie.get('domain', ''), path=cookie.get('path', '/')
                )
            if session_data.get('headers'):
                self.session.headers.update(session_data['headers'])
            self.logged_in = True
            self.auth_type = session_data.get('auth_type', 'session')
            logger.info("Session loaded from encrypted storage")
            return True
        except Exception as e:
            logger.warning(f"Could not load session: {e}")
            return False

    def save_session(self) -> None:
        session_data = {
            'auth_type': self.auth_type,
            'cookies': [
                {
                    'name': c.name, 'value': c.value,
                    'domain': c.domain, 'path': c.path,
                    'secure': c.secure, 'expires': c.expires
                }
                for c in self.session.cookies
            ],
            'headers': {
                k: v for k, v in self.session.headers.items()
                if k.lower() not in ('user-agent', 'content-type', 'accept', 'accept-encoding')
            }
        }
        try:
            encrypted = self._fernet.encrypt(json.dumps(session_data).encode())
            with open(self.session_file, 'wb') as f:
                f.write(encrypted)
            os.chmod(self.session_file, 0o600)
            logger.info("Session saved to encrypted storage")
        except Exception as e:
            logger.error(f"Failed to save session: {e}")

    def export_cookies_netscape(self, filepath: str) -> None:
        """Export cookies in Netscape format for external tools."""
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write("# Netscape HTTP Cookie File\n")
                for cookie in self.session.cookies:
                    domain = cookie.domain or ''
                    flag = "TRUE" if domain.startswith('.') else "FALSE"
                    path = cookie.path or '/'
                    secure = "TRUE" if cookie.secure else "FALSE"
                    expiry = str(int(cookie.expires)) if cookie.expires else "0"
                    f.write(f"{domain}\t{flag}\t{path}\t{secure}\t{expiry}\t{cookie.name}\t{cookie.value}\n")
            os.chmod(filepath, 0o600)
        except OSError as e:
            logger.error(f"Failed to export cookies: {e}")

    def login_form(self, login_url: str, username: str, password: str,
                   username_field: str = 'username', password_field: str = 'password',
                   extra_data: Optional[dict] = None, csrf_field: Optional[str] = None) -> bool:
        logger.info(f"Attempting form login to {login_url}")
        self.auth_type = 'form'
        self.auth_data = {'username': username}

        try:
            resp = self.session.get(login_url, timeout=15)
            data = {username_field: username, password_field: password}

            # Extract CSRF token
            if csrf_field:
                patterns = [
                    rf'name=["\']?{csrf_field}["\']?\s+value=["\']?([^"\'>]+)',
                    rf'value=["\']?([^"\'>]+)["\']?\s+name=["\']?{csrf_field}',
                    rf'"{csrf_field}"\s*:\s*"([^"]+)"',
                ]
                for pat in patterns:
                    match = re.search(pat, resp.text, re.IGNORECASE)
                    if match:
                        data[csrf_field] = match.group(1)
                        logger.debug(f"Found CSRF token: {data[csrf_field][:10]}...")
                        break

            if extra_data:
                data.update(extra_data)

            login_resp = self.session.post(login_url, data=data, timeout=15, allow_redirects=True)

            # Detect successful login
            if self._detect_login_success(login_resp, username):
                self.logged_in = True
                self.save_session()
                logger.info("Login successful")
                return True
            else:
                logger.warning("Login appears to have failed (no success indicator detected)")
                # Still mark as logged in if we got cookies
                if self.session.cookies:
                    self.logged_in = True
                    self.save_session()
                    return True
                return False

        except Exception as e:
            logger.error(f"Form login failed: {e}")
            return False

    def _detect_login_success(self, response: requests.Response, username: str) -> bool:
        """Heuristic: detect if login was successful."""
        # Check for common failure indicators
        fail_indicators = ['invalid', 'incorrect', 'wrong password', 'login failed',
                           'authentication failed', 'bad credentials']
        body_lower = response.text.lower()
        for indicator in fail_indicators:
            if indicator in body_lower:
                return False

        # Success if redirect happened or username appears in page
        if response.history and response.status_code == 200:
            return True
        if username.lower() in body_lower:
            return True
        if self.session.cookies:
            return True
        return response.status_code in (200, 302)

    def login_basic(self, username: str, password: str) -> None:
        self.session.auth = (username, password)
        self.auth_type = 'basic'
        self.logged_in = True
        logger.info("HTTP Basic Auth configured")

    def set_token(self, token: str, header: str = 'Authorization', scheme: str = 'Bearer') -> None:
        if scheme:
            self.session.headers[header] = f"{scheme} {token}"
        else:
            self.session.headers[header] = token
        self.auth_type = 'token'
        self.logged_in = True
        logger.info(f"Token auth configured ({header}: {scheme} ***)")

    def set_cookies(self, cookies: Dict[str, str]) -> None:
        for k, v in cookies.items():
            self.session.cookies.set(k, v)
        self.auth_type = 'cookies'
        self.logged_in = True
        self.save_session()
        logger.info(f"Cookies set ({len(cookies)} cookies)")

    def verify_session(self, check_url: Optional[str] = None) -> bool:
        """Verify session is still valid."""
        url = check_url or self.base_url
        if not url:
            return self.logged_in
        try:
            resp = self.session.get(url, timeout=10, allow_redirects=True)
            # If redirected to login page, session expired
            if 'login' in resp.url.lower() and 'login' not in url.lower():
                logger.warning("Session appears to have expired")
                self.logged_in = False
                return False
            return resp.status_code == 200
        except Exception:
            return False

    def get_auth_headers_for_tool(self) -> str:
        """Return -H flags for external tools like nuclei/ffuf."""
        headers = []
        for k, v in self.session.headers.items():
            if k.lower() in ('authorization', 'x-auth-token', 'x-api-key'):
                headers.append(f"-H '{k}: {v}'")
        return ' '.join(headers)
