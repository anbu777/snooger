"""
Rate Limiter v3.0 — token-bucket rate limiter with per-domain tracking.
Thread-safe with adaptive penalties and async compatibility.
"""
import time
import threading
from typing import Dict, Optional, Tuple

_global_limiter = None


class RateLimiter:
    """Token-bucket rate limiter with per-domain tracking."""

    def __init__(self, requests_per_second: float = 10,
                 adaptive: bool = True):
        self.rps = requests_per_second
        self.adaptive = adaptive
        self._lock = threading.Lock()
        self._domain_state: Dict[str, dict] = {}
        self._global_last = 0.0
        self._min_interval = 1.0 / max(self.rps, 0.1)

    def _get_domain(self, domain: str) -> dict:
        with self._lock:
            if domain not in self._domain_state:
                self._domain_state[domain] = {
                    'last_request': 0.0,
                    'penalty': 0.0,
                    'penalty_until': 0.0,
                }
            return self._domain_state[domain]

    def wait(self, domain: str = 'global') -> None:
        """Wait until we can make a request (thread-safe)."""
        state = self._get_domain(domain)

        with self._lock:
            now = time.time()

            # Check penalty
            if now < state['penalty_until']:
                wait_time = state['penalty_until'] - now
                self._lock.release()
                time.sleep(wait_time)
                self._lock.acquire()
                now = time.time()

            # Check rate limit
            elapsed = now - state['last_request']
            delay = self._min_interval + state['penalty']

            if elapsed < delay:
                wait_time = delay - elapsed
                self._lock.release()
                time.sleep(wait_time)
                self._lock.acquire()

            state['last_request'] = time.time()

    def penalize(self, domain: str = 'global', seconds: float = 5.0) -> None:
        """Apply a penalty delay for the domain (e.g., 429 response)."""
        state = self._get_domain(domain)
        with self._lock:
            state['penalty'] = min(state['penalty'] + 1.0, 10.0)
            state['penalty_until'] = time.time() + seconds

    def reset_penalty(self, domain: str = 'global') -> None:
        """Reset penalty for a domain (successful request)."""
        state = self._get_domain(domain)
        with self._lock:
            if state['penalty'] > 0:
                state['penalty'] = max(state['penalty'] - 0.5, 0)

    def get_stats(self) -> Dict[str, dict]:
        """Get rate limiter statistics."""
        with self._lock:
            return {
                domain: {
                    'last_request': s['last_request'],
                    'penalty': s['penalty'],
                }
                for domain, s in self._domain_state.items()
            }


def init_rate_limiter(config: dict = None) -> RateLimiter:
    """Initialize the global rate limiter from config."""
    global _global_limiter
    config = config or {}
    rps = config.get('requests_per_second', 10)
    adaptive = config.get('adaptive_delay', True)
    _global_limiter = RateLimiter(rps, adaptive)
    return _global_limiter


def get_rate_limiter() -> RateLimiter:
    """Get the global rate limiter instance."""
    global _global_limiter
    if _global_limiter is None:
        _global_limiter = RateLimiter()
    return _global_limiter
