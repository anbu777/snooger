import time
import threading
import logging
from collections import defaultdict

logger = logging.getLogger('snooger')

class RateLimiter:
    """
    Token-bucket rate limiter per domain.
    Thread-safe implementation.
    """
    def __init__(self, requests_per_second: float = 5.0,
                 adaptive: bool = True, max_retries: int = 3):
        self.rps = requests_per_second
        self.min_interval = 1.0 / requests_per_second if requests_per_second > 0 else 0
        self.adaptive = adaptive
        self.max_retries = max_retries
        self._lock = threading.Lock()
        self._last_request = defaultdict(float)
        self._penalty = defaultdict(float)  # extra delay per domain

    def wait(self, domain: str = 'global') -> None:
        """Block until it's safe to make another request to domain."""
        with self._lock:
            now = time.time()
            last = self._last_request[domain]
            penalty = self._penalty[domain]
            required_wait = self.min_interval + penalty
            elapsed = now - last
            if elapsed < required_wait:
                sleep_time = required_wait - elapsed
                time.sleep(sleep_time)
            self._last_request[domain] = time.time()

    def penalize(self, domain: str, extra_delay: float = 5.0) -> None:
        """Add extra delay for domain after rate limiting response."""
        if self.adaptive:
            self._penalty[domain] = min(
                self._penalty[domain] + extra_delay,
                60.0  # max 60s penalty
            )
            logger.warning(f"Rate limit hit for {domain}. Penalty: {self._penalty[domain]:.1f}s")

    def reset_penalty(self, domain: str) -> None:
        """Reduce penalty gradually on successful requests."""
        if self._penalty[domain] > 0:
            self._penalty[domain] = max(0, self._penalty[domain] - 0.5)

# Global rate limiter instance
_global_limiter: RateLimiter = None

def init_rate_limiter(config: dict) -> RateLimiter:
    global _global_limiter
    rl_config = config.get('rate_limit', {})
    _global_limiter = RateLimiter(
        requests_per_second=rl_config.get('requests_per_second', 5),
        adaptive=rl_config.get('adaptive_delay', True),
        max_retries=rl_config.get('max_retries', 3)
    )
    return _global_limiter

def get_rate_limiter() -> RateLimiter:
    global _global_limiter
    if _global_limiter is None:
        _global_limiter = RateLimiter()
    return _global_limiter
