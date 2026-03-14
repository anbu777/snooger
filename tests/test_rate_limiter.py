"""Unit tests for RateLimiter."""
import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import unittest
from core.rate_limiter import RateLimiter

class TestRateLimiter(unittest.TestCase):
    def test_basic_rate_limiting(self):
        rl = RateLimiter(requests_per_second=10)
        start = time.time()
        for _ in range(5):
            rl.wait('test.com')
        elapsed = time.time() - start
        self.assertGreater(elapsed, 0.3)

    def test_adaptive_penalty(self):
        rl = RateLimiter(requests_per_second=100, adaptive=True)
        rl.penalize('slowsite.com', 5.0)
        state = rl._domain_state.get('slowsite.com', {})
        self.assertGreater(state.get('penalty', 0), 0)

    def test_penalty_reset(self):
        rl = RateLimiter(requests_per_second=100, adaptive=True)
        rl.penalize('site.com', 5.0)
        initial_penalty = rl._domain_state['site.com']['penalty']
        rl.reset_penalty('site.com')
        self.assertLess(rl._domain_state['site.com']['penalty'], initial_penalty)

    def test_get_stats(self):
        rl = RateLimiter(requests_per_second=10)
        rl.wait('stats.com')
        stats = rl.get_stats()
        self.assertIn('stats.com', stats)

if __name__ == '__main__':
    unittest.main()
