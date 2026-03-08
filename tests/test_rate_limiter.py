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
        self.assertGreater(rl._penalty['slowsite.com'], 0)

    def test_penalty_reset(self):
        rl = RateLimiter(requests_per_second=100, adaptive=True)
        rl.penalize('site.com', 5.0)
        initial_penalty = rl._penalty['site.com']
        rl.reset_penalty('site.com')
        self.assertLess(rl._penalty['site.com'], initial_penalty)

if __name__ == '__main__':
    unittest.main()
