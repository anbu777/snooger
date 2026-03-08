"""Unit tests for race condition detection logic."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import unittest
from modules.business_logic.race_condition import discover_race_targets

class TestDiscoverRaceTargets(unittest.TestCase):
    def test_finds_coupon_urls(self):
        crawler = {
            'visited_urls': [
                'https://shop.example.com/coupon/apply',
                'https://shop.example.com/products',
                'https://shop.example.com/redeem/voucher',
            ],
            'forms': []
        }
        candidates = discover_race_targets(crawler, [])
        urls = [c['url'] for c in candidates]
        self.assertIn('https://shop.example.com/coupon/apply', urls)
        self.assertIn('https://shop.example.com/redeem/voucher', urls)
        self.assertNotIn('https://shop.example.com/products', urls)

    def test_finds_form_candidates(self):
        crawler = {
            'visited_urls': [],
            'forms': [
                {
                    'action': 'https://example.com/payment/submit',
                    'method': 'POST',
                    'inputs': [{'name': 'amount', 'type': 'text', 'value': '100'}]
                }
            ]
        }
        candidates = discover_race_targets(crawler, [])
        self.assertTrue(any('payment' in c['url'] for c in candidates))

if __name__ == '__main__':
    unittest.main()
