"""Unit tests for IDOR detection logic."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import unittest
from modules.business_logic.idor import detect_id_type, increment_id, extract_ids_from_urls

class TestDetectIdType(unittest.TestCase):
    def test_numeric(self):
        self.assertEqual(detect_id_type('123'), 'numeric')
        self.assertEqual(detect_id_type('1'), 'numeric')
        self.assertIsNone(detect_id_type('abc'))

    def test_uuid(self):
        self.assertEqual(detect_id_type('550e8400-e29b-41d4-a716-446655440000'), 'uuid')
        self.assertIsNone(detect_id_type('not-a-uuid'))

    def test_hash_md5(self):
        self.assertEqual(detect_id_type('d41d8cd98f00b204e9800998ecf8427e'), 'hash_md5')

    def test_base64(self):
        import base64
        encoded = base64.b64encode(b'user:123').decode()
        self.assertEqual(detect_id_type(encoded), 'base64')

class TestIncrementId(unittest.TestCase):
    def test_numeric(self):
        alts = increment_id('5', 'numeric')
        self.assertIn('4', alts)
        self.assertIn('6', alts)

    def test_uuid_alternatives(self):
        uuid_val = '550e8400-e29b-41d4-a716-446655440000'
        alts = increment_id(uuid_val, 'uuid')
        self.assertGreater(len(alts), 0)

class TestExtractIdsFromUrls(unittest.TestCase):
    def test_path_id(self):
        urls = ['https://example.com/users/123/profile']
        results = extract_ids_from_urls(urls)
        found = [(url, val, typ) for url, val, typ in results if val == '123']
        self.assertTrue(len(found) > 0)

    def test_query_param_id(self):
        urls = ['https://example.com/api?user_id=456&other=abc']
        results = extract_ids_from_urls(urls)
        found = [(url, val, typ) for url, val, typ in results if val == '456']
        self.assertTrue(len(found) > 0)

if __name__ == '__main__':
    unittest.main()
