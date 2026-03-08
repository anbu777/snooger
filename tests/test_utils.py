"""Unit tests for core utilities."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import unittest
from core.utils import sanitize_domain, sanitize_url, parse_url_params, load_json_file
import tempfile, json

class TestSanitizeDomain(unittest.TestCase):
    def test_valid_domain(self):
        self.assertEqual(sanitize_domain('example.com'), 'example.com')
        self.assertEqual(sanitize_domain('sub.example.com'), 'sub.example.com')
        self.assertEqual(sanitize_domain('https://example.com'), 'https://example.com')

    def test_invalid_domain(self):
        with self.assertRaises(ValueError):
            sanitize_domain('exa mple.com')
        with self.assertRaises(ValueError):
            sanitize_domain('ex&ample.com')

class TestSanitizeURL(unittest.TestCase):
    def test_valid_url(self):
        url = sanitize_url('https://example.com/path?q=1')
        self.assertEqual(url, 'https://example.com/path?q=1')

    def test_no_protocol(self):
        with self.assertRaises(ValueError):
            sanitize_url('example.com/path')

    def test_blocks_metadata(self):
        with self.assertRaises(ValueError):
            sanitize_url('http://169.254.169.254/latest/')

class TestParseURLParams(unittest.TestCase):
    def test_with_params(self):
        base, params = parse_url_params('https://example.com/page?id=1&name=test')
        self.assertEqual(base, 'https://example.com/page')
        self.assertEqual(params['id'], '1')
        self.assertEqual(params['name'], 'test')

    def test_no_params(self):
        base, params = parse_url_params('https://example.com/page')
        self.assertEqual(base, 'https://example.com/page')
        self.assertEqual(params, {})

class TestLoadJsonFile(unittest.TestCase):
    def test_valid_json(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({'key': 'value'}, f)
            fname = f.name
        result = load_json_file(fname)
        os.unlink(fname)
        self.assertEqual(result['key'], 'value')

    def test_missing_file(self):
        result = load_json_file('/nonexistent/file.json')
        self.assertIsNone(result)

    def test_invalid_json(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write('not valid json {{{')
            fname = f.name
        result = load_json_file(fname)
        os.unlink(fname)
        self.assertIsNone(result)

if __name__ == '__main__':
    unittest.main()
