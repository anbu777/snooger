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

    def test_url_extracts_domain(self):
        result = sanitize_domain('https://example.com')
        self.assertEqual(result, 'example.com')

    def test_strips_path(self):
        result = sanitize_domain('example.com/path/to/page')
        self.assertEqual(result, 'example.com')

    def test_space_in_domain(self):
        # Current sanitize_domain strips and splits, handles gracefully
        result = sanitize_domain('exa mple.com')
        self.assertIsInstance(result, str)

class TestSanitizeURL(unittest.TestCase):
    def test_valid_url(self):
        url = sanitize_url('https://example.com/path?q=1')
        self.assertEqual(url, 'https://example.com/path?q=1')

    def test_no_protocol_adds_https(self):
        url = sanitize_url('example.com/path')
        self.assertEqual(url, 'https://example.com/path')

    def test_http_preserved(self):
        url = sanitize_url('http://example.com')
        self.assertEqual(url, 'http://example.com')

    def test_strips_whitespace(self):
        url = sanitize_url('  https://example.com  ')
        self.assertEqual(url, 'https://example.com')

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

    def test_blank_value(self):
        base, params = parse_url_params('https://example.com/page?q=')
        self.assertEqual(base, 'https://example.com/page')
        self.assertIn('q', params)

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
        # Returns default (empty dict) for missing files
        self.assertIsNotNone(result)

    def test_missing_file_custom_default(self):
        result = load_json_file('/nonexistent/file.json', default=[])
        self.assertEqual(result, [])

    def test_invalid_json(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write('not valid json {{{')
            fname = f.name
        result = load_json_file(fname)
        os.unlink(fname)
        # Returns default (empty dict) for invalid json
        self.assertIsNotNone(result)

if __name__ == '__main__':
    unittest.main()
