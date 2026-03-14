"""Unit tests for ScopeManager (core version used by snooger.py)."""
import sys, os, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import unittest
from core.scope_manager import ScopeManager

class TestScopeManager(unittest.TestCase):
    def setUp(self):
        self.scope = ScopeManager()

    def test_basic_in_scope(self):
        self.scope.add_target('example.com')
        self.assertTrue(self.scope.is_in_scope('http://example.com/page'))
        self.assertTrue(self.scope.is_in_scope('https://example.com'))

    def test_subdomain_in_scope(self):
        self.scope.add_target('*.example.com')
        self.assertTrue(self.scope.is_in_scope('https://sub.example.com'))

    def test_out_of_scope_domain(self):
        self.scope.add_target('example.com')
        self.assertFalse(self.scope.is_in_scope('https://malicious.com'))

    def test_empty_scope_strict(self):
        # Default strict=True, empty scope should block
        self.scope.strict = True
        self.scope._loaded = True
        self.assertFalse(self.scope.is_in_scope('https://anything.com'))

    def test_empty_scope_not_strict(self):
        self.scope.strict = False
        self.scope._loaded = True
        self.assertTrue(self.scope.is_in_scope('https://anything.com'))

    def test_filter_in_scope(self):
        self.scope.add_target('example.com')
        targets = ['https://example.com', 'https://other.com']
        filtered = self.scope.filter_in_scope(targets)
        self.assertIn('https://example.com', filtered)
        self.assertNotIn('https://other.com', filtered)

    def test_load_plain_text(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("example.com\n*.test.com\n!bad.example.com\n")
            fname = f.name
        scope = ScopeManager()
        scope.load_from_file(fname)
        os.unlink(fname)
        self.assertIn('example.com', scope.include_patterns)
        self.assertIn('bad.example.com', scope.exclude_patterns)

if __name__ == '__main__':
    unittest.main()
