"""Unit tests for ScopeManager."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import unittest
from modules.scope.scope_manager import ScopeManager

class TestScopeManager(unittest.TestCase):
    def setUp(self):
        self.scope = ScopeManager()

    def test_basic_in_scope(self):
        self.scope.add_domain('example.com')
        self.assertTrue(self.scope.is_in_scope('http://example.com/page'))
        self.assertTrue(self.scope.is_in_scope('https://example.com'))

    def test_out_of_scope(self):
        self.scope.add_domain('example.com')
        self.scope.add_out_of_scope('admin.example.com')
        self.assertFalse(self.scope.is_in_scope('https://admin.example.com'))
        self.assertTrue(self.scope.is_in_scope('https://app.example.com'))

    def test_wildcard_scope(self):
        self.scope.in_scope = ['*.example.com']
        self.scope._compile_patterns()
        self.assertTrue(self.scope.is_in_scope('https://sub.example.com'))
        self.assertTrue(self.scope.is_in_scope('https://deep.sub.example.com'))

    def test_empty_scope_allows_all(self):
        self.assertTrue(self.scope.is_in_scope('https://anything.com'))

    def test_filter_targets(self):
        self.scope.add_domain('example.com')
        self.scope.add_out_of_scope('bad.example.com')
        targets = ['https://example.com', 'https://bad.example.com', 'https://other.com']
        filtered = self.scope.filter_targets(targets)
        self.assertIn('https://example.com', filtered)
        self.assertNotIn('https://bad.example.com', filtered)

class TestScopeManagerJSON(unittest.TestCase):
    def test_plain_text_scope(self):
        import tempfile
        scope = ScopeManager()
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("example.com\n*.example.com\n!bad.example.com\n")
            fname = f.name
        scope.load_from_file(fname)
        os.unlink(fname)
        self.assertIn('example.com', scope.in_scope)
        self.assertIn('bad.example.com', scope.out_of_scope)

if __name__ == '__main__':
    unittest.main()
