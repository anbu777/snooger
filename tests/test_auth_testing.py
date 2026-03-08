"""Unit tests for JWT vulnerability detection."""
import sys, os, base64, json, hmac, hashlib
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import unittest
from modules.auth.auth_testing import test_jwt_vulnerabilities, _encode_jwt_part

def _make_jwt(header: dict, payload: dict, secret: str = 'secret',
              alg: str = 'HS256') -> str:
    h = _encode_jwt_part(header)
    p = _encode_jwt_part(payload)
    signing = f"{h}.{p}".encode()
    hash_fn = {'HS256': hashlib.sha256, 'HS384': hashlib.sha384}.get(alg, hashlib.sha256)
    sig = hmac.new(secret.encode(), signing, hash_fn).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b'=').decode()
    return f"{h}.{p}.{sig_b64}"

class TestJWTVulnerabilities(unittest.TestCase):
    def test_weak_secret_cracked(self):
        token = _make_jwt({'alg': 'HS256', 'typ': 'JWT'},
                          {'sub': '1', 'role': 'user'}, secret='secret')
        findings = test_jwt_vulnerabilities(token)
        weak_secret = [f for f in findings if f['type'] == 'jwt_weak_secret']
        self.assertTrue(len(weak_secret) > 0)
        self.assertEqual(weak_secret[0]['secret'], 'secret')

    def test_none_alg_forged(self):
        token = _make_jwt({'alg': 'HS256', 'typ': 'JWT'},
                          {'sub': '1'}, secret='strongpassword')
        findings = test_jwt_vulnerabilities(token)
        none_alg = [f for f in findings if f['type'] == 'jwt_none_algorithm']
        self.assertTrue(len(none_alg) > 0)
        # Verify forged token has empty signature
        forged = none_alg[0]['token_to_try']
        self.assertTrue(forged.endswith('.'))

    def test_privilege_claims_detected(self):
        token = _make_jwt({'alg': 'HS256', 'typ': 'JWT'},
                          {'sub': '1', 'role': 'user', 'is_admin': False},
                          secret='secret')
        findings = test_jwt_vulnerabilities(token)
        priv = [f for f in findings if f['type'] == 'jwt_privilege_claims']
        self.assertTrue(len(priv) > 0)
        self.assertIn('role', priv[0]['claims'])

    def test_rs256_confusion_candidate(self):
        # Build a fake RS256 token (signature will be wrong but structure matters)
        h = _encode_jwt_part({'alg': 'RS256', 'typ': 'JWT'})
        p = _encode_jwt_part({'sub': '1'})
        token = f"{h}.{p}.fakesignature"
        findings = test_jwt_vulnerabilities(token)
        confusion = [f for f in findings if f['type'] == 'jwt_alg_confusion_candidate']
        self.assertTrue(len(confusion) > 0)

    def test_invalid_token_returns_empty(self):
        findings = test_jwt_vulnerabilities("not.a.valid.jwt.token.here")
        self.assertEqual(findings, [])

if __name__ == '__main__':
    unittest.main()
