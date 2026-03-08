"""SSRF Validator"""
import logging
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

logger = logging.getLogger('snooger')

INTERNAL_ENDPOINTS = [
    'http://169.254.169.254/latest/meta-data/',
    'http://localhost/',
    'http://127.0.0.1/',
]

CLOUD_INDICATORS = ['ami-id', 'instance-id', 'iam', 'computeMetadata', 'azure']


def quick_ssrf_test(url: str, workspace_dir: str) -> dict:
    """Quick SSRF test by injecting internal URLs into parameters."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    url_params = {k for k, v in params.items()
                  if any(kw in k.lower() for kw in ('url', 'uri', 'link', 'src', 'dest', 'redirect', 'host', 'server', 'callback', 'path'))}

    if not url_params:
        return {'validated': False}

    session = requests.Session()
    for param in url_params:
        for endpoint in INTERNAL_ENDPOINTS:
            test_params = {k: v[0] for k, v in params.items()}
            test_params[param] = endpoint
            test_url = urlunparse(parsed._replace(query=urlencode(test_params)))
            try:
                resp = session.get(test_url, timeout=10)
                for indicator in CLOUD_INDICATORS:
                    if indicator.lower() in resp.text.lower():
                        return {
                            'validated': True,
                            'type': 'SSRF',
                            'url': url,
                            'parameter': param,
                            'payload': endpoint,
                            'evidence': f'Cloud metadata indicator: {indicator}',
                            'severity': 'critical',
                        }
            except Exception:
                continue

    return {'validated': False}
