"""
API Security Testing: REST, GraphQL, OpenAPI/Swagger parsing, versioning abuse.
"""
import re
import json
import logging
import requests
from typing import List, Dict, Optional
from core.utils import write_json, random_user_agent
from core.rate_limiter import get_rate_limiter

logger = logging.getLogger('snooger')

COMMON_API_PATHS = [
    '/api', '/api/v1', '/api/v2', '/api/v3', '/v1', '/v2',
    '/rest', '/rest/v1', '/graphql', '/query', '/gql',
    '/swagger.json', '/swagger/v1/swagger.json', '/openapi.json',
    '/api-docs', '/api/docs', '/docs/api', '/_api',
    '/api/swagger', '/api/openapi', '/spec.json',
    '/api/v1/users', '/api/v1/admin', '/api/v1/health',
]

GRAPHQL_INTROSPECTION = """
{
  __schema {
    types {
      name
      kind
      fields {
        name
        type { name kind }
      }
    }
    queryType { name }
    mutationType { name }
    subscriptionType { name }
  }
}
"""

def discover_api_endpoints(base_url: str, auth=None) -> List[dict]:
    """Discover API endpoints via common paths and content negotiation."""
    session = auth.session if auth else requests.Session()
    session.headers.setdefault('User-Agent', random_user_agent())
    rl = get_rate_limiter()
    found = []
    base = base_url.rstrip('/')

    for path in COMMON_API_PATHS:
        url = f"{base}{path}"
        try:
            rl.wait(base_url)
            resp = session.get(url, timeout=8, verify=False,
                               headers={'Accept': 'application/json'})
            if resp.status_code in (200, 201, 401, 403):
                ct = resp.headers.get('content-type', '')
                endpoint = {
                    'url': url,
                    'status': resp.status_code,
                    'content_type': ct,
                    'length': len(resp.content),
                }
                if 'json' in ct:
                    try:
                        endpoint['schema_preview'] = list(resp.json().keys())[:5] if isinstance(resp.json(), dict) else 'array'
                    except Exception:
                        pass
                found.append(endpoint)
                if resp.status_code == 200:
                    logger.info(f"  API endpoint: {url} [{resp.status_code}]")
        except Exception as e:
            logger.debug(f"API discovery error {url}: {e}")

    return found

def parse_openapi_spec(spec_url: str, auth=None) -> dict:
    """Parse OpenAPI/Swagger spec and extract all testable endpoints."""
    session = auth.session if auth else requests.Session()
    rl = get_rate_limiter()
    endpoints = []

    try:
        rl.wait(spec_url)
        resp = session.get(spec_url, timeout=15, verify=False)
        if resp.status_code != 200:
            return {}
        spec = resp.json()
    except Exception as e:
        logger.warning(f"Cannot fetch OpenAPI spec from {spec_url}: {e}")
        return {}

    base_path = spec.get('basePath', '') or ''
    servers = spec.get('servers', [])
    if servers:
        base_path = servers[0].get('url', '')

    paths = spec.get('paths', {})
    for path, methods in paths.items():
        for method, details in methods.items():
            if method.upper() not in ('GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'):
                continue
            endpoint = {
                'path': path,
                'method': method.upper(),
                'full_url': f"{base_path}{path}",
                'summary': details.get('summary', ''),
                'parameters': details.get('parameters', []),
                'requires_auth': bool(details.get('security')),
                'tags': details.get('tags', []),
            }
            # Flag interesting endpoints
            if any(kw in path.lower() for kw in ['admin', 'internal', 'debug', 'secret', 'token']):
                endpoint['interesting'] = True
            endpoints.append(endpoint)

    result = {
        'spec_url': spec_url,
        'total_endpoints': len(endpoints),
        'endpoints': endpoints,
        'auth_required_count': sum(1 for e in endpoints if e.get('requires_auth')),
        'interesting_endpoints': [e for e in endpoints if e.get('interesting')],
    }
    logger.info(f"OpenAPI spec parsed: {len(endpoints)} endpoints found")
    return result

def test_api_versioning_bypass(base_url: str, auth=None) -> List[dict]:
    """Test API version downgrade for access control bypass."""
    session = auth.session if auth else requests.Session()
    rl = get_rate_limiter()
    findings = []

    # Find current version
    version_patterns = ['/api/v2/', '/api/v3/', '/v2/', '/v3/']
    for vp in version_patterns:
        if vp in base_url:
            # Try older versions
            for old_ver in ['v1', 'v0', 'beta', 'alpha']:
                old_url = re.sub(r'/v\d+/', f'/{old_ver}/', base_url)
                try:
                    rl.wait(old_url)
                    resp = session.get(old_url, timeout=8, verify=False)
                    if resp.status_code == 200:
                        findings.append({
                            'type': 'api_version_bypass',
                            'current_url': base_url,
                            'bypass_url': old_url,
                            'severity': 'medium',
                            'evidence': f"Old API version accessible: {old_url}"
                        })
                        logger.warning(f"API version bypass: {old_url}")
                except Exception:
                    pass

    return findings

def test_graphql(base_url: str, auth=None) -> dict:
    """Test GraphQL endpoint for introspection, batching, and field suggestions."""
    session = auth.session if auth else requests.Session()
    rl = get_rate_limiter()
    findings = []
    schema = None

    graphql_urls = [f"{base_url}/graphql", f"{base_url}/gql",
                    f"{base_url}/api/graphql", f"{base_url}/query"]

    for gql_url in graphql_urls:
        try:
            # Test introspection
            rl.wait(gql_url)
            resp = session.post(
                gql_url,
                json={'query': GRAPHQL_INTROSPECTION},
                headers={'Content-Type': 'application/json'},
                timeout=10, verify=False
            )
            if resp.status_code == 200:
                data = resp.json()
                if 'data' in data and '__schema' in data.get('data', {}):
                    schema = data['data']['__schema']
                    types = [t['name'] for t in schema.get('types', [])
                             if not t['name'].startswith('__')]
                    findings.append({
                        'type': 'graphql_introspection_enabled',
                        'url': gql_url,
                        'severity': 'medium',
                        'evidence': f"Schema exposed: {len(types)} types",
                        'types': types[:20],
                    })
                    logger.warning(f"GraphQL introspection enabled: {gql_url}")

                # Test batch attack
                batch_query = [
                    {'query': '{ __typename }'},
                    {'query': '{ __typename }'},
                ] * 5
                rl.wait(gql_url)
                batch_resp = session.post(
                    gql_url, json=batch_query,
                    headers={'Content-Type': 'application/json'},
                    timeout=10, verify=False
                )
                if batch_resp.status_code == 200 and isinstance(batch_resp.json(), list):
                    findings.append({
                        'type': 'graphql_batching_enabled',
                        'url': gql_url,
                        'severity': 'low',
                        'evidence': 'Batch queries accepted (DoS risk, brute force amplification)'
                    })

                break
        except Exception as e:
            logger.debug(f"GraphQL test error {gql_url}: {e}")

    return {'url': gql_url if graphql_urls else '', 'findings': findings, 'schema': schema}

def test_api_key_in_response(url: str, auth=None) -> List[dict]:
    """Detect API key leakage in response headers and body."""
    session = auth.session if auth else requests.Session()
    rl = get_rate_limiter()
    findings = []

    sensitive_headers = [
        'x-api-key', 'x-auth-token', 'x-secret', 'api-key',
        'authorization', 'x-access-token', 'x-internal-token',
    ]

    try:
        rl.wait(url)
        resp = session.get(url, timeout=8, verify=False)
        for header in resp.headers:
            if any(sh in header.lower() for sh in sensitive_headers):
                if header.lower() not in ('authorization',):  # Expected on requests, not responses
                    findings.append({
                        'type': 'api_key_in_response_header',
                        'url': url,
                        'header': header,
                        'value': resp.headers[header][:30] + '...',
                        'severity': 'high',
                        'evidence': f"Sensitive header in response: {header}"
                    })

        # Check body for API keys
        from modules.javascript.js_analyzer import extract_secrets
        secrets = extract_secrets(resp.text, url)
        for s in secrets:
            if s.get('severity') in ('critical', 'high'):
                findings.append({
                    'type': 'api_key_in_response_body',
                    'url': url,
                    'secret_type': s['type'],
                    'severity': s['severity'],
                    'evidence': s['context'][:100]
                })
    except Exception as e:
        logger.debug(f"API key detection error: {e}")

    return findings

def run_api_tests(target: str, workspace_dir: str, auth=None,
                  crawler_results: dict = None) -> dict:
    """Run comprehensive API security tests."""
    logger.info(f"Starting API security testing for {target}")
    results = {
        'endpoints_discovered': [],
        'openapi_analysis': {},
        'graphql_findings': {},
        'version_bypass': [],
        'api_key_leakage': [],
    }

    # Discover endpoints
    endpoints = discover_api_endpoints(target, auth)
    results['endpoints_discovered'] = endpoints

    # Check for OpenAPI/Swagger spec
    spec_urls = [e['url'] for e in endpoints
                 if any(kw in e['url'] for kw in ['swagger', 'openapi', 'api-docs'])]
    for spec_url in spec_urls[:3]:
        spec = parse_openapi_spec(spec_url, auth)
        if spec:
            results['openapi_analysis'] = spec
            break

    # GraphQL testing
    gql_results = test_graphql(target, auth)
    results['graphql_findings'] = gql_results

    # API versioning
    if crawler_results:
        for url in crawler_results.get('api_endpoints', [])[:10]:
            bypass = test_api_versioning_bypass(url, auth)
            results['version_bypass'].extend(bypass)

    # API key in responses
    for endpoint in endpoints[:10]:
        if endpoint.get('status') == 200:
            leakage = test_api_key_in_response(endpoint['url'], auth)
            results['api_key_leakage'].extend(leakage)

    # Consolidate findings count
    total_findings = (
        len(gql_results.get('findings', [])) +
        len(results['version_bypass']) +
        len(results['api_key_leakage'])
    )
    if total_findings > 0:
        logger.warning(f"API tests: {total_findings} potential issues found")

    write_json(os.path.join(workspace_dir, 'api_findings.json'), results)
    return results
