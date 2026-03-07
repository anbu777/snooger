import os
import json
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

def extract_ids_from_urls(urls):
    """
    Extract potential ID patterns from URLs.
    Returns dict: {url_pattern: list_of_ids_found}
    """
    patterns = {}
    for url in urls:
        parsed = urlparse(url)
        # Check path segments for numbers
        path_segments = parsed.path.split('/')
        for i, seg in enumerate(path_segments):
            if seg.isdigit():
                new_segments = path_segments.copy()
                new_segments[i] = '{id}'
                pattern = '/'.join(new_segments)
                if pattern not in patterns:
                    patterns[pattern] = []
                patterns[pattern].append(seg)
        # Check query parameters
        query_params = parse_qs(parsed.query)
        for param, values in query_params.items():
            for val in values:
                if val.isdigit():
                    pattern = f"{param}={{id}}"
                    if pattern not in patterns:
                        patterns[pattern] = []
                    patterns[pattern].append(val)
    return patterns

def test_idor_on_pattern(auth, base_url, pattern, ids, param_name=None, path_segment_index=None):
    """
    Test IDOR by replacing an ID with another.
    If param_name, it's query parameter; else path segment.
    """
    findings = []
    if len(ids) < 2:
        return findings

    victim_id = ids[0]
    attacker_ids = ids[1:3]

    # Construct baseline URL
    if param_name:
        base_parsed = urlparse(base_url)
        query = parse_qs(base_parsed.query)
        if param_name not in query:
            return findings
        query[param_name] = [victim_id]
        new_query = urlencode(query, doseq=True)
        victim_url = urlunparse(base_parsed._replace(query=new_query))
    else:
        path_segments = base_url.split('/')
        if path_segment_index is None:
            for i, seg in enumerate(path_segments):
                if seg == '{id}':
                    path_segment_index = i
                    break
        if path_segment_index is None:
            return findings
        path_segments[path_segment_index] = victim_id
        victim_url = '/'.join(path_segments)

    # Fetch victim's page with attacker's session
    resp_victim = auth.get(victim_url)
    if resp_victim.status_code != 200:
        return findings

    for attacker_id in attacker_ids:
        if param_name:
            query[param_name] = [attacker_id]
            new_query = urlencode(query, doseq=True)
            attacker_url = urlunparse(base_parsed._replace(query=new_query))
        else:
            path_segments[path_segment_index] = attacker_id
            attacker_url = '/'.join(path_segments)

        resp_attacker = auth.get(attacker_url)
        if resp_attacker.status_code == 200 and len(resp_attacker.text) > 0:
            if resp_attacker.text != resp_victim.text:
                finding = {
                    'type': 'IDOR',
                    'url': attacker_url,
                    'victim_url': victim_url,
                    'victim_id': victim_id,
                    'attacker_id': attacker_id,
                    'evidence': f"Accessed resource of ID {attacker_id} with session of user who owns ID {victim_id}",
                    'status_code': resp_attacker.status_code
                }
                findings.append(finding)
    return findings

def scan_idor(auth, urls, workspace_dir):
    """
    Main function to scan for IDOR vulnerabilities.
    """
    print("[IDOR] Scanning for potential IDOR...")
    patterns = extract_ids_from_urls(urls)
    findings = []
    for pattern, ids in patterns.items():
        if '?{id}' in pattern or '=' in pattern:
            # Query parameter pattern
            param_name = pattern.split('=')[0]
            sample_url = None
            for url in urls:
                if param_name in url and str(ids[0]) in url:
                    sample_url = url
                    break
            if sample_url:
                res = test_idor_on_pattern(auth, sample_url, pattern, ids, param_name=param_name)
                findings.extend(res)
        else:
            # Path pattern
            sample_url = None
            for url in urls:
                if pattern.replace('{id}', str(ids[0])) in url:
                    sample_url = url
                    break
            if sample_url:
                res = test_idor_on_pattern(auth, sample_url, pattern, ids)
                findings.extend(res)

    if findings:
        with open(os.path.join(workspace_dir, 'idor_findings.json'), 'w') as f:
            json.dump(findings, f, indent=2)
    print(f"[IDOR] Found {len(findings)} potential IDOR vulnerabilities.")
    return findings