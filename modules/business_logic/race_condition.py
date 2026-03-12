"""
Race Condition Testing — Point 17 dari perbaikan.
Tests for TOCTOU, limit bypass, double-spend, and concurrent request issues.
"""
import time
import logging
import requests
import threading
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.utils import write_json, random_user_agent
from core.rate_limiter import get_rate_limiter

logger = logging.getLogger('snooger')

# HTTP status codes indicating potential race wins
RACE_WIN_INDICATORS = {
    'status': [200, 201, 302],
    'body_keywords': [
        'success', 'created', 'confirmed', 'applied', 'redeemed',
        'transferred', 'processed', 'activated', 'unlocked', 'granted'
    ],
    'negative_keywords': [
        'already used', 'limit reached', 'exceeded', 'invalid', 'expired',
        'already redeemed', 'not allowed', 'duplicate', 'error'
    ]
}

def _fire_concurrent(session: requests.Session, method: str, url: str,
                      data: dict, headers: dict, results: list, idx: int):
    """Single thread worker for race condition test."""
    try:
        if method.upper() == 'POST':
            resp = session.post(url, data=data, headers=headers, timeout=10, verify=False)
        elif method.upper() == 'PUT':
            resp = session.put(url, json=data, headers=headers, timeout=10, verify=False)
        else:
            resp = session.get(url, headers=headers, timeout=10, verify=False)
        results[idx] = {
            'status': resp.status_code,
            'length': len(resp.content),
            'text': resp.text[:300],
            'time': resp.elapsed.total_seconds()
        }
    except Exception as e:
        results[idx] = {'status': 0, 'error': str(e), 'length': 0, 'text': '', 'time': 0}

def test_race_condition(url: str, method: str = 'POST', data = None,
                         auth=None, threads: int = 20,
                         rounds: int = 3) -> Optional[dict]:
    """
    Send N concurrent requests simultaneously to detect race condition.
    Uses 'last-byte sync' technique: open connections, send all at once.
    """
    session = auth.session if auth else requests.Session()
    session.headers['User-Agent'] = random_user_agent()
    data = data or {}
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    all_findings = []

    for round_num in range(rounds):
        results = [None] * threads
        thread_list = []

        # Create all threads but don't start yet
        for i in range(threads):
            t = threading.Thread(
                target=_fire_concurrent,
                args=(session, method, url, data, headers, results, i),
                daemon=True
            )
            thread_list.append(t)

        # Start all threads simultaneously (best approximation of last-byte sync)
        start_ts = time.time()
        for t in thread_list:
            t.start()
        for t in thread_list:
            t.join(timeout=15)
        elapsed = time.time() - start_ts

        valid_results = [r for r in results if r and r.get('status', 0) > 0]
        if not valid_results:
            continue

        # Analyze results for race wins
        success_count = 0
        status_counts: Dict[int, int] = {}
        for r in valid_results:
            s = r['status']
            status_counts[s] = status_counts.get(s, 0) + 1
            text_lower = r['text'].lower()
            is_success = (
                s in RACE_WIN_INDICATORS['status'] and
                any(kw in text_lower for kw in RACE_WIN_INDICATORS['body_keywords']) and
                not any(kw in text_lower for kw in RACE_WIN_INDICATORS['negative_keywords'])
            )
            if is_success:
                success_count += 1

        # Multiple successes = likely race condition
        if success_count >= 2:
            finding = {
                'type': 'race_condition',
                'url': url,
                'method': method,
                'severity': 'high',
                'round': round_num + 1,
                'threads': threads,
                'success_count': success_count,
                'total_responses': len(valid_results),
                'status_distribution': status_counts,
                'evidence': (f"Round {round_num+1}: {success_count}/{threads} requests succeeded "
                            f"simultaneously (total {elapsed:.2f}s)"),
                'impact': 'Potential double-spend, limit bypass, or duplicate action possible'
            }
            all_findings.append(finding)
            logger.warning(f"[RACE] Potential race condition at {url}: "
                         f"{success_count}/{threads} simultaneous successes")

        # Brief pause between rounds
        time.sleep(1.0)

    if all_findings:
        return max(all_findings, key=lambda x: x['success_count'])
    return None

def discover_race_targets(crawler_results: dict, historical_urls: list) -> List[dict]:
    """
    Identify URLs that are good candidates for race condition testing.
    Targets: coupon, voucher, transfer, redeem, purchase, payment endpoints.
    """
    race_keywords = [
        'coupon', 'voucher', 'redeem', 'promo', 'discount', 'transfer',
        'payment', 'purchase', 'order', 'checkout', 'apply', 'use',
        'withdraw', 'deposit', 'convert', 'exchange', 'claim', 'unlock',
        'register', 'signup', 'reset', 'confirm', 'vote', 'like', 'follow'
    ]

    candidates = []
    all_urls = list(set(
        crawler_results.get('visited_urls', []) + historical_urls
    ))

    for url in all_urls:
        url_lower = url.lower()
        if any(kw in url_lower for kw in race_keywords):
            # Try to identify method and payload
            method = 'POST' if any(
                kw in url_lower for kw in ['submit', 'create', 'apply', 'redeem', 'transfer']
            ) else 'GET'
            candidates.append({'url': url, 'method': method})

    # Also check forms from crawler
    for form in crawler_results.get('forms', []):
        action = form.get('action', '')
        if action and any(kw in action.lower() for kw in race_keywords):
            data = {inp.get('name', ''): inp.get('value', 'test')
                   for inp in form.get('inputs', [])
                   if inp.get('name')}
            candidates.append({
                'url': action,
                'method': form.get('method', 'POST').upper(),
                'data': data
            })

    logger.info(f"Race condition candidates: {len(candidates)} endpoints")
    return candidates

def run_race_condition_tests(workspace_dir: str, auth=None,
                              crawler_results = None,
                              historical_urls = None) -> List[dict]:
    """Run race condition tests on all identified candidates."""
    crawler_results = crawler_results or {}
    historical_urls = historical_urls or []

    candidates = discover_race_targets(crawler_results, historical_urls)
    if not candidates:
        logger.info("No race condition candidates found")
        return []

    findings = []
    for candidate in candidates[:10]:  # Limit to avoid DoS
        url = candidate['url']
        method = candidate.get('method', 'POST')
        data = candidate.get('data', {})

        logger.info(f"Testing race condition: {method} {url}")
        finding = test_race_condition(url, method=method, data=data,
                                       auth=auth, threads=15, rounds=2)
        if finding:
            findings.append(finding)

    if findings:
        write_json(f"{workspace_dir}/race_condition_findings.json", findings)
        logger.warning(f"Race condition: {len(findings)} potential vulnerabilities found")

    return findings
