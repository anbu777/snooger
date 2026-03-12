"""
Advanced False Positive Reduction & Confidence Scoring Module
Implements multi-layered verification to minimize false positives.
"""
import re
import time
import logging
import difflib
import requests
from typing import List, Dict, Optional, Tuple
from urllib.parse import urlparse, parse_qs
from core.utils import random_user_agent
from core.rate_limiter import get_rate_limiter

logger = logging.getLogger('snooger')


class ConfidenceScorer:
    """Assigns confidence scores to findings based on evidence strength."""

    SEVERITY_BASE = {
        'critical': 50,
        'high': 40,
        'medium': 30,
        'low': 20,
        'info': 10,
    }

    def score(self, finding: dict) -> int:
        """Calculate confidence score (0-100) for a finding."""
        score = self.SEVERITY_BASE.get(finding.get('severity', 'info'), 10)

        # Evidence quality bonuses
        evidence = finding.get('evidence', '')
        if evidence and len(evidence) > 50:
            score += 10

        # Confirmed via multiple methods
        if finding.get('confirmed'):
            score += 20
        if finding.get('confirmed_twice'):
            score += 15

        # Specific indicators found
        if finding.get('db_type'):
            score += 10
        if finding.get('payload') and finding.get('evidence'):
            score += 5

        # Penalty for weak evidence
        if 'candidate' in finding.get('type', '').lower():
            score -= 15
        if 'potential' in finding.get('evidence', '').lower():
            score -= 10

        # Existing confidence override
        existing = finding.get('confidence')
        if existing:
            score = int((score + existing) / 2)

        return max(0, min(100, score))


class FalsePositiveFilter:
    """Multi-layer false positive detection and filtering."""

    def __init__(self, session: requests.Session = None):
        self.session = session or requests.Session()
        self.session.headers.setdefault('User-Agent', random_user_agent())
        self.rl = get_rate_limiter()
        self.scorer = ConfidenceScorer()
        self._baseline_cache: Dict[str, Tuple[int, int, str]] = {}

    def _get_baseline(self, url: str) -> Tuple[int, int, str]:
        """Get cached baseline response for a URL."""
        if url not in self._baseline_cache:
            try:
                self.rl.wait(url)
                resp = self.session.get(url, timeout=10, verify=False)
                self._baseline_cache[url] = (
                    resp.status_code,
                    len(resp.content),
                    resp.text[:3000]
                )
            except Exception:
                self._baseline_cache[url] = (0, 0, '')
        return self._baseline_cache[url]

    def verify_sqli(self, finding: dict) -> dict:
        """Verify SQL injection finding with additional checks."""
        url = finding.get('url', '')
        param = finding.get('parameter', '')
        subtype = finding.get('subtype', '')

        if not url or not param:
            finding['fp_verified'] = False
            return finding

        if subtype == 'error_based':
            # Re-test with a benign value that shouldn't trigger errors
            bl_status, bl_len, bl_text = self._get_baseline(url)

            # Try with normal numeric values - if they ALSO trigger DB errors, it's FP
            benign_values = ['1', 'test', '0', 'abc123']
            db_error_patterns = [
                r'SQL syntax', r'mysql', r'postgresql', r'oracle', r'sqlite',
                r'ODBC', r'ORA-\d{4}', r'PG::',
            ]

            errors_on_benign = 0
            for val in benign_values:
                try:
                    parsed = urlparse(url)
                    params = parse_qs(parsed.query)
                    params[param] = [val]
                    test_url = url.split('?')[0] + '?' + '&'.join(
                        f"{k}={v[0]}" for k, v in params.items()
                    )
                    self.rl.wait(url)
                    resp = self.session.get(test_url, timeout=10, verify=False)
                    for pattern in db_error_patterns:
                        if re.search(pattern, str(resp.text), re.IGNORECASE):
                            errors_on_benign += 1
                            break
                except Exception:
                    pass

            if errors_on_benign >= 2:
                # DB errors appear even with benign input → likely FP (custom error page)
                finding['fp_status'] = 'likely_false_positive'
                finding['fp_reason'] = 'DB error patterns appear with benign input values'
                finding['confidence'] = max(20, finding.get('confidence', 50) - 40)
            else:
                finding['fp_status'] = 'confirmed'
                finding['confirmed'] = True
                finding['confidence'] = min(100, finding.get('confidence', 50) + 20)

        elif subtype == 'time_based_blind':
            # Re-test timing to confirm it's not natural latency
            baseline_times = []
            for _ in range(3):
                try:
                    self.rl.wait(url)
                    start = time.time()
                    self.session.get(url, timeout=15, verify=False)
                    baseline_times.append(time.time() - start)
                except Exception:
                    pass
            
            if baseline_times:
                avg_baseline = sum(baseline_times) / len(baseline_times)
                max_baseline = max(baseline_times)
                delay_time = finding.get('delay_time_1', 0)
                
                # If baseline is already high or variable → likely FP
                if max_baseline > delay_time * 0.5:
                    finding['fp_status'] = 'likely_false_positive'
                    finding['fp_reason'] = f'High baseline latency ({max_baseline:.2f}s)'
                    finding['confidence'] = max(20, finding.get('confidence', 50) - 30)
                else:
                    finding['fp_status'] = 'confirmed'
                    finding['confirmed'] = True

        finding['fp_verified'] = True
        return finding

    def verify_xss(self, finding: dict) -> dict:
        """Verify XSS finding with additional checks."""
        url = finding.get('url', '')
        payload = finding.get('payload', '')
        param = finding.get('parameter', '')
        
        if not url or not payload or not param:
            finding['fp_verified'] = False
            return finding

        # Check if the "reflection" is actually from a different source
        bl_status, bl_len, bl_text = self._get_baseline(url)

        # If the payload's key parts appear in the baseline (without injection), it's FP
        dangerous_parts = ['<script', 'onerror=', 'onload=', 'alert(']
        for part in dangerous_parts:
            if part in payload.lower() and part in bl_text.lower():
                finding['fp_status'] = 'likely_false_positive'
                finding['fp_reason'] = f'Dangerous tag "{part}" appears in baseline response'
                finding['confidence'] = max(15, finding.get('confidence', 50) - 40)
                finding['fp_verified'] = True
                return finding

        # Verify reflection is actually user-controlled
        # Send a unique canary and verify it reflects
        import random, string
        canary = 'SNOOGER' + ''.join(random.choices(string.ascii_lowercase, k=10))
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            params[param] = [canary]
            test_url = url.split('?')[0] + '?' + '&'.join(
                f"{k}={v[0]}" for k, v in params.items()
            )
            self.rl.wait(url)
            resp = self.session.get(test_url, timeout=10, verify=False)
            if canary not in resp.text:
                finding['fp_status'] = 'likely_false_positive'
                finding['fp_reason'] = 'Parameter value not reflected in response'
                finding['confidence'] = 10
            else:
                finding['fp_status'] = 'confirmed'
                finding['confirmed'] = True
        except Exception:
            pass

        finding['fp_verified'] = True
        return finding

    def verify_generic(self, finding: dict) -> dict:
        """Generic verification for other finding types."""
        finding['confidence'] = self.scorer.score(finding)
        finding['fp_verified'] = True
        return finding

    def filter_findings(self, findings: List[dict],
                        min_confidence: int = 30) -> List[dict]:
        """Filter findings by verifying and scoring them."""
        verified = []

        for finding in findings:
            ftype = finding.get('type', '').lower()

            # Route to specialized verifiers
            if 'sql' in ftype or 'sqli' in ftype:
                finding = self.verify_sqli(finding)
            elif 'xss' in ftype:
                finding = self.verify_xss(finding)
            else:
                finding = self.verify_generic(finding)

            # Score
            if 'confidence' not in finding:
                finding['confidence'] = self.scorer.score(finding)

            # Filter by confidence
            if finding.get('confidence', 0) >= min_confidence:
                if finding.get('fp_status') != 'likely_false_positive':
                    verified.append(finding)
                else:
                    logger.info(f"Filtered FP: {finding.get('type')} at {finding.get('url', '')[:60]} "
                               f"(confidence={finding.get('confidence')})")

        logger.info(f"False positive filter: {len(findings)} → {len(verified)} findings "
                   f"({len(findings) - len(verified)} filtered)")
        return verified


def triage_findings_with_ai(findings: List[dict], ai_engine) -> List[dict]:
    """Use AI to triage findings for false positives."""
    if not ai_engine or ai_engine.mode == 'off':
        return findings

    triaged = []
    for finding in findings:
        try:
            result = ai_engine.triage_false_positives(finding, {})
            if isinstance(result, dict):
                verdict = result.get('ai_triage', {}).get('verdict', '')
                if verdict != 'false_positive':
                    finding['ai_verdict'] = verdict
                    finding['ai_reasoning'] = result.get('ai_triage', {}).get('reasoning', '')
                    triaged.append(finding)
                else:
                    logger.info(f"AI triaged as FP: {finding.get('type')} at {finding.get('url', '')[:60]}")
            else:
                triaged.append(finding)
        except Exception:
            triaged.append(finding)

    logger.info(f"AI triage: {len(findings)} → {len(triaged)} findings")
    return triaged
