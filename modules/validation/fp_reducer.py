"""
False Positive Filter — Confidence-based validation and deduplication.
Reduces noise by verifying findings and assigning confidence scores.
"""
import hashlib
import logging
import requests
from typing import List, Dict, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

logger = logging.getLogger('snooger')


class FalsePositiveFilter:
    """Filter false positives using multi-signal validation."""

    # Known false-positive patterns
    FP_PATTERNS = [
        'example.com', 'test.com', 'localhost', '127.0.0.1',
        'placeholder', 'changeme', 'xxxx', 'your-', 'TODO',
    ]

    # Minimum response body length to consider a "real" page
    MIN_RESPONSE_LENGTH = 50

    def filter_findings(self, findings: List[Dict], min_confidence: int = 30) -> List[Dict]:
        """Filter findings by confidence score and deduplication."""
        if not findings:
            return []

        logger.info(f"Filtering {len(findings)} findings for false positives...")

        # Step 1: Deduplicate
        deduped = self._deduplicate(findings)
        logger.debug(f"After dedup: {len(deduped)} findings")

        # Step 2: Assign confidence scores
        scored = []
        for finding in deduped:
            score = self._calculate_confidence(finding)
            finding['fp_confidence'] = score
            if score >= min_confidence:
                scored.append(finding)
            else:
                logger.debug(f"Filtered out (confidence={score}): {finding.get('type', 'unknown')} @ {finding.get('url', 'n/a')[:60]}")

        removed = len(deduped) - len(scored)
        if removed > 0:
            logger.info(f"Removed {removed} likely false positives (below {min_confidence}% confidence)")

        return scored

    def _deduplicate(self, findings: List[Dict]) -> List[Dict]:
        """Remove duplicate findings based on normalized URL + type."""
        seen = set()
        unique = []
        for f in findings:
            url = self._normalize_url(str(f.get('url', '') or f.get('host', '') or ''))
            f_type = f.get('type', f.get('info', {}).get('name', 'unknown'))
            key = hashlib.md5(f"{url}:{f_type}".encode()).hexdigest()
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    def _normalize_url(self, url: str) -> str:
        """Normalize URL for dedup comparison."""
        if not url:
            return ''
        try:
            parsed = urlparse(url)
            # Sort query params for consistent comparison
            params = parse_qs(parsed.query)
            sorted_query = urlencode(sorted(params.items()), doseq=True)
            return urlunparse((
                parsed.scheme, parsed.netloc, parsed.path.rstrip('/'),
                '', sorted_query, ''
            )).lower()
        except Exception:
            return url.lower().rstrip('/')

    def _calculate_confidence(self, finding: Dict) -> int:
        """Calculate confidence score (0-100) for a finding."""
        score = 50  # Base score

        # Boost: has concrete evidence
        evidence = finding.get('evidence', finding.get('matched-at', ''))
        if evidence and len(str(evidence)) > 20:
            score += 15

        # Boost: has severity from a trusted scanner
        severity = finding.get('severity', finding.get('info', {}).get('severity', ''))
        if severity in ('critical', 'high'):
            score += 15
        elif severity == 'medium':
            score += 10

        # Boost: has specific template/CVE
        tags = finding.get('info', {}).get('tags', [])
        if isinstance(tags, list):
            if any('cve' in str(t).lower() for t in tags):
                score += 15
            if any('owasp' in str(t).lower() for t in tags):
                score += 5

        # Penalty: matches known FP patterns
        url = str(finding.get('url', ''))
        for pattern in self.FP_PATTERNS:
            if pattern in url.lower():
                score = score - 30
                break

        # Penalty: generic info-level finding
        if severity == 'info':
            score = score - 15

        # Penalty: no URL or host
        if not finding.get('url') and not finding.get('host') and not finding.get('matched-at'):
            score = score - 20

        return max(0, min(100, score))

    def validate_finding_live(self, finding: Dict, timeout: int = 10) -> Dict:
        """Re-request finding URL to verify it's still exploitable."""
        url = finding.get('url', finding.get('matched-at', ''))
        if not url:
            finding['fp_live_check'] = 'no_url'
            return finding

        try:
            resp = requests.get(url, timeout=timeout, verify=False, allow_redirects=True,
                                headers={'User-Agent': 'Mozilla/5.0 (compatible; SnoogerVerify/1.0)'})
            finding['fp_live_check'] = 'verified'
            finding['fp_status_code'] = resp.status_code
            finding['fp_response_length'] = len(resp.text)

            # Extra check: if the evidence should be reflected in the response
            evidence = str(finding.get('evidence', ''))
            if evidence and len(evidence) > 5:
                if evidence in resp.text:
                    finding['fp_confidence'] = min(100, finding.get('fp_confidence', 50) + 20)
                else:
                    finding['fp_confidence'] = max(0, finding.get('fp_confidence', 50) - 10)

        except requests.exceptions.RequestException:
            finding['fp_live_check'] = 'unreachable'
            finding['fp_confidence'] = max(0, finding.get('fp_confidence', 50) - 15)

        return finding


def triage_findings_with_ai(findings: List[Dict], ai_engine) -> List[Dict]:
    """Use AI to triage findings for false positives."""
    if not findings or not ai_engine:
        return findings

    triaged = []
    for finding in findings:
        result = ai_engine.triage_false_positives(finding)
        # Remove findings the AI is confident are false positives
        triage = result.get('ai_triage', {})
        if triage.get('verdict') == 'false_positive' and triage.get('confidence', 0) > 80:
            logger.debug(f"AI filtered FP: {finding.get('type', 'unknown')} (confidence={triage.get('confidence')})")
            continue
        triaged.append(result)

    removed = len(findings) - len(triaged)
    if removed > 0:
        logger.info(f"AI triage removed {removed} false positives")

    return triaged
