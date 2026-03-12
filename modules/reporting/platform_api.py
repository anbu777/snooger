"""
Platform API — HackerOne & Bugcrowd report submission.
Supports draft mode for safe testing before auto-submit.
"""
import os
import json
import logging
import requests
from typing import Optional, Dict, List
from core.utils import write_json

logger = logging.getLogger('snooger')


class HackerOneAPI:
    """HackerOne API v1 integration."""

    BASE_URL = "https://api.hackerone.com/v1"

    def __init__(self, username: str, api_token: str):
        self.username = username
        self.api_token = api_token
        self.session = requests.Session()
        self.session.auth = (username, api_token)
        self.session.headers['Content-Type'] = 'application/json'
        self.session.headers['Accept'] = 'application/json'

    def is_configured(self) -> bool:
        return bool(self.username and self.api_token)

    def submit_report(self, program_handle: str, finding: dict,
                      poc_writeup: str = '', draft: bool = True) -> dict:
        """Submit a vulnerability report to HackerOne."""
        if not self.is_configured():
            return {'error': 'HackerOne API not configured'}

        severity_map = {
            'critical': {'rating': 'critical'},
            'high': {'rating': 'high'},
            'medium': {'rating': 'medium'},
            'low': {'rating': 'low'},
        }

        title = self._generate_title(finding)
        body = self._format_report_body(finding, poc_writeup)
        severity = finding.get('severity', 'medium').lower()

        payload = {
            'data': {
                'type': 'report',
                'attributes': {
                    'team_handle': program_handle,
                    'title': title,
                    'vulnerability_information': body,
                    'severity': severity_map.get(severity, {'rating': 'medium'}),
                    'weakness_id': self._get_weakness_id(finding.get('type', '')),
                }
            }
        }

        if draft:
            logger.info(f"[HackerOne] Draft report prepared: {title}")
            return {
                'status': 'draft',
                'title': title,
                'program': program_handle,
                'payload': payload,
                'note': 'Set draft_mode=false in config to auto-submit'
            }

        try:
            resp = self.session.post(
                f"{self.BASE_URL}/reports",
                json=payload,
                timeout=30
            )
            if resp.status_code in (200, 201):
                report_data = resp.json()
                report_id = report_data.get('data', {}).get('id', 'unknown')
                logger.info(f"[HackerOne] Report submitted: #{report_id}")
                return {'status': 'submitted', 'report_id': report_id, 'response': report_data}
            else:
                logger.error(f"[HackerOne] Submit failed: {resp.status_code} — {resp.text[:200]}")
                return {'status': 'error', 'code': resp.status_code, 'message': resp.text[:200]}
        except Exception as e:
            logger.error(f"[HackerOne] API error: {e}")
            return {'status': 'error', 'message': str(e)}

    def _generate_title(self, finding: dict) -> str:
        vuln_type = finding.get('type', 'Vulnerability')
        url = finding.get('url', finding.get('matched-at', 'target'))
        return f"{vuln_type} on {url}"

    def _format_report_body(self, finding: dict, poc_writeup: str) -> str:
        if poc_writeup:
            return poc_writeup

        url = finding.get('url', finding.get('matched-at', 'N/A'))
        evidence = finding.get('evidence', '')
        severity = finding.get('severity', 'medium')

        return f"""## Summary
{finding.get('type', 'Vulnerability')} was discovered on the target application.

## Severity
**{severity.upper()}**

## Steps to Reproduce
1. Navigate to: `{url}`
2. {evidence}

## Impact
This vulnerability could allow an attacker to exploit the {finding.get('type', 'vulnerability')}.

## Evidence
```
{json.dumps(finding, indent=2, default=str)[:2000]}
```
"""

    def _get_weakness_id(self, vuln_type: str) -> int:
        """Map vulnerability type to HackerOne weakness ID."""
        mapping = {
            'xss': 60, 'sql': 67, 'sqli': 67, 'ssrf': 68,
            'idor': 55, 'open_redirect': 53, 'cors': 75,
            'ssti': 72, 'xxe': 66, 'rce': 58, 'lfi': 69,
            'path_traversal': 69, 'crlf': 73, 'csrf': 45,
        }
        for key, wid in mapping.items():
            if key in vuln_type.lower():
                return wid
        return 0


class BugcrowdAPI:
    """Bugcrowd API integration."""

    BASE_URL = "https://api.bugcrowd.com"

    def __init__(self, api_token: str):
        self.api_token = api_token
        self.session = requests.Session()
        self.session.headers['Authorization'] = f'Token {api_token}'
        self.session.headers['Content-Type'] = 'application/vnd.bugcrowd+json'
        self.session.headers['Accept'] = 'application/vnd.bugcrowd+json'

    def is_configured(self) -> bool:
        return bool(self.api_token)

    def submit_report(self, program_id: str, finding: dict,
                      poc_writeup: str = '', draft: bool = True) -> dict:
        """Submit a vulnerability report to Bugcrowd."""
        if not self.is_configured():
            return {'error': 'Bugcrowd API not configured'}

        title = f"{finding.get('type', 'Vulnerability')} on {finding.get('url', 'target')}"
        body = poc_writeup or self._format_body(finding)
        severity = self._map_severity(finding.get('severity', 'medium'))

        payload = {
            'data': {
                'type': 'submission',
                'attributes': {
                    'title': title,
                    'description': body,
                    'severity': severity,
                },
                'relationships': {
                    'program': {'data': {'type': 'program', 'id': program_id}}
                }
            }
        }

        if draft:
            logger.info(f"[Bugcrowd] Draft report prepared: {title}")
            return {
                'status': 'draft', 'title': title,
                'program': program_id, 'payload': payload,
            }

        try:
            resp = self.session.post(
                f"{self.BASE_URL}/submissions",
                json=payload, timeout=30
            )
            if resp.status_code in (200, 201):
                return {'status': 'submitted', 'response': resp.json()}
            else:
                return {'status': 'error', 'code': resp.status_code, 'message': resp.text[:200]}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def _format_body(self, finding: dict) -> str:
        return f"""**Type:** {finding.get('type', 'Unknown')}
**URL:** {finding.get('url', 'N/A')}
**Severity:** {finding.get('severity', 'medium')}
**Evidence:** {finding.get('evidence', '')}
"""

    def _map_severity(self, severity: str) -> int:
        return {'critical': 5, 'high': 4, 'medium': 3, 'low': 2, 'info': 1}.get(severity.lower(), 3)


def submit_findings_to_platforms(findings: List[dict], workspace_dir: str,
                                 config: dict, ai=None) -> dict:
    """Submit all critical/high findings to configured platforms."""
    results = {'hackerone': [], 'bugcrowd': []}
    platform_cfg = config.get('platform', {})

    # HackerOne
    h1_cfg = platform_cfg.get('hackerone', {})
    if h1_cfg.get('api_username') and h1_cfg.get('api_token'):
        h1 = HackerOneAPI(h1_cfg['api_username'], h1_cfg['api_token'])
        draft = h1_cfg.get('draft_mode', True)

        for finding in findings:
            if finding.get('severity') in ('critical', 'high'):
                poc = ''
                if ai:
                    poc = ai.generate_poc_writeup(finding)
                result = h1.submit_report('PROGRAM_HANDLE', finding, poc, draft=draft)
                results['hackerone'].append(result)

    # Bugcrowd
    bc_cfg = platform_cfg.get('bugcrowd', {})
    if bc_cfg.get('api_token'):
        bc = BugcrowdAPI(bc_cfg['api_token'])
        draft = bc_cfg.get('draft_mode', True)

        for finding in findings:
            if finding.get('severity') in ('critical', 'high'):
                poc = ''
                if ai:
                    poc = ai.generate_poc_writeup(finding)
                result = bc.submit_report('PROGRAM_ID', finding, poc, draft=draft)
                results['bugcrowd'].append(result)

    write_json(os.path.join(workspace_dir, 'platform_submissions.json'), results)
    return results
