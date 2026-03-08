"""
AI-powered report generation: executive summary, PoC writeups,
markdown report, HTML report, Bugcrowd/HackerOne ready format.
"""
import os
import json
import logging
from datetime import datetime
from jinja2 import Template
from core.utils import write_json

logger = logging.getLogger('snooger')

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Snooger Security Report - {{ target }}</title>
<style>
body{font-family:Arial,sans-serif;margin:30px;background:#f5f5f5;color:#333}
.header{background:#1a1a2e;color:white;padding:20px;border-radius:8px;margin-bottom:20px}
.summary-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:20px}
.card{background:white;padding:15px;border-radius:8px;text-align:center;box-shadow:0 2px 4px rgba(0,0,0,.1)}
.critical{border-left:4px solid #dc3545;background:#fff5f5}
.high{border-left:4px solid #fd7e14;background:#fff8f0}
.medium{border-left:4px solid #ffc107;background:#fffdf0}
.low{border-left:4px solid #28a745;background:#f0fff4}
.finding{background:white;margin:10px 0;padding:15px;border-radius:8px;box-shadow:0 2px 4px rgba(0,0,0,.1)}
.badge{display:inline-block;padding:3px 10px;border-radius:12px;font-size:12px;font-weight:bold;color:white}
.badge-critical{background:#dc3545}.badge-high{background:#fd7e14}
.badge-medium{background:#ffc107;color:#333}.badge-low{background:#28a745}
.badge-info{background:#6c757d}
pre{background:#f8f9fa;padding:10px;border-radius:4px;overflow-x:auto;font-size:12px}
table{width:100%;border-collapse:collapse}th,td{padding:8px;text-align:left;border-bottom:1px solid #ddd}
th{background:#1a1a2e;color:white}tr:hover{background:#f5f5f5}
.chain{background:#fff3cd;border:1px solid #ffc107;padding:10px;border-radius:8px;margin:8px 0}
</style>
</head>
<body>
<div class="header">
  <h1>🔒 Snooger Security Assessment Report</h1>
  <p>Target: <strong>{{ target }}</strong> | Generated: {{ generated_at }}</p>
</div>
<div class="summary-grid">
  <div class="card critical"><h2>{{ by_severity.critical }}</h2><p>Critical</p></div>
  <div class="card high"><h2>{{ by_severity.high }}</h2><p>High</p></div>
  <div class="card medium"><h2>{{ by_severity.medium }}</h2><p>Medium</p></div>
  <div class="card low"><h2>{{ by_severity.low }}</h2><p>Low</p></div>
</div>
{% if ai_summary %}
<div style="background:white;padding:20px;border-radius:8px;margin-bottom:20px">
  <h2>🤖 AI Executive Summary</h2>
  <pre style="white-space:pre-wrap">{{ ai_summary }}</pre>
</div>
{% endif %}
{% if exploit_chains %}
<div style="background:white;padding:20px;border-radius:8px;margin-bottom:20px">
  <h2>⛓️ Exploit Chain Opportunities</h2>
  {% for chain in exploit_chains %}
  <div class="chain">
    <strong>[{{ chain.impact|upper }}] {{ chain.description }}</strong><br>
    Steps: {{ chain.steps|join(' → ') }}<br>
    <small>Trigger: {{ chain.trigger_finding.type }} @ {{ chain.trigger_finding.url[:80] }}</small>
  </div>
  {% endfor %}
</div>
{% endif %}
<div style="background:white;padding:20px;border-radius:8px;margin-bottom:20px">
  <h2>🔍 Vulnerability Findings</h2>
  {% for v in vulnerabilities %}
  {% set sev = v.severity or v.info.severity if v.info is defined else 'info' %}
  {% set name = v.type or (v.info.name if v.info is defined else 'Unknown') %}
  {% set url = v.url or v['matched-at'] or v.host or '' %}
  <div class="finding {{ sev }}">
    <span class="badge badge-{{ sev }}">{{ sev|upper }}</span>
    <strong>{{ name }}</strong>
    <br><small>URL: {{ url[:100] }}</small>
    {% if v.evidence %}<br><small>Evidence: {{ v.evidence[:200] }}</small>{% endif %}
    {% if v.cvss_score %}<br><small>CVSS: {{ v.cvss_score }} | {{ v.cwe_id }}</small>{% endif %}
  </div>
  {% endfor %}
</div>
{% if subdomain_takeovers %}
<div style="background:white;padding:20px;border-radius:8px;margin-bottom:20px">
  <h2>⚠️ Subdomain Takeovers</h2>
  <table>
    <tr><th>Subdomain</th><th>CNAME</th><th>Service</th><th>Severity</th></tr>
    {% for t in subdomain_takeovers %}
    <tr><td>{{ t.subdomain }}</td><td>{{ t.cname }}</td><td>{{ t.service }}</td>
        <td><span class="badge badge-{{ t.severity }}">{{ t.severity }}</span></td></tr>
    {% endfor %}
  </table>
</div>
{% endif %}
<div style="background:white;padding:20px;border-radius:8px;margin-bottom:20px">
  <h2>📊 Scan Statistics</h2>
  <table>
    <tr><th>Metric</th><th>Value</th></tr>
    <tr><td>Total Findings</td><td>{{ summary.total_findings }}</td></tr>
    <tr><td>Subdomains Found</td><td>{{ summary.subdomains_found }}</td></tr>
    <tr><td>Alive Hosts</td><td>{{ summary.alive_hosts }}</td></tr>
    <tr><td>IDOR Findings</td><td>{{ summary.idor_findings }}</td></tr>
    <tr><td>JS Secrets Found</td><td>{{ summary.js_secrets }}</td></tr>
    <tr><td>Exploit Chains</td><td>{{ summary.exploit_chains }}</td></tr>
    <tr><td>Start Time</td><td>{{ start_time }}</td></tr>
    <tr><td>End Time</td><td>{{ end_time }}</td></tr>
  </table>
</div>
</body>
</html>"""

MARKDOWN_TEMPLATE = """# Security Assessment Report

**Target:** `{{ target }}`
**Date:** {{ generated_at }}
**Tool:** Snooger v2.0

## Executive Summary

{{ ai_summary or "No AI summary generated." }}

## Findings Summary

| Severity | Count |
|----------|-------|
| Critical | {{ by_severity.critical }} |
| High     | {{ by_severity.high }} |
| Medium   | {{ by_severity.medium }} |
| Low      | {{ by_severity.low }} |

## Vulnerability Details

{% for v in vulnerabilities %}
### {{ loop.index }}. {{ v.type or (v.info.name if v.info is defined else 'Unknown') }}

- **Severity:** {{ v.severity or 'unknown' }}
- **URL:** `{{ v.url or v.get('matched-at', v.get('host', 'N/A')) }}`
- **CVSS:** {{ v.cvss_score or 'N/A' }}
- **CWE:** {{ v.cwe_id or 'N/A' }}
- **Evidence:** {{ v.evidence or 'See raw findings' }}

{% endfor %}

{% if exploit_chains %}
## Exploit Chain Opportunities

{% for chain in exploit_chains %}
### {{ chain.description }}
- **Impact:** {{ chain.impact }}
- **Steps:** {{ chain.steps|join(' → ') }}

{% endfor %}
{% endif %}

## Subdomain Takeovers

{% for t in subdomain_takeovers %}
- **{{ t.subdomain }}** → CNAME: `{{ t.cname }}` ({{ t.service }})
{% endfor %}
"""

HACKERONE_TEMPLATE = """## Summary

{{ description }}

## Steps To Reproduce

{{ steps_to_reproduce }}

## Supporting Material/References

{{ references }}

## Impact

{{ impact }}

## Severity Assessment

- **CVSS Score:** {{ cvss_score }}
- **CWE:** {{ cwe_id }}
"""

def generate_summary(ai_engine, report: dict) -> str:
    """Generate AI executive summary from report data."""
    vulns = report.get('vulnerabilities', [])
    summary_data = report.get('summary', {})

    prompt = f"""You are a senior penetration tester writing a professional security assessment report.

Target: {report['metadata'].get('target', 'unknown')}
Total Findings: {summary_data.get('total_findings', 0)}
Critical: {summary_data.get('by_severity', {}).get('critical', 0)}
High: {summary_data.get('by_severity', {}).get('high', 0)}
Medium: {summary_data.get('by_severity', {}).get('medium', 0)}
Low: {summary_data.get('by_severity', {}).get('low', 0)}
Subdomain Takeovers: {summary_data.get('subdomain_takeovers', 0)}
Exploit Chains: {summary_data.get('exploit_chains', 0)}
JS Secrets: {summary_data.get('js_secrets', 0)}

Top Findings:
{json.dumps([{
    'name': v.get('type', v.get('info', {}).get('name', 'Unknown')),
    'severity': v.get('severity', v.get('info', {}).get('severity', 'unknown')),
    'url': v.get('url', v.get('matched-at', ''))[:80],
    'cvss': v.get('cvss_score', '')
} for v in vulns[:10]], indent=2)}

Write a professional executive summary in English (4-6 paragraphs) covering:
1. Overall security posture
2. Most critical findings and their business impact
3. Attack chains and escalation potential
4. Prioritized remediation recommendations
5. Compliance implications

Use professional security assessment language suitable for HackerOne/Bugcrowd submission."""

    system = "You are a professional penetration tester writing a formal security assessment report."
    response = ai_engine.ask(prompt, task_type='summary', system=system)
    return response or _generate_rule_based_summary(report)

def _generate_rule_based_summary(report: dict) -> str:
    """Fallback rule-based summary when AI is unavailable."""
    s = report.get('summary', {})
    sev = s.get('by_severity', {})
    target = report['metadata'].get('target', 'the target')
    lines = [
        f"Security Assessment Summary for {target}",
        f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        f"Total findings: {s.get('total_findings', 0)} "
        f"(Critical: {sev.get('critical',0)}, High: {sev.get('high',0)}, "
        f"Medium: {sev.get('medium',0)}, Low: {sev.get('low',0)})",
    ]
    if sev.get('critical', 0) > 0:
        lines.append(f"CRITICAL: {sev['critical']} critical severity vulnerabilities require immediate remediation.")
    if s.get('subdomain_takeovers', 0) > 0:
        lines.append(f"WARNING: {s['subdomain_takeovers']} subdomain takeover(s) detected.")
    if s.get('js_secrets', 0) > 0:
        lines.append(f"WARNING: {s['js_secrets']} potential secret(s) exposed in JavaScript files.")
    if s.get('exploit_chains', 0) > 0:
        lines.append(f"NOTE: {s['exploit_chains']} exploit chain(s) identified for elevated impact.")
    return '\n'.join(lines)

def generate_html_report(report: dict, ai_summary: str, workspace_dir: str) -> str:
    """Generate HTML report."""
    template = Template(HTML_TEMPLATE)
    html = template.render(
        target=report['metadata'].get('target', 'unknown'),
        generated_at=report['metadata'].get('generated_at', ''),
        start_time=report['metadata'].get('start_time', ''),
        end_time=report['metadata'].get('end_time', ''),
        by_severity=report.get('summary', {}).get('by_severity', {}),
        summary=report.get('summary', {}),
        vulnerabilities=report.get('vulnerabilities', [])[:50],
        exploit_chains=report.get('exploit_chains', []),
        subdomain_takeovers=report.get('subdomain_takeovers', []),
        ai_summary=ai_summary,
    )
    html_path = os.path.join(workspace_dir, 'report.html')
    with open(html_path, 'w', encoding='utf-8') as f:
        f.write(html)
    logger.info(f"HTML report saved: {html_path}")
    return html_path

def generate_markdown_report(report: dict, ai_summary: str, workspace_dir: str) -> str:
    """Generate Markdown report suitable for bug bounty submission."""
    template = Template(MARKDOWN_TEMPLATE)
    md = template.render(
        target=report['metadata'].get('target', 'unknown'),
        generated_at=report['metadata'].get('generated_at', ''),
        by_severity=report.get('summary', {}).get('by_severity', {}),
        vulnerabilities=report.get('vulnerabilities', [])[:30],
        exploit_chains=report.get('exploit_chains', []),
        subdomain_takeovers=report.get('subdomain_takeovers', []),
        ai_summary=ai_summary,
    )
    md_path = os.path.join(workspace_dir, 'report.md')
    with open(md_path, 'w', encoding='utf-8') as f:
        f.write(md)
    logger.info(f"Markdown report saved: {md_path}")
    return md_path

def generate_hackerone_submission(finding: dict, ai_engine, workspace_dir: str) -> str:
    """Generate HackerOne-ready submission for a single finding."""
    vuln_type = finding.get('type', finding.get('info', {}).get('name', 'Unknown'))
    url = finding.get('url', finding.get('matched-at', ''))
    evidence = finding.get('evidence', '')

    if ai_engine and ai_engine.mode != 'off':
        poc = ai_engine.generate_poc_writeup(finding)
    else:
        template = Template(HACKERONE_TEMPLATE)
        poc = template.render(
            description=f"{vuln_type} vulnerability found at {url}",
            steps_to_reproduce=f"1. Navigate to {url}\n2. Observe: {evidence}",
            references=f"CVSS: {finding.get('cvss_score', 'N/A')}\n{finding.get('cwe_id', '')}",
            impact=f"This {vuln_type} vulnerability could allow an attacker to...",
            cvss_score=finding.get('cvss_score', 'N/A'),
            cwe_id=finding.get('cwe_id', 'N/A'),
        )

    fname = f"hackerone_{vuln_type.replace(' ', '_')[:30]}.md"
    fpath = os.path.join(workspace_dir, 'submissions', fname)
    os.makedirs(os.path.dirname(fpath), exist_ok=True)
    with open(fpath, 'w', encoding='utf-8') as f:
        f.write(poc)
    return fpath
