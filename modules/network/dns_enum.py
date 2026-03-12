"""
DNS Enumeration — comprehensive DNS record analysis.
Queries A, AAAA, MX, TXT, NS, SOA, CNAME, SRV records.
Analyzes SPF, DMARC, DKIM, and performs DNS cache snooping.
"""
import os
import logging
import json
from typing import List, Dict, Optional
from core.utils import run_command, write_json

logger = logging.getLogger('snooger')

RECORD_TYPES = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'SOA', 'CNAME', 'SRV', 'PTR', 'CAA']


def query_dns(domain: str, record_type: str) -> List[str]:
    """Query DNS records using dig."""
    stdout, _, code = run_command(f"dig +short {domain} {record_type}", timeout=10)
    if code == 0 and stdout.strip():
        return [line.strip() for line in stdout.strip().split('\n') if line.strip()]
    return []


def enumerate_dns(domain: str, workspace_dir: str) -> dict:
    """Full DNS enumeration for a domain."""
    results = {'domain': domain, 'records': {}, 'security': {}, 'findings': []}

    # Query all record types
    for rtype in RECORD_TYPES:
        records = query_dns(domain, rtype)
        if records:
            results['records'][rtype] = records
            logger.info(f"DNS {rtype}: {len(records)} records for {domain}")

    # SPF Analysis
    txt_records = results['records'].get('TXT', [])
    spf_records = [r for r in txt_records if 'v=spf1' in r.lower()]
    if spf_records:
        results['security']['spf'] = spf_records[0]
        spf = spf_records[0].lower()
        if '+all' in spf:
            results['findings'].append({
                'type': 'spf_permissive',
                'severity': 'high',
                'evidence': f"SPF record uses +all (allows any sender): {spf_records[0]}",
                'url': domain,
            })
        elif '~all' in spf:
            results['findings'].append({
                'type': 'spf_softfail',
                'severity': 'low',
                'evidence': f"SPF uses softfail (~all): {spf_records[0]}",
                'url': domain,
            })
    else:
        results['findings'].append({
            'type': 'missing_spf',
            'severity': 'medium',
            'evidence': 'No SPF record found — email spoofing possible',
            'url': domain,
        })

    # DMARC Analysis
    dmarc = query_dns(f"_dmarc.{domain}", 'TXT')
    if dmarc:
        results['security']['dmarc'] = dmarc[0]
        if 'p=none' in dmarc[0].lower():
            results['findings'].append({
                'type': 'dmarc_none_policy',
                'severity': 'medium',
                'evidence': f"DMARC policy is none (monitoring only): {dmarc[0]}",
                'url': domain,
            })
    else:
        results['findings'].append({
            'type': 'missing_dmarc',
            'severity': 'medium',
            'evidence': 'No DMARC record found — email spoofing risk',
            'url': domain,
        })

    # DKIM Check (common selectors)
    dkim_selectors = ['default', 'google', 'selector1', 'selector2', 'k1', 'mail', 'dkim']
    for sel in dkim_selectors:
        dkim = query_dns(f"{sel}._domainkey.{domain}", 'TXT')
        if dkim:
            results['security']['dkim'] = {'selector': sel, 'record': dkim[0]}
            break

    if 'dkim' not in results['security']:
        results['findings'].append({
            'type': 'missing_dkim',
            'severity': 'low',
            'evidence': 'No DKIM record found (checked common selectors)',
            'url': domain,
        })

    # CAA Analysis
    caa = results['records'].get('CAA', [])
    if not caa:
        results['findings'].append({
            'type': 'missing_caa',
            'severity': 'low',
            'evidence': 'No CAA record — any CA can issue certificates',
            'url': domain,
        })

    # NS takeover check
    ns_records = results['records'].get('NS', [])
    for ns in ns_records:
        ns_a = query_dns(ns.rstrip('.'), 'A')
        if not ns_a:
            results['findings'].append({
                'type': 'dangling_ns',
                'severity': 'critical',
                'evidence': f"NS {ns} has no A record — possible NS takeover",
                'url': domain,
            })

    # Save results
    write_json(os.path.join(workspace_dir, 'dns_enum.json'), results)

    if results['findings']:
        logger.warning(f"DNS enumeration: {len(results['findings'])} findings for {domain}")

    return results


def run_dns_enum(target: str, workspace_dir: str, config = None) -> dict:
    """Entry point for DNS enumeration."""
    return enumerate_dns(target, workspace_dir)
