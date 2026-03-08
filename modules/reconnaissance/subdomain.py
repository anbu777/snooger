"""
Multi-source subdomain enumeration:
subfinder, amass, assetfinder, crt.sh, certspotter, zone transfer, reverse IP.
"""
import os
import json
import re
import logging
import requests
from typing import List, Set
from core.utils import run_command, save_raw_output, sanitize_domain
from core.rate_limiter import get_rate_limiter

logger = logging.getLogger('snooger')

def run_subfinder(domain: str, workspace_dir: str) -> List[str]:
    logger.info(f"Running subfinder for {domain}")
    cmd = f"subfinder -d {domain} -oJ -silent -all"
    stdout, stderr, rc = run_command(cmd, timeout=300)
    save_raw_output(workspace_dir, 'recon', 'subfinder', stdout, 'json')
    if rc < 0:
        logger.warning(f"subfinder not available: {stderr}")
        return []
    subdomains = set()
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            host = data.get('host', '')
            if host:
                subdomains.add(host)
        except json.JSONDecodeError:
            if '.' in line and not line.startswith('{'):
                subdomains.add(line)
    logger.info(f"subfinder found {len(subdomains)} subdomains")
    return list(subdomains)

def run_amass(domain: str, workspace_dir: str) -> List[str]:
    logger.info(f"Running amass for {domain}")
    out_file = os.path.join(workspace_dir, 'amass_output.txt')
    cmd = f"amass enum -passive -d {domain} -o {out_file} -timeout 5"
    stdout, stderr, rc = run_command(cmd, timeout=360)
    save_raw_output(workspace_dir, 'recon', 'amass', stdout + stderr, 'txt')
    if rc < 0:
        logger.warning("amass not available")
        return []
    subdomains = set()
    if os.path.exists(out_file):
        with open(out_file, 'r', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if line and domain in line:
                    subdomains.add(line)
    return list(subdomains)

def run_assetfinder(domain: str, workspace_dir: str) -> List[str]:
    logger.info(f"Running assetfinder for {domain}")
    cmd = f"assetfinder --subs-only {domain}"
    stdout, stderr, rc = run_command(cmd, timeout=120)
    save_raw_output(workspace_dir, 'recon', 'assetfinder', stdout, 'txt')
    if rc < 0:
        return []
    return [l.strip() for l in stdout.splitlines() if l.strip() and domain in l]

def query_crtsh(domain: str) -> List[str]:
    """Certificate Transparency via crt.sh."""
    logger.info(f"Querying crt.sh for {domain}")
    rl = get_rate_limiter()
    rl.wait('crt.sh')
    try:
        resp = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=30,
            headers={'Accept': 'application/json'}
        )
        if resp.status_code == 200:
            data = resp.json()
            subdomains = set()
            for entry in data:
                name = entry.get('name_value', '')
                for sub in name.split('\n'):
                    sub = sub.strip().lstrip('*.')
                    if sub and domain in sub and not sub.startswith('@'):
                        subdomains.add(sub)
            logger.info(f"crt.sh found {len(subdomains)} entries")
            return list(subdomains)
    except Exception as e:
        logger.warning(f"crt.sh query failed: {e}")
    return []

def query_certspotter(domain: str) -> List[str]:
    """Certificate Transparency via certspotter."""
    logger.info(f"Querying certspotter for {domain}")
    rl = get_rate_limiter()
    rl.wait('certspotter')
    try:
        resp = requests.get(
            f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names",
            timeout=30
        )
        if resp.status_code == 200:
            subdomains = set()
            for entry in resp.json():
                for name in entry.get('dns_names', []):
                    name = name.lstrip('*.')
                    if domain in name:
                        subdomains.add(name)
            logger.info(f"certspotter found {len(subdomains)} entries")
            return list(subdomains)
    except Exception as e:
        logger.warning(f"certspotter query failed: {e}")
    return []

def attempt_zone_transfer(domain: str) -> List[str]:
    """Attempt DNS zone transfer."""
    logger.info(f"Attempting zone transfer for {domain}")
    subdomains = set()
    # Get nameservers first
    ns_stdout, _, _ = run_command(f"dig NS {domain} +short", timeout=15)
    nameservers = [ns.strip().rstrip('.') for ns in ns_stdout.splitlines() if ns.strip()]
    for ns in nameservers[:3]:  # Try first 3 nameservers
        cmd = f"dig AXFR {domain} @{ns} +time=5 +tries=1"
        stdout, _, rc = run_command(cmd, timeout=20)
        if rc == 0 and domain in stdout and 'Transfer failed' not in stdout:
            # Parse zone transfer results
            for line in stdout.splitlines():
                parts = line.split()
                if len(parts) >= 5 and parts[3] in ('A', 'AAAA', 'CNAME'):
                    host = parts[0].rstrip('.').replace(f'.{domain}', '')
                    if domain in parts[0]:
                        subdomains.add(parts[0].rstrip('.'))
            if subdomains:
                logger.warning(f"ZONE TRANSFER SUCCESSFUL from {ns}! Found {len(subdomains)} records")
                save_raw_output(os.path.dirname(os.path.dirname(domain)), 'recon',
                                f'zone_transfer_{ns}', stdout, 'txt')
    return list(subdomains)

def whois_asn_lookup(domain: str, workspace_dir: str) -> dict:
    """WHOIS and ASN data collection."""
    result = {'whois': None, 'asn': None}
    whois_stdout, _, _ = run_command(f"whois {domain}", timeout=20)
    if whois_stdout:
        result['whois'] = whois_stdout[:2000]
        save_raw_output(workspace_dir, 'recon', 'whois', whois_stdout, 'txt')
    # ASN lookup via hackertarget
    rl = get_rate_limiter()
    rl.wait('hackertarget.com')
    try:
        resp = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=15)
        if resp.status_code == 200:
            result['asn'] = resp.text[:1000]
    except Exception:
        pass
    return result

def run_full_subdomain_enum(domain: str, workspace_dir: str) -> List[str]:
    """Run all subdomain enumeration sources and deduplicate."""
    all_subs: Set[str] = set()

    # Active tools
    for func in [run_subfinder, run_amass, run_assetfinder]:
        try:
            subs = func(domain, workspace_dir)
            all_subs.update(subs)
            logger.info(f"{func.__name__}: +{len(subs)} (total: {len(all_subs)})")
        except Exception as e:
            logger.error(f"{func.__name__} failed: {e}")

    # Certificate Transparency
    for func in [query_crtsh, query_certspotter]:
        try:
            subs = func(domain)
            all_subs.update(subs)
        except Exception as e:
            logger.error(f"{func.__name__} failed: {e}")

    # Zone transfer attempt
    try:
        zt_subs = attempt_zone_transfer(domain)
        all_subs.update(zt_subs)
    except Exception as e:
        logger.error(f"Zone transfer failed: {e}")

    # Save combined results
    result_list = sorted(all_subs)
    with open(os.path.join(workspace_dir, 'all_subdomains.txt'), 'w') as f:
        f.write('\n'.join(result_list))

    logger.info(f"Total unique subdomains: {len(result_list)}")
    return result_list
