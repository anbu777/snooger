"""
Subdomain takeover detection using subjack, subzy, and custom CNAME checks.
"""
import os
import json
import logging
import requests
from typing import List, Dict
from core.utils import run_command, save_raw_output, write_json
from core.rate_limiter import get_rate_limiter

logger = logging.getLogger('snooger')

# Fingerprints for dangling service CNAMEs
TAKEOVER_FINGERPRINTS = {
    'github': ('github.io', 'There isn\'t a GitHub Pages site here'),
    'heroku': ('herokuapp.com', 'No such app'),
    'shopify': ('myshopify.com', 'Sorry, this shop is currently unavailable'),
    'fastly': ('fastly.net', 'Fastly error: unknown domain'),
    'ghost': ('ghost.io', 'The thing you were looking for is no longer here'),
    'bitbucket': ('bitbucket.io', 'Repository not found'),
    'amazon_s3': ('s3.amazonaws.com', 'NoSuchBucket'),
    'amazon_cloudfront': ('cloudfront.net', 'Bad request'),
    'azure_websites': ('azurewebsites.net', 'The site you were looking for doesn\'t exist'),
    'azure_storage': ('blob.core.windows.net', 'The specified account does not exist'),
    'wordpress': ('wordpress.com', 'Do you want to register'),
    'helpscout': ('helpscoutdocs.com', 'No settings were found for this company'),
    'unbounce': ('unbouncepages.com', 'Sorry, this page is no longer here'),
    'smugmug': ('smugmug.com', 'Page Not Found'),
    'tictail': ('tictail.com', 'Building a brand'),
    'campaignmonitor': ('createsend.com', 'Double check the URL'),
    'zendesk': ('zendesk.com', 'Help Center Closed'),
    'teamwork': ('teamwork.com', 'Oops - We didn\'t find your site'),
    'cargocollective': ('cargocollective.com', '404 Not Found'),
    'statuspage': ('statuspage.io', 'Better Uptime'),
    'surge': ('surge.sh', 'project not found'),
    'intercom': ('intercom.io', 'Uh oh. That page doesn\'t exist'),
    'desk': ('desk.com', 'Sorry, We couldn\'t find your page'),
    'tumblr': ('tumblr.com', 'Whatever you were looking for doesn\'t currently exist'),
}

def run_subjack(subdomains: List[str], workspace_dir: str) -> List[dict]:
    """Run subjack for subdomain takeover detection."""
    if not subdomains:
        return []
    input_file = os.path.join(workspace_dir, 'temp_subjack_input.txt')
    output_file = os.path.join(workspace_dir, 'subjack_results.json')
    try:
        with open(input_file, 'w') as f:
            f.write('\n'.join(subdomains))
        cmd = f"subjack -w {input_file} -t 50 -timeout 30 -ssl -o {output_file} -a"
        stdout, stderr, rc = run_command(cmd, timeout=600)
        save_raw_output(workspace_dir, 'recon', 'subjack', stdout + stderr, 'txt')
        if os.path.exists(output_file) and os.path.getsize(output_file) > 2:
            with open(output_file, 'r') as f:
                data = json.load(f)
            return data if isinstance(data, list) else [data]
    except Exception as e:
        logger.warning(f"subjack failed: {e}")
    finally:
        if os.path.exists(input_file):
            os.remove(input_file)
    return []

def run_subzy(subdomains: List[str], workspace_dir: str) -> List[dict]:
    """Run subzy for subdomain takeover detection."""
    if not subdomains:
        return []
    input_file = os.path.join(workspace_dir, 'temp_subzy_input.txt')
    try:
        with open(input_file, 'w') as f:
            f.write('\n'.join(subdomains))
        cmd = f"subzy run --targets {input_file} --vuln --hide-fails"
        stdout, stderr, rc = run_command(cmd, timeout=600)
        save_raw_output(workspace_dir, 'recon', 'subzy', stdout + stderr, 'txt')
        findings = []
        for line in stdout.splitlines():
            if '[VULNERABLE]' in line or 'VULNERABLE' in line:
                findings.append({'raw': line.strip(), 'source': 'subzy'})
        return findings
    except Exception as e:
        logger.warning(f"subzy failed: {e}")
    finally:
        if os.path.exists(input_file):
            os.remove(input_file)
    return []

def manual_cname_check(subdomains: List[str], workspace_dir: str) -> List[dict]:
    """Manual CNAME-based takeover check using fingerprints."""
    import subprocess
    rl = get_rate_limiter()
    findings = []

    for subdomain in subdomains:
        try:
            # Get CNAME record
            result = subprocess.run(
                ['dig', 'CNAME', subdomain, '+short'],
                capture_output=True, text=True, timeout=10
            )
            cname = result.stdout.strip().rstrip('.')
            if not cname:
                continue

            # Check if CNAME matches any known vulnerable service
            for service, (domain_pattern, fingerprint) in TAKEOVER_FINGERPRINTS.items():
                if domain_pattern in cname:
                    # Try to access the subdomain and check for fingerprint
                    rl.wait(subdomain)
                    try:
                        resp = requests.get(
                            f"https://{subdomain}", timeout=10,
                            allow_redirects=True, verify=False
                        )
                        if fingerprint.lower() in resp.text.lower():
                            finding = {
                                'subdomain': subdomain,
                                'cname': cname,
                                'service': service,
                                'fingerprint': fingerprint,
                                'status_code': resp.status_code,
                                'severity': 'high',
                                'type': 'subdomain_takeover',
                                'evidence': f"CNAME {cname} points to unclaimed {service} resource"
                            }
                            findings.append(finding)
                            logger.warning(f"SUBDOMAIN TAKEOVER: {subdomain} → {service} ({cname})")
                    except requests.exceptions.SSLError:
                        # Try HTTP
                        try:
                            resp = requests.get(f"http://{subdomain}", timeout=10, allow_redirects=True)
                            if fingerprint.lower() in resp.text.lower():
                                findings.append({
                                    'subdomain': subdomain,
                                    'cname': cname,
                                    'service': service,
                                    'fingerprint': fingerprint,
                                    'severity': 'high',
                                    'type': 'subdomain_takeover'
                                })
                        except Exception:
                            pass
                    except Exception:
                        pass
        except Exception as e:
            logger.debug(f"CNAME check failed for {subdomain}: {e}")

    return findings

def check_subdomain_takeovers(subdomains: List[str], workspace_dir: str) -> List[dict]:
    """Run all subdomain takeover checks."""
    logger.info(f"Checking {len(subdomains)} subdomains for takeover vulnerabilities")
    all_findings = []

    # Run automated tools
    for func in [run_subjack, run_subzy]:
        try:
            findings = func(subdomains, workspace_dir)
            all_findings.extend(findings)
        except Exception as e:
            logger.error(f"{func.__name__} error: {e}")

    # Manual CNAME check (more reliable)
    try:
        manual_findings = manual_cname_check(subdomains[:100], workspace_dir)
        all_findings.extend(manual_findings)
    except Exception as e:
        logger.error(f"Manual CNAME check error: {e}")

    if all_findings:
        write_json(os.path.join(workspace_dir, 'subdomain_takeover.json'), all_findings)
        logger.warning(f"Found {len(all_findings)} potential subdomain takeover vulnerabilities!")

    return all_findings
