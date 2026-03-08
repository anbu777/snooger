"""
Wayback Machine / GAU — poin 5 dari perbaikan.
Ekstrak URL historis dari Wayback Machine, Common Crawl, dan AlienVault OTX.
"""
import os
import logging
import requests
from core.utils import run_command, save_raw_output

logger = logging.getLogger('snooger')


def run_gau(domain: str, workspace_dir: str) -> list:
    """Run gau (Get All URLs) to fetch historical URLs."""
    logger.info(f"[Wayback] Running gau for {domain}")
    out_file = os.path.join(workspace_dir, 'raw_logs', 'recon', 'gau.txt')
    os.makedirs(os.path.dirname(out_file), exist_ok=True)

    cmd = f"gau --subs {domain} --o {out_file} --threads 5 --timeout 30"
    stdout, stderr, rc = run_command(cmd, timeout=300)
    save_raw_output(workspace_dir, 'recon', 'gau', stdout + stderr, 'txt')

    urls = set()
    if os.path.exists(out_file):
        with open(out_file, 'r', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if line and line.startswith('http'):
                    urls.add(line)

    logger.info(f"[Wayback] gau found {len(urls)} historical URLs")
    return list(urls)


def run_waybackurls(domain: str, workspace_dir: str) -> list:
    """Run waybackurls to fetch Wayback Machine URLs."""
    logger.info(f"[Wayback] Running waybackurls for {domain}")
    cmd = f"waybackurls {domain}"
    stdout, stderr, rc = run_command(cmd, timeout=180)
    save_raw_output(workspace_dir, 'recon', 'waybackurls', stdout, 'txt')

    urls = set()
    for line in stdout.splitlines():
        line = line.strip()
        if line and line.startswith('http'):
            urls.add(line)

    logger.info(f"[Wayback] waybackurls found {len(urls)} URLs")
    return list(urls)


def query_wayback_api(domain: str) -> list:
    """Query Wayback Machine CDX API directly."""
    logger.info(f"[Wayback] Querying CDX API for {domain}")
    urls = set()
    try:
        resp = requests.get(
            "http://web.archive.org/cdx/search/cdx",
            params={
                'url': f'*.{domain}/*',
                'output': 'text',
                'fl': 'original',
                'collapse': 'urlkey',
                'filter': ['statuscode:200', 'mimetype:text/html'],
                'limit': 5000,
            },
            timeout=60,
            headers={'User-Agent': 'Snooger-Recon/2.0'}
        )
        if resp.status_code == 200:
            for line in resp.text.splitlines():
                line = line.strip()
                if line and line.startswith('http'):
                    urls.add(line)
    except Exception as e:
        logger.warning(f"[Wayback] CDX API error: {e}")

    logger.info(f"[Wayback] CDX API found {len(urls)} URLs")
    return list(urls)


def extract_interesting_params(urls: list) -> dict:
    """
    From historical URLs, extract interesting parameters for fuzzing.
    Returns dict: {param_name: [example_values]}
    """
    from urllib.parse import urlparse, parse_qs
    params = {}
    for url in urls:
        try:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            for param, values in qs.items():
                if param not in params:
                    params[param] = []
                params[param].extend(values[:2])  # Max 2 values per URL
                params[param] = list(set(params[param]))[:5]  # Deduplicate, max 5
        except Exception:
            continue
    return params


def collect_wayback_urls(domain: str, workspace_dir: str) -> list:
    """Collect URLs from all Wayback sources."""
    all_urls = set()

    # Try gau first (most comprehensive)
    try:
        gau_urls = run_gau(domain, workspace_dir)
        all_urls.update(gau_urls)
    except Exception:
        pass

    # Try waybackurls
    try:
        wb_urls = run_waybackurls(domain, workspace_dir)
        all_urls.update(wb_urls)
    except Exception:
        pass

    # Direct CDX API as fallback
    if len(all_urls) < 100:
        cdx_urls = query_wayback_api(domain)
        all_urls.update(cdx_urls)

    urls_list = list(all_urls)

    # Save
    out_file = os.path.join(workspace_dir, 'wayback_urls.txt')
    with open(out_file, 'w') as f:
        for url in urls_list:
            f.write(url + '\n')

    # Extract parameters
    params = extract_interesting_params(urls_list)
    params_file = os.path.join(workspace_dir, 'discovered_params.json')
    import json
    with open(params_file, 'w') as f:
        json.dump(params, f, indent=2)

    logger.info(f"[Wayback] Total historical URLs: {len(urls_list)}, unique params: {len(params)}")
    return urls_list
