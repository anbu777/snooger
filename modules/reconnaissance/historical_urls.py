"""
Historical URL discovery via Wayback Machine, GAU, and Common Crawl.
"""
import os
import logging
import requests
from typing import List, Set
from core.utils import run_command, save_raw_output
from core.rate_limiter import get_rate_limiter

logger = logging.getLogger('snooger')

def run_waybackurls(domain: str, workspace_dir: str) -> List[str]:
    """Get historical URLs from Wayback Machine via waybackurls."""
    logger.info(f"Running waybackurls for {domain}")
    cmd = f"waybackurls {domain}"
    stdout, stderr, rc = run_command(cmd, timeout=120)
    if rc < 0:
        # Fallback to direct Wayback Machine API
        return _query_wayback_api(domain, workspace_dir)
    save_raw_output(workspace_dir, 'recon', 'waybackurls', stdout, 'txt')
    urls = [u.strip() for u in stdout.splitlines() if u.strip() and 'http' in u]
    logger.info(f"waybackurls: {len(urls)} URLs")
    return urls

def _query_wayback_api(domain: str, workspace_dir: str) -> List[str]:
    """Fallback: query Wayback CDX API directly."""
    logger.info(f"Querying Wayback Machine CDX API for {domain}")
    rl = get_rate_limiter()
    rl.wait('web.archive.org')
    try:
        resp = requests.get(
            f"http://web.archive.org/cdx/search/cdx",
            params={
                'url': f"*.{domain}/*",
                'output': 'json',
                'fl': 'original',
                'collapse': 'urlkey',
                'limit': 5000,
                'filter': 'statuscode:200'
            },
            timeout=45
        )
        if resp.status_code == 200:
            data = resp.json()
            urls = [row[0] for row in data[1:] if row]  # skip header
            save_raw_output(workspace_dir, 'recon', 'wayback_api', '\n'.join(urls), 'txt')
            logger.info(f"Wayback CDX API: {len(urls)} URLs")
            return urls
    except Exception as e:
        logger.warning(f"Wayback CDX API failed: {e}")
    return []

def run_gau(domain: str, workspace_dir: str) -> List[str]:
    """Get URLs via gau (GetAllUrls)."""
    logger.info(f"Running gau for {domain}")
    cmd = f"gau --subs {domain} --providers wayback,commoncrawl,otx,urlscan"
    stdout, stderr, rc = run_command(cmd, timeout=180)
    if rc < 0:
        logger.warning("gau not available")
        return []
    save_raw_output(workspace_dir, 'recon', 'gau', stdout, 'txt')
    urls = [u.strip() for u in stdout.splitlines() if u.strip() and 'http' in u]
    logger.info(f"gau: {len(urls)} URLs")
    return urls

def get_all_historical_urls(domain: str, workspace_dir: str) -> List[str]:
    """Combine all historical URL sources."""
    all_urls: Set[str] = set()

    for func in [run_waybackurls, run_gau]:
        try:
            urls = func(domain, workspace_dir)
            all_urls.update(urls)
        except Exception as e:
            logger.error(f"{func.__name__} failed: {e}")

    result = sorted(all_urls)
    if result:
        with open(os.path.join(workspace_dir, 'historical_urls.txt'), 'w') as f:
            f.write('\n'.join(result))
        logger.info(f"Total historical URLs: {len(result)}")
    return result

def extract_interesting_params(urls: List[str]) -> dict:
    """Extract parameter names from historical URLs for targeted testing."""
    from urllib.parse import urlparse, parse_qs
    param_count = {}
    param_urls = {}
    for url in urls:
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            for param in params:
                param_count[param] = param_count.get(param, 0) + 1
                if param not in param_urls:
                    param_urls[param] = url
        except Exception:
            continue
    # Sort by frequency
    sorted_params = sorted(param_count.items(), key=lambda x: x[1], reverse=True)
    return {
        'top_params': [{'param': p, 'count': c, 'example_url': param_urls[p]}
                       for p, c in sorted_params[:50]],
        'total_urls': len(urls),
        'total_params': len(param_count)
    }
