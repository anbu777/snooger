"""
Content discovery with tech-aware wordlist selection and adaptive rate limiting.
"""
import os
import json
import logging
from typing import List, Optional
from core.utils import run_command, save_raw_output, safe_remove, load_json_file
from core.rate_limiter import get_rate_limiter

logger = logging.getLogger('snooger')

# Wordlist priority order
WORDLIST_PATHS = [
    "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
    "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
]

# Tech-specific wordlists
TECH_WORDLISTS = {
    'wordpress': '/usr/share/seclists/Discovery/Web-Content/CMS/wordpress.fuzz.txt',
    'drupal': '/usr/share/seclists/Discovery/Web-Content/CMS/drupal.txt',
    'joomla': '/usr/share/seclists/Discovery/Web-Content/CMS/joomla.txt',
    'spring': '/usr/share/seclists/Discovery/Web-Content/spring-boot.txt',
    'api': '/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt',
    'backup': '/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt',
}

SENSITIVE_FILES_WORDLIST = [
    ".git/HEAD", ".git/config", ".env", ".env.local", ".env.production",
    "backup.zip", "backup.sql", "db.sql", "database.sql", "dump.sql",
    "phpinfo.php", "info.php", "test.php", "config.php", "wp-config.php",
    "config.json", "config.yml", "config.yaml", "settings.py",
    "package.json", "composer.json", "Gemfile", "requirements.txt",
    "swagger.json", "openapi.json", "openapi.yaml", "api-docs.json",
    "robots.txt", "sitemap.xml", ".htaccess", "web.config",
    "crossdomain.xml", "clientaccesspolicy.xml",
    "/.well-known/security.txt", "/.well-known/change-password",
    "/server-status", "/server-info", "/.git/", "/.svn/",
    "/WEB-INF/web.xml", "/WEB-INF/classes/", "/META-INF/",
    "/actuator", "/actuator/health", "/actuator/env", "/actuator/mappings",
    "/actuator/dump", "/actuator/heapdump", "/actuator/logfile",
    "/trace", "/metrics", "/health", "/debug", "/console",
    "/.DS_Store", "/Thumbs.db", "/.idea/", "/.vscode/",
    "/adminer.php", "/phpmyadmin/", "/admin/", "/administrator/",
    "/panel/", "/dashboard/", "/cpanel/", "/webmail/",
    "/old/", "/backup/", "/bak/", "/temp/", "/tmp/",
]

def get_wordlist(tech_stack: Optional[List[str]] = None) -> str:
    """Select best available wordlist, optionally based on tech stack."""
    # Try tech-specific first
    if tech_stack:
        for tech in tech_stack:
            for key, wl_path in TECH_WORDLISTS.items():
                if key in tech.lower() and os.path.exists(wl_path):
                    logger.info(f"Using tech-specific wordlist for {key}: {wl_path}")
                    return wl_path

    # Fall back to general wordlists
    for wl in WORDLIST_PATHS:
        if os.path.exists(wl):
            logger.info(f"Using wordlist: {wl}")
            return wl

    return ""

def generate_custom_wordlist(domain: str, page_content: str, workspace_dir: str) -> str:
    """Generate domain-specific wordlist from page content and domain name."""
    words = set()

    # Words from domain name
    domain_clean = domain.replace('www.', '').split('.')[0]
    words.add(domain_clean)
    words.add(f"{domain_clean}-admin")
    words.add(f"{domain_clean}-api")
    words.add(f"api.{domain_clean}")

    # Words from page content
    import re
    content_words = set(re.findall(r'\b[a-zA-Z][a-zA-Z0-9_-]{2,20}\b', page_content))
    common_ignore = {'the', 'and', 'for', 'not', 'this', 'that', 'with', 'from',
                     'have', 'are', 'but', 'was', 'been', 'more', 'will', 'your'}
    words.update(w.lower() for w in content_words if w.lower() not in common_ignore)

    # Add common paths
    words.update(['api', 'admin', 'v1', 'v2', 'v3', 'user', 'users', 'account',
                  'accounts', 'auth', 'login', 'logout', 'register', 'signup',
                  'dashboard', 'panel', 'backend', 'internal', 'private',
                  'upload', 'uploads', 'file', 'files', 'media', 'static',
                  'assets', 'img', 'images', 'css', 'js', 'fonts'])

    wordlist_file = os.path.join(workspace_dir, 'custom_wordlist.txt')
    with open(wordlist_file, 'w') as f:
        f.write('\n'.join(sorted(words)))
    logger.info(f"Generated custom wordlist with {len(words)} words")
    return wordlist_file

def check_sensitive_files(base_url: str, workspace_dir: str,
                          cookies_file: Optional[str] = None) -> List[dict]:
    """Check for exposed sensitive files with soft-404 detection."""
    logger.info(f"Checking for sensitive file exposure on {base_url}")
    rl = get_rate_limiter()
    import requests
    import hashlib
    import uuid

    found = []
    base = base_url.rstrip('/')

    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)'})

    if cookies_file and os.path.exists(cookies_file):
        import http.cookiejar
        cj = http.cookiejar.MozillaCookieJar(cookies_file)
        try:
            cj.load()
            session.cookies.update(cj)
        except Exception:
            pass

    # ── Soft-404 Baseline Detection ──────────────────────────────────
    # Request a random non-existent path to fingerprint the server's
    # default "not found" page (even if it returns HTTP 200).
    baseline_hash = None
    baseline_length = None
    baseline_lengths = set()  # Track multiple baseline sizes
    try:
        for _ in range(2):  # Two random paths for accuracy
            random_path = f"nonexistent_{uuid.uuid4().hex[:12]}.html"
            rl.wait(base_url)
            bl_resp = session.get(f"{base}/{random_path}", timeout=8, allow_redirects=False)
            if bl_resp.status_code == 200:
                bl_hash = hashlib.md5(bl_resp.content).hexdigest()
                bl_len = len(bl_resp.content)
                if baseline_hash is None:
                    baseline_hash = bl_hash
                    baseline_length = bl_len
                baseline_lengths.add(bl_len)
                logger.info(f"Soft-404 baseline: status=200, length={bl_len}, hash={bl_hash[:8]}...")
    except Exception as e:
        logger.debug(f"Baseline detection error: {e}")

    # Track content lengths to detect bulk false positives
    length_counter: dict = {}

    for path in SENSITIVE_FILES_WORDLIST:
        try:
            rl.wait(base_url)
            url = f"{base}/{path.lstrip('/')}"
            resp = session.get(url, timeout=8, allow_redirects=False)
            if resp.status_code in (200, 403):
                content_len = len(resp.content)
                content_hash = hashlib.md5(resp.content).hexdigest()

                # Don't add 403 without content
                if resp.status_code == 403 and content_len < 100:
                    continue

                # ── Soft-404 Filter ──────────────────────────────────
                if resp.status_code == 200 and baseline_hash:
                    # Skip if content hash matches baseline (identical page)
                    if content_hash == baseline_hash:
                        logger.debug(f"  [SOFT-404] {path} — matches baseline hash, skipping")
                        continue
                    # Skip if content length matches baseline (same-size generic page)
                    if content_len in baseline_lengths:
                        logger.debug(f"  [SOFT-404] {path} — matches baseline length ({content_len}), skipping")
                        continue

                # Track how many paths return the same content length
                length_counter[content_len] = length_counter.get(content_len, 0) + 1

                item = {
                    'url': url,
                    'path': path,
                    'status_code': resp.status_code,
                    'content_length': content_len,
                    'content_type': resp.headers.get('content-type', ''),
                    'content_hash': content_hash,
                }
                found.append(item)
                severity = 'high' if resp.status_code == 200 else 'medium'
                logger.warning(f"  [{resp.status_code}] {path} ({content_len} bytes) — {severity}")
                if resp.status_code == 200:
                    rl.penalize(base_url, 0.5)  # slow down on hits
        except Exception as e:
            logger.debug(f"Error checking {path}: {e}")

    # ── Post-scan: Remove bulk false positives ───────────────────────
    # If 4+ paths share the same content length, they're likely all
    # generic pages (another form of soft-404 not caught by baseline).
    suspicious_lengths = {l for l, c in length_counter.items() if c >= 4}
    if suspicious_lengths:
        before_count = len(found)
        found = [f for f in found if f['content_length'] not in suspicious_lengths]
        filtered = before_count - len(found)
        if filtered > 0:
            logger.info(f"Filtered {filtered} likely soft-404 results (identical content lengths: {suspicious_lengths})")

    if found:
        import json
        with open(os.path.join(workspace_dir, 'sensitive_files.json'), 'w') as f:
            json.dump(found, f, indent=2)
        logger.info(f"Found {len(found)} verified sensitive file exposures")
    else:
        logger.info("No genuine sensitive file exposures found (soft-404s filtered)")
    return found

def discover_content(domain: str, workspace_dir: str,
                     wordlist: Optional[str] = None,
                     tech_stack: Optional[List[str]] = None,
                     threads: int = 20,
                     delay: float = 0.5,
                     cookies_file: Optional[str] = None) -> dict:
    """Run ffuf directory brute force with smart settings."""
    logger.info(f"Starting content discovery for {domain}")

    if wordlist is None or not os.path.exists(wordlist):
        wordlist = get_wordlist(tech_stack)

    if wordlist is None:
        logger.warning("No wordlist found. Using built-in minimal wordlist.")
        wordlist = os.path.join(workspace_dir, 'temp_wordlist.txt')
        with open(wordlist, 'w') as f:
            f.write('\n'.join(['admin', 'login', 'api', 'backup', 'config', 'test',
                               'upload', 'uploads', 'static', 'assets', 'media',
                               'v1', 'v2', 'dashboard', 'panel', 'internal',
                               '.git', '.env', 'swagger', 'graphql', 'actuator']))

    output_file = os.path.join(workspace_dir, 'ffuf_output.json')
    if domain.startswith('http'):
        base_url = domain.rstrip('/') + '/FUZZ'
    else:
        base_url = f"https://{domain}/FUZZ"

    cmd = (f"ffuf -u {base_url} -w {wordlist} -ac -of json -o {output_file} "
           f"-t {threads} -p {delay} -timeout 10 -fc 404,400 "
           f"-mc 200,201,202,204,301,302,307,401,403,405,500")

    if cookies_file and os.path.exists(cookies_file):
        with open(cookies_file, 'r') as f:
            cookie_lines = [l for l in f if not l.startswith('#') and '\t' in l]
        cookie_parts = []
        for line in cookie_lines:
            parts = line.strip().split('\t')
            if len(parts) >= 7:
                cookie_parts.append(f"{parts[5]}={parts[6]}")
        if cookie_parts:
            cookie_str = '; '.join(cookie_parts)
            cmd += f" -H 'Cookie: {cookie_str}'"

    logger.info(f"Running ffuf with {threads} threads, {delay}s delay...")
    # Increase timeout for stealth scans with large wordlists
    stdout, stderr, rc = run_command(cmd, timeout=7200)
    save_raw_output(workspace_dir, 'recon', 'ffuf', stdout + stderr, 'txt')

    results = {'paths': [], 'count': 0}
    if os.path.exists(output_file):
        data = load_json_file(output_file)
        if data and 'results' in data:
            results['paths'] = data['results']
            results['count'] = len(data['results'])
            logger.info(f"ffuf found {results['count']} paths")
        elif data:
            results['paths'] = data if isinstance(data, list) else [data]
            results['count'] = len(results['paths'])

    # Also check sensitive files
    results['sensitive_files'] = check_sensitive_files(
        domain if domain.startswith('http') else f"https://{domain}",
        workspace_dir, cookies_file
    )

    # Parse robots.txt and sitemap.xml
    results['robots'] = _parse_robots(domain)
    results['sitemap'] = _parse_sitemap(domain)

    return results

def _parse_robots(domain: str) -> List[str]:
    """Extract paths from robots.txt."""
    import requests
    try:
        base = domain if domain.startswith('http') else f"https://{domain}"
        resp = requests.get(f"{base.rstrip('/')}/robots.txt", timeout=10)
        if resp.status_code == 200:
            paths = []
            for line in resp.text.splitlines():
                if line.lower().startswith(('disallow:', 'allow:')):
                    path = line.split(':', 1)[1].strip()
                    if path and path != '/':
                        paths.append(path)
            if paths:
                logger.info(f"robots.txt: {len(paths)} paths found")
            return paths
    except Exception:
        pass
    return []

def _parse_sitemap(domain: str) -> List[str]:
    """Extract URLs from sitemap.xml."""
    import requests
    import re
    urls = []
    try:
        base = domain if domain.startswith('http') else f"https://{domain}"
        resp = requests.get(f"{base.rstrip('/')}/sitemap.xml", timeout=10)
        if resp.status_code == 200:
            urls = re.findall(r'<loc>(.*?)</loc>', resp.text)
            if urls:
                logger.info(f"sitemap.xml: {len(urls)} URLs found")
    except Exception:
        pass
    return urls
