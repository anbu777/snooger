import subprocess
import os
import json
import random
import time
import re
import shlex
import logging
from typing import Tuple, Optional, List

logger = logging.getLogger('snooger')

# Extended User-Agent list
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.90 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
]

def sanitize_domain(domain: str) -> str:
    """Sanitize domain to prevent command injection."""
    # Only allow valid hostname/URL characters
    domain = domain.strip()
    # Remove protocol if present for validation
    clean = re.sub(r'^https?://', '', domain)
    clean = clean.split('/')[0].split('?')[0].split('#')[0]
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\-\.]*[a-zA-Z0-9]$', clean):
        raise ValueError(f"Invalid domain/host: {clean!r}")
    return domain

def sanitize_url(url: str) -> str:
    """Validate URL is well-formed."""
    url = url.strip()
    if not re.match(r'^https?://', url):
        raise ValueError(f"URL must start with http:// or https://: {url!r}")
    # Block private/metadata IPs
    dangerous_patterns = [
        r'169\.254\.169\.254',  # AWS metadata
        r'metadata\.google\.internal',
        r'100\.100\.100\.200',  # Alibaba metadata
        r'fd00:',               # IPv6 private
        r'127\.',               # localhost
        r'0\.0\.0\.0',
    ]
    for pat in dangerous_patterns:
        if re.search(pat, url, re.IGNORECASE):
            logger.warning(f"Blocked potentially dangerous URL: {url}")
            raise ValueError(f"URL targets a restricted/metadata address: {url}")
    return url

def run_command(cmd: str, cwd: Optional[str] = None, timeout: int = 300,
                env: Optional[dict] = None) -> Tuple[str, str, int]:
    """
    Run a shell command safely with timeout.
    Uses shlex parsing to avoid injection.
    Returns (stdout, stderr, returncode).
    """
    try:
        # Split command safely
        args = shlex.split(cmd)
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            cwd=cwd,
            timeout=timeout,
            env={**os.environ, **(env or {})},
            shell=False  # Never use shell=True
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out after {timeout}s: {cmd[:100]}")
        return "", f"Timeout after {timeout}s", -1
    except FileNotFoundError as e:
        logger.error(f"Tool not found: {e}")
        return "", str(e), -2
    except Exception as e:
        logger.error(f"Command error: {e} | cmd: {cmd[:100]}")
        return "", str(e), -3

def save_raw_output(workspace_dir: str, phase: str, tool_name: str,
                    content: str, ext: str = 'txt') -> str:
    raw_dir = os.path.join(workspace_dir, 'raw_logs', phase)
    os.makedirs(raw_dir, exist_ok=True)
    fname = f"{tool_name}.{ext}"
    fpath = os.path.join(raw_dir, fname)
    try:
        with open(fpath, 'w', encoding='utf-8', errors='replace') as f:
            f.write(content)
    except OSError as e:
        logger.error(f"Failed to save raw output {fpath}: {e}")
    return fpath

def load_json_file(filepath: str) -> Optional[dict]:
    if not os.path.exists(filepath):
        return None
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        logger.warning(f"JSON parse error in {filepath}: {e}")
        return None
    except OSError as e:
        logger.error(f"Cannot read {filepath}: {e}")
        return None

def load_jsonl_file(filepath: str) -> List[dict]:
    results = []
    if not os.path.exists(filepath):
        return results
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError as e:
                    logger.debug(f"JSONL parse error at line {lineno} in {filepath}: {e}")
    except OSError as e:
        logger.error(f"Cannot read {filepath}: {e}")
    return results

def safe_remove(filepath: str) -> None:
    """Remove a file, swallowing errors gracefully."""
    try:
        if os.path.exists(filepath):
            os.remove(filepath)
    except OSError as e:
        logger.debug(f"Failed to remove {filepath}: {e}")

def random_user_agent() -> str:
    try:
        from fake_useragent import UserAgent
        ua = UserAgent()
        return ua.random
    except Exception:
        return random.choice(USER_AGENTS)

def adaptive_sleep(response_code: int, base_delay: float = 0.5) -> float:
    """Return appropriate sleep time based on HTTP response code."""
    if response_code in (429, 503, 503):
        delay = base_delay * 5
        logger.warning(f"Rate limited (HTTP {response_code}), sleeping {delay:.1f}s")
        time.sleep(delay)
        return delay
    elif response_code in (500, 502, 504):
        delay = base_delay * 2
        time.sleep(delay)
        return delay
    time.sleep(base_delay)
    return base_delay

def write_json(filepath: str, data) -> bool:
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return True
    except OSError as e:
        logger.error(f"Failed to write JSON to {filepath}: {e}")
        return False

def parse_url_params(url: str) -> Tuple[str, dict]:
    """Parse URL into base and params dict."""
    base = url.split('?')[0]
    params = {}
    if '?' in url:
        qs = url.split('?')[1].split('#')[0]
        for pair in qs.split('&'):
            if '=' in pair:
                k, v = pair.split('=', 1)
                params[k] = v
    return base, params

def check_tool_version(tool_name: str, min_version: Optional[str] = None) -> Tuple[bool, str]:
    """Check if tool exists and optionally its version."""
    import shutil
    path = shutil.which(tool_name)
    if not path:
        return False, "not found"
    if not min_version:
        return True, path
    # Try to get version
    stdout, _, rc = run_command(f"{tool_name} --version", timeout=10)
    if rc == 0 or stdout:
        return True, stdout.strip().split('\n')[0]
    return True, "version unknown"
