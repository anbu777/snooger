"""
Core Utilities v3.0 — shared helper functions for the Snooger framework.
Async-compatible variants included.
"""
import os
import re
import json
import time
import random
import hashlib
import logging
import subprocess
import shutil
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime
from urllib.parse import urlparse

logger = logging.getLogger('snooger')

# ─── User-Agent Pool ─────────────────────────────────────────────────
USER_AGENTS = [
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36",
]


def random_user_agent() -> str:
    """Get a random user agent string."""
    try:
        from fake_useragent import UserAgent
        return UserAgent().random
    except Exception:
        return random.choice(USER_AGENTS)


# ─── Command Execution ───────────────────────────────────────────────

def run_command(cmd: str, timeout: int = 300, cwd: Optional[str] = None,
                env: Optional[dict] = None) -> Tuple[str, str, int]:
    """
    Run a shell command safely.
    Returns: (stdout, stderr, returncode)
    """
    try:
        if isinstance(cmd, str):
            import shlex
            cmd_list = shlex.split(cmd)
        else:
            cmd_list = cmd

        import threading
        import sys
        
        stop_spinner = False
        def spinner():
            chars = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
            i = 0
            # Get just the tool name for display
            tool_display = cmd_list[0] if cmd_list else "command"
            sys.stdout.write(f"\033[36m    [~] Running {tool_display} \033[0m")
            sys.stdout.flush()
            
            # Record start time
            start = time.time()
            
            while not stop_spinner:
                elapsed = int(time.time() - start)
                sys.stdout.write(f"\r\033[36m    [{chars[i]}] Running {tool_display} ({elapsed}s elapsed) \033[0m")
                sys.stdout.flush()
                i = (i + 1) % len(chars)
                time.sleep(0.1)
            
            # Clear spinner line when done
            sys.stdout.write(f"\r\033[K")
            sys.stdout.flush()

        # Start spinner thread
        t = threading.Thread(target=spinner)
        t.daemon = True
        t.start()

        try:
            proc = subprocess.run(
                cmd_list,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd,
                env=env,
            )
        finally:
            stop_spinner = True
            t.join(timeout=1.0)

        return proc.stdout, proc.stderr, proc.returncode

    except subprocess.TimeoutExpired:
        logger.error(f"Command timeout ({timeout}s): {cmd[:80]}")
        return "", f"Timeout after {timeout}s", -1
    except FileNotFoundError as e:
        logger.debug(f"Tool not found: {e}")
        return "", str(e), -2
    except Exception as e:
        logger.error(f"Command error: {e}")
        return "", str(e), -3


# ─── File Operations ─────────────────────────────────────────────────

def write_json(filepath: str, data: Any, indent: int = 2) -> None:
    """Write data to a JSON file."""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=indent, default=str, ensure_ascii=False)


def load_json_file(filepath: str, default=None) -> Any:
    """Load JSON file or return default."""
    if not os.path.exists(filepath):
        return default if default is not None else {}
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.warning(f"Cannot load JSON: {filepath}: {e}")
        return default if default is not None else {}


def load_jsonl_file(filepath: str) -> List[dict]:
    """Load JSONL (one JSON per line) file."""
    results = []
    if not os.path.exists(filepath):
        return results
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        results.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
    except OSError:
        pass
    return results


def save_raw_output(workspace_dir: str, category: str, tool_name: str, content: str, ext: str = 'txt') -> str:
    """Save raw command output to workspace."""
    raw_dir = os.path.join(workspace_dir, 'raw', category)
    os.makedirs(raw_dir, exist_ok=True)
    filename = f"{tool_name}.{ext}" if ext else tool_name
    filepath = os.path.join(raw_dir, filename)
    with open(filepath, 'w', encoding='utf-8', errors='ignore') as f:
        f.write(content)
    return filepath


def load_payload_file(filename: str) -> List[str]:
    """Load payloads from data/payloads/ directory."""
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    filepath = os.path.join(base, 'data', 'payloads', filename)
    if not os.path.exists(filepath):
        logger.warning(f"Payload file not found: {filepath}")
        return []
    with open(filepath, 'r', encoding='utf-8') as f:
        return [l.strip() for l in f if l.strip() and not l.startswith('#')]


def load_wordlist(filename: str) -> List[str]:
    """Load wordlist from data/wordlists/ directory."""
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    filepath = os.path.join(base, 'data', 'wordlists', filename)
    if not os.path.exists(filepath):
        logger.warning(f"Wordlist not found: {filepath}")
        return []
    with open(filepath, 'r', encoding='utf-8') as f:
        return [l.strip() for l in f if l.strip() and not l.startswith('#')]


# ─── URL / Domain Utilities ──────────────────────────────────────────

def sanitize_domain(target: str) -> str:
    """Extract clean domain from target input."""
    target = target.strip()
    if '://' in target:
        parsed = urlparse(target)
        return parsed.netloc or parsed.path
    return target.split('/')[0]


def sanitize_url(target: str) -> str:
    """Ensure target has a URL scheme."""
    target = target.strip()
    if not target.startswith(('http://', 'https://')):
        return f"https://{target}"
    return target


def extract_domain(url: str) -> str:
    """Extract domain from URL."""
    try:
        parsed = urlparse(url)
        return parsed.netloc or parsed.path.split('/')[0]
    except Exception:
        return url


def normalize_url(url: str) -> str:
    """Normalize URL for deduplication."""
    url = url.strip().rstrip('/')
    if not url.startswith(('http://', 'https://')):
        url = f"https://{url}"
    return url


# ─── Hashing & Dedup ─────────────────────────────────────────────────

def hash_finding(finding: dict) -> str:
    """Generate unique hash for a finding to prevent duplicates."""
    key_parts = [
        str(finding.get('type', '')),
        str(finding.get('url', finding.get('matched-at', ''))),
        str(finding.get('severity', '')),
        str(finding.get('matched-at', '')),
    ]
    key = '|'.join(key_parts)
    return hashlib.md5(key.encode()).hexdigest()


# ─── Tool Checking ───────────────────────────────────────────────────

def check_tool(tool_name: str) -> bool:
    """Check if an external tool is available."""
    return shutil.which(tool_name) is not None


def check_tools(tool_names: List[str]) -> Dict[str, bool]:
    """Check multiple tools and return availability map."""
    return {name: check_tool(name) for name in tool_names}


def get_tool_version(tool_name: str) -> Optional[str]:
    """Get version of an installed tool."""
    for flag in ['--version', '-version', '-v', 'version']:
        stdout, _, code = run_command(f"{tool_name} {flag}", timeout=5)
        if code == 0 and stdout.strip():
            # Extract version number
            match = re.search(r'(\d+\.\d+[\.\d]*)', stdout)
            if match:
                return match.group(1)
    return None


# ─── Timing ──────────────────────────────────────────────────────────

def adaptive_sleep(response=None, min_delay: float = 0.3,
                   max_delay: float = 2.0) -> None:
    """Sleep adaptively based on server response."""
    delay = random.uniform(min_delay, max_delay)
    if response:
        status = getattr(response, 'status_code', getattr(response, 'status', 200))
        if status == 429:
            delay = max(delay, 5.0)
            logger.debug("Rate limited — waiting 5s")
        elif status >= 500:
            delay = max(delay, 2.0)
    time.sleep(delay)


# ─── URL Parsing ─────────────────────────────────────────────────────

def parse_url_params(url: str) -> tuple:
    """
    Parse a URL into base URL and parameters dict.
    Returns: (base_url, params_dict)
    """
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    # Flatten single-value lists
    flat_params = {k: v[0] if len(v) == 1 else v for k, v in params.items()}
    base_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', ''))
    return base_url, flat_params


# ─── File Cleanup ────────────────────────────────────────────────────

def safe_remove(filepath: str) -> bool:
    """Safely remove a file if it exists."""
    try:
        if os.path.exists(filepath):
            os.remove(filepath)
            return True
    except OSError as e:
        logger.debug(f"Cannot remove {filepath}: {e}")
    return False


# ─── Tool Version Check ─────────────────────────────────────────────

def check_tool_version(tool_name: str) -> tuple:
    """
    Check if a tool exists and get its version.
    Returns: (exists: bool, version_info: str)
    """
    path = shutil.which(tool_name)
    if not path:
        return False, f"{tool_name} not found"
    version = get_tool_version(tool_name)
    info = f"{tool_name} {version}" if version else f"{tool_name} (version unknown)"
    return True, info


# ─── CVSS / CWE Helpers ──────────────────────────────────────────────

SEVERITY_CVSS = {
    'critical': 9.5,
    'high': 7.5,
    'medium': 5.0,
    'low': 2.5,
    'info': 0.0,
}

VULN_CWE_MAP = {
    'xss': 'CWE-79',
    'sqli': 'CWE-89',
    'sql_injection': 'CWE-89',
    'ssrf': 'CWE-918',
    'ssti': 'CWE-1336',
    'xxe': 'CWE-611',
    'lfi': 'CWE-98',
    'path_traversal': 'CWE-22',
    'open_redirect': 'CWE-601',
    'idor': 'CWE-639',
    'csrf': 'CWE-352',
    'cors': 'CWE-942',
    'crlf': 'CWE-93',
    'command_injection': 'CWE-78',
    'cmdi': 'CWE-78',
    'rce': 'CWE-94',
    'deserialization': 'CWE-502',
    'nosql_injection': 'CWE-943',
    'jwt': 'CWE-347',
    'broken_auth': 'CWE-287',
    'session_fixation': 'CWE-384',
    'host_header_injection': 'CWE-644',
    'subdomain_takeover': 'CWE-250',
    'exposed_panel': 'CWE-200',
    'information_disclosure': 'CWE-200',
}


def get_cvss_score(severity: str) -> float:
    return SEVERITY_CVSS.get(severity.lower(), 0.0)


def get_cwe_id(vuln_type: str) -> str:
    vuln_lower = vuln_type.lower()
    for key, cwe in VULN_CWE_MAP.items():
        if key in vuln_lower:
            return cwe
    return 'CWE-0'
