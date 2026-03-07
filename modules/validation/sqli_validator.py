import os
import json
import requests
from core.utils import run_command, save_raw_output

def quick_sqli_test(url, workspace_dir):
    """
    Run a quick boolean-based test to confirm SQLi without heavy scanning.
    """
    print(f"[Validation] Quick SQLi test on {url}")
    try:
        session = requests.Session()
        base_url = url.split('?')[0]
        params = {}
        if '?' in url:
            qs = url.split('?')[1]
            for pair in qs.split('&'):
                if '=' in pair:
                    k, v = pair.split('=', 1)
                    params[k] = v

        original_resp = session.get(base_url, params=params, timeout=10)
        original_length = len(original_resp.text)

        payloads = [
            ("' OR '1'='1", "' OR '1'='1"),
            ("' OR '1'='1' --", "' OR '1'='1' --"),
            ("1 AND 1=1", "1 AND 1=1"),
            ("1 AND 1=2", "1 AND 1=2")
        ]

        for param in params:
            original = params[param]
            for payload_desc, payload in payloads:
                test_params = params.copy()
                test_params[param] = original + payload
                try:
                    resp = session.get(base_url, params=test_params, timeout=10)
                    if len(resp.text) != original_length or "error" in resp.text.lower():
                        return {
                            'validated': True,
                            'type': 'SQL Injection',
                            'parameter': param,
                            'payload': payload,
                            'evidence': f"Response length changed from {original_length} to {len(resp.text)}"
                        }
                except Exception:
                    pass
    except Exception as e:
        print(f"[Validation] Quick SQLi test error: {e}")
    return {'validated': False}

def validate_sqlmap(url, workspace_dir, extra_params="--batch --dbs --level=1 --risk=1"):
    """
    Validate SQL injection using sqlmap.
    """
    print(f"[Validation] Running sqlmap on {url}")
    out_dir = os.path.join(workspace_dir, 'validation', 'sqlmap')
    os.makedirs(out_dir, exist_ok=True)
    cmd = f"sqlmap -u {url} {extra_params} --output-dir={out_dir}"
    stdout, stderr, rc = run_command(cmd, timeout=300)
    save_raw_output(workspace_dir, 'validation', f'sqlmap_{abs(hash(url))}', stdout + stderr, 'txt')

    if "available databases" in stdout or "vulnerable" in stdout.lower():
        lines = stdout.splitlines()
        dbs = []
        capture = False
        for line in lines:
            if "available databases" in line:
                capture = True
                continue
            if capture and line.strip() and not line.startswith('['):
                dbs.append(line.split()[0] if line.split() else '')
        return {
            'validated': True,
            'type': 'SQL Injection',
            'tool': 'sqlmap',
            'evidence': stdout[:500] + "...",
            'databases': dbs[:5]
        }
    else:
        return {'validated': False, 'tool': 'sqlmap'}