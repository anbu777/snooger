import random
from core.utils import random_user_agent

def get_evasion_headers():
    return {
        'User-Agent': random_user_agent(),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'DNT': '1',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
    }

def obfuscate_payload(payload, technique='urlencode'):
    if technique == 'urlencode':
        import urllib.parse
        return urllib.parse.quote(payload)
    elif technique == 'double_urlencode':
        import urllib.parse
        return urllib.parse.quote(urllib.parse.quote(payload))
    elif technique == 'base64':
        import base64
        return base64.b64encode(payload.encode()).decode()
    else:
        return payload