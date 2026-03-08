import shutil
import logging
from typing import List, Tuple, Dict
from core.utils import check_tool_version

logger = logging.getLogger('snooger')

TOOL_INSTALL_HINTS = {
    'subfinder': 'go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
    'amass': 'go install -v github.com/owasp-amass/amass/v4/...@master',
    'assetfinder': 'go install github.com/tomnomnom/assetfinder@latest',
    'dnsx': 'go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest',
    'httpx': 'go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest',
    'nuclei': 'go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest',
    'nmap': 'sudo apt install nmap',
    'sqlmap': 'sudo apt install sqlmap',
    'ffuf': 'go install github.com/ffuf/ffuf/v2@latest',
    'whatweb': 'sudo apt install whatweb',
    'wpscan': 'sudo gem install wpscan',
    'xsstrike': 'pipx install xsstrike',
    'commix': 'sudo apt install commix',
    'testssl': 'sudo apt install testssl.sh',
    'arjun': 'pipx install arjun',
    'gobuster': 'sudo apt install gobuster',
    'dirsearch': 'sudo apt install dirsearch',
    'subjack': 'go install github.com/haccer/subjack@latest',
    'subzy': 'go install -v github.com/PentestPad/subzy@latest',
    'gau': 'go install github.com/lc/gau/v2/cmd/gau@latest',
    'waybackurls': 'go install github.com/tomnomnom/waybackurls@latest',
    'interactsh_client': 'go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest',
}

REQUIRED_TOOLS = [
    'subfinder', 'httpx', 'nuclei', 'nmap', 'sqlmap', 'ffuf'
]

OPTIONAL_TOOLS = [
    'amass', 'assetfinder', 'dnsx', 'whatweb', 'wpscan', 'xsstrike',
    'commix', 'testssl', 'arjun', 'gobuster', 'dirsearch',
    'subjack', 'subzy', 'gau', 'waybackurls', 'interactsh_client'
]

def check_dependencies(config: dict) -> Tuple[List[Tuple[str, str]], List[Tuple[str, str]]]:
    """
    Returns (missing_required, missing_optional) lists of (name, install_hint).
    """
    tools = config.get('tools', {})
    missing_required = []
    missing_optional = []

    for name, cmd in tools.items():
        exists, info = check_tool_version(cmd)
        if not exists:
            hint = TOOL_INSTALL_HINTS.get(name, f'check documentation for {cmd}')
            if name in REQUIRED_TOOLS:
                missing_required.append((name, hint))
            else:
                missing_optional.append((name, hint))

    return missing_required, missing_optional

def print_dependency_report(missing_required: list, missing_optional: list) -> None:
    from colorama import Fore, Style
    print(f"\n{'='*60}")
    print("  DEPENDENCY CHECKER")
    print(f"{'='*60}")

    if not missing_required and not missing_optional:
        print(f"{Fore.GREEN}[OK] All tools installed.{Style.RESET_ALL}")
    else:
        if missing_required:
            print(f"\n{Fore.RED}[REQUIRED — MISSING]{Style.RESET_ALL}")
            for name, hint in missing_required:
                print(f"  {Fore.RED}✗{Style.RESET_ALL} {name}")
                print(f"    Install: {hint}")
        if missing_optional:
            print(f"\n{Fore.YELLOW}[OPTIONAL — MISSING]{Style.RESET_ALL}")
            for name, hint in missing_optional:
                print(f"  {Fore.YELLOW}○{Style.RESET_ALL} {name}")
                print(f"    Install: {hint}")
    print()
