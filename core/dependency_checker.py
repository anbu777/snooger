import shutil
import subprocess
import sys
import yaml

def check_dependencies(config_path='config.yaml'):
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
    tools = config['tools']
    missing = []
    for name, cmd in tools.items():
        if shutil.which(cmd) is None:
            missing.append((name, cmd))
    return missing

def print_dependency_report(missing):
    print("\n[DEPENDENCY CHECKER]")
    if not missing:
        print("[OK] Semua tool terinstall.")
    else:
        print("[WARNING] Beberapa tool tidak ditemukan di PATH:")
        for name, cmd in missing:
            print(f"  - {name}: {cmd}")
        print("\nSaran instalasi:")
        for name, cmd in missing:
            if name == 'subfinder':
                print("  subfinder: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
            elif name == 'amass':
                print("  amass: go install -v github.com/OWASP/Amass/v3/...@master")
            elif name == 'assetfinder':
                print("  assetfinder: go install github.com/tomnomnom/assetfinder@latest")
            elif name == 'dnsx':
                print("  dnsx: go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest")
            elif name == 'httpx':
                print("  httpx: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest")
            elif name == 'nuclei':
                print("  nuclei: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
            elif name == 'nmap':
                print("  nmap: sudo apt install nmap")
            elif name == 'sqlmap':
                print("  sqlmap: sudo apt install sqlmap")
            elif name == 'ffuf':
                print("  ffuf: go install github.com/ffuf/ffuf@latest")
            elif name == 'whatweb':
                print("  whatweb: sudo apt install whatweb")
            elif name == 'wpscan':
                print("  wpscan: sudo gem install wpscan")
            elif name == 'xsstrike':
                print("  xsstrike: git clone https://github.com/s0md3v/XSStrike && cd XSStrike && pip install -r requirements.txt")
            elif name == 'commix':
                print("  commix: git clone https://github.com/commixproject/commix.git && cd commix && python setup.py install")
            elif name == 'testssl':
                print("  testssl.sh: git clone --depth 1 https://github.com/drwetter/testssl.sh.git")
            elif name == 'arjun':
                print("  arjun: pip install arjun")
            elif name == 'gobuster':
                print("  gobuster: sudo apt install gobuster")
            elif name == 'dirsearch':
                print("  dirsearch: pip install dirsearch")
            else:
                print(f"  {name}: cek dokumentasi tool {cmd}")
        print()