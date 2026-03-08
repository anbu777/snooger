#!/bin/bash
echo "=== Snooger v2.0 Tool Verification ==="
REQUIRED=("subfinder" "httpx" "nuclei" "nmap" "sqlmap" "ffuf")
OPTIONAL=("amass" "assetfinder" "dnsx" "whatweb" "wpscan" "gobuster"
          "dirsearch" "testssl.sh" "arjun" "xsstrike" "commix"
          "subjack" "subzy" "gau" "waybackurls" "interactsh-client" "dig")

echo -e "\n[REQUIRED]"
for tool in "${REQUIRED[@]}"; do
    if command -v "$tool" &>/dev/null; then
        VER=$(${tool} --version 2>&1 | head -1 | cut -c1-50)
        echo "  ✅ $tool: $VER"
    else
        echo "  ❌ $tool: NOT FOUND — REQUIRED"
    fi
done

echo -e "\n[OPTIONAL]"
for tool in "${OPTIONAL[@]}"; do
    if command -v "$tool" &>/dev/null; then
        echo "  ✅ $tool"
    else
        echo "  ○  $tool: not found (optional)"
    fi
done

echo -e "\n[PYTHON]"
python3 --version
pip show fake-useragent pyyaml requests colorama tqdm cryptography jinja2 2>/dev/null | grep -E "^(Name|Version):" | paste - -

echo -e "\n[WORDLISTS]"
WLISTS=("/usr/share/seclists/Discovery/Web-Content/common.txt"
        "/usr/share/wordlists/dirb/common.txt"
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt")
for wl in "${WLISTS[@]}"; do
    [ -f "$wl" ] && echo "  ✅ $wl" || echo "  ○  $wl"
done
