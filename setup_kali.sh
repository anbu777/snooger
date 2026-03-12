#!/bin/bash

# ══════════════════════════════════════════════════════════════════════════════
# Snooger v3.0 — Kali Linux Environment Setup Script
# ══════════════════════════════════════════════════════════════════════════════

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}====================================================${NC}"
echo -e "${BLUE}    Snooger Pentesting Framework — Environment Setup  ${NC}"
echo -e "${BLUE}====================================================${NC}"

# 1. System Updates
echo -e "\n${YELLOW}[+] Updating system packages...${NC}"
sudo apt update -y

# 2. Install Core Apt Tools
echo -e "\n${YELLOW}[+] Installing core security tools from apt...${NC}"
sudo apt install -y git jq curl golang python3-pip python3-venv \
    nmap masscan ffuf gobuster dirsearch sqlmap commix wpscan \
    amass assetfinder seclists wordlists

# Update PATH permanently in .bashrc if not exists
if ! grep -q "go/bin" "$HOME/.bashrc"; then
    echo 'export GOPATH=$HOME/go' >> "$HOME/.bashrc"
    echo 'export PATH=$PATH:$GOPATH/bin' >> "$HOME/.bashrc"
    echo -e "${YELLOW}[!] Added go/bin to .bashrc. Please run 'source ~/.bashrc' after setup.${NC}"
fi

# 3. Install ProjectDiscovery Tools & Go-based Tools
echo -e "\n${YELLOW}[+] Installing Go-based advanced tools...${NC}"
# Setup Go path
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin
mkdir -p $GOPATH/bin

# Install via go (always get latest)
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/s0md3v/Arjun@latest
go install -v github.com/lukasikic/subzy@latest

# 4. Install Python Environment
echo -e "\n${YELLOW}[+] Setting up Python Virtual Environment...${NC}"
if [ ! -d "snooger-env" ]; then
    python3 -m venv snooger-env
fi
source snooger-env/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# 5. Optional: Install Ollama (AI Local)
if ! command -v ollama &> /dev/null; then
    echo -e "\n${YELLOW}[+] Installing Ollama (Local AI Engine)...${NC}"
    curl -fsSL https://ollama.com/install.sh | sh
fi

# 6. Ensure Wordlists are linked
if [ ! -d "/usr/share/seclists" ]; then
    echo -e "\n${YELLOW}[+] SecLists not found in default path. Cloning...${NC}"
    sudo git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists
fi

echo -e "\n${GREEN}====================================================${NC}"
echo -e "${GREEN}    Setup Complete! Your Kali is now Overpowered.    ${NC}"
echo -e "${GREEN}====================================================${NC}"
echo -e "${YELLOW}Untuk memverifikasi, jalankan: python core/health_check.py${NC}"
