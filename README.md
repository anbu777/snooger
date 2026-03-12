<div align="center">
  <img src="https://raw.githubusercontent.com/snooger/snooger/main/assets/logo.png" alt="Snooger Logo" width="200"/>
  <h1>🛡️ Snooger Pentesting Framework</h1>
  <p><b>An Overpowered, AI-Driven, Intelligent Web Application Security Scanner</b></p>
  <p>
    <a href="https://github.com/snooger-env/snooger"><img src="https://img.shields.io/badge/Maintained%3F-yes-green.svg" alt="Maintenance"></a>
    <a href="https://python.org"><img src="https://img.shields.io/badge/Python-3.10+-blue.svg" alt="Python 3.10+"></a>
    <a href="https://kali.org"><img src="https://img.shields.io/badge/Kali-Linux-black.svg?logo=kali-linux" alt="Kali Linux"></a>
    <a href="https://mit-license.org/"><img src="https://img.shields.io/badge/License-MIT-purple.svg" alt="License: MIT"></a>
  </p>
</div>

---

## 📖 Overview

**Snooger** is a next-generation, asynchronous web application penetration testing framework designed exclusively for **Kali Linux**. Engineered for red teamers, bug bounty hunters, and security researchers, Snooger automates the entire offensive security lifecycle—from reconnaissance and vulnerability discovery to post-exploitation and automated AI reporting.

Powered by a modular plugin architecture and state-of-the-art AI analysis (via Groq/Llama3 and local Ollama inference), Snooger dynamically adapts its payload execution to the target's underlying technology stack, evades WAFs, and hunts for complex exploit chains that traditional scanners miss.

## 🚀 Key Features

### 🔍 Unparalleled Reconnaissance
- **Intelligent Spidering & Crawling**: JavaScript parsing, parameterized URL extraction, and API endpoint discovery.
- **Deep Content Discovery**: Context-aware directory brute-forcing based on detected server technologies.
- **Subdomain Enumeration**: Passive OSINT gathering combined with active bruteforcing, DNS resolution, and takeover validation.
- **Port & Service Scanning**: Rapid `nmap`-like asynchronous port scanning with service banner grabbing.

### 💥 Active Vulnerability Hunting
- **Advanced Injection Detection**: SQLi (Error, Blind, Time-based), XSS (Reflected, Stored, DOM), command injection, CRLF, and Host Header injection.
- **Business Logic Flaws**: Out-of-the-box IDOR detection and access control bypass testing.
- **Server Misconfigurations**: SSTI, XXE, CORS misconfigurations, Open Redirects, and insecure HTTP methods.
- **Exploit Chain Engine**: Automatically links low-severity findings (e.g., Information Disclosure + CSRF) into high-impact exploit chains.

### 🧠 AI-Powered Analysis
- **Smart Remediation**: Integrates with Groq API and local Ollama to provide intelligent, contextual remediation advice and payload mutation suggestions.
- **Automated Reporting**: Generates sleek Markdown and JSON reports featuring AI-summarized executive briefs.
- **Zero-False-Positive Tuning**: AI correlation analyzes responses to filter out standard scanner noise.

### ⚙️ Engine Mechanics
- **Asynchronous Core**: Built on Python `asyncio` and `aiohttp` for blindingly fast, unblocking I/O operations.
- **Out-of-Band (OOB) Testing**: Built-in HTTP/DNS server modules for detecting blind vulnerabilities (Blind SSRF, Blind SQLi).
- **Extensible Event Bus**: A robust messaging system that manages inter-module communication, allowing researchers to write custom plugins easily.
- **Platform Integrations**: Built-in Bugcrowd and HackerOne API submission support, coupled with Telegram and Discord webhook notifications.

## 🛠️ Installation

Snooger is built for **Kali Linux** but will work on most Unix-like environments. 

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/snooger.git
   cd snooger
   ```

2. **Set up a virtual environment (Recommended):**
   ```bash
   python3 -m venv snooger-env
   source snooger-env/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Initialize Submodules & Tools:**
   Ensure you have Go installed on your Kali VM to utilize Nuclei integrations.
   ```bash
   go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
   ```

5. **Configure Environment Variables:**
   Rename `.env.example` to `.env` and fill in your API keys:
   ```bash
   cp .env.example .env
   nano .env
   ```

## 🎯 Usage

Snooger is incredibly intuitive. The CLI offers multiple modes of engagement depending on your required stealth and comprehensiveness.

### Basic Scan
Run a full pentest against a target with default settings:
```bash
python snooger.py -t https://target.com
```

### Stealth Mode + AI
Evade early detection and utilize the Groq/Ollama AI engine for intelligent payload generation:
```bash
python snooger.py -t https://target.com -p stealth --ai-mode smart
```

### Comprehensive Bug Bounty Mode
Initialize everything: Deep crawling, OOB testing, API fuzzing, and Nuclei templates:
```bash
python snooger.py -t https://target.com -p aggressive --crawl-depth 5 --enable-oob
```

### Modular Execution
Only run specific modules (e.g., SQLi and XSS testing):
```bash
python snooger.py -t https://target.com -m sqli,xss
```

## 🏗️ Architecture Design

Snooger is built on a V3 modern framework structure:
- **`core/`**: Contains the `AsyncExecutor`, `EventBus`, `StateManager` (SQLite), and the overarching AI Engine.
- **`modules/`**: The heart of the offensive tooling. Categorized into `reconnaissance`, `scanning`, `vulnerability`, `exploitation`, and `post_exploitation`.
- **`plugins/`**: Drop-in directory for community-driven scripts.
- **`data/`**: Tailored, context-specific wordlists and bypass payloads.

## ⚠️ Disclaimer

Snooger is created for **educational purposes and authorized ethical hacking only**. The contributors and maintainers are not responsible for any misuse, damage, or illegal activities caused by this tool. Always obtain explicit, written permission before scanning any networks or web applications. 

---
<div align="center">
  <i>"Hack the Planet, Responsibly."</i><br>
  Maintained by the Snooger Open Source Community
</div>
