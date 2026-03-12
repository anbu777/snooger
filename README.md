# 🕷️ Snooger v3.0

> **An overpowered, AI-driven, asynchronous penetration testing framework.**

Snooger v3.0 is a complete overhaul of the original framework, designed specifically for professional bug bounty hunters and penetration testers on Kali Linux. It combines high-speed asynchronous enumeration with an intelligent multi-provider AI engine to prioritize vulnerabilities, suggest payloads, and triage false positives.

![Kali Linux Supported](https://img.shields.io/badge/OS-Kali_Linux-blue?style=flat-square&logo=kalilinux)
![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-green?style=flat-square&logo=python)
![AsyncIO](https://img.shields.io/badge/Architecture-Async-purple?style=flat-square)

---

## 🔥 Key Features

- **⚡ Async Engine:** Built on `asyncio` and `aiohttp` for blistering fast parallel execution, rate limiting, and connection pooling.
- **🤖 Multi-Provider AI (Auto-Fallback):** Support for Local AI (Ollama) and Free Cloud AI (Groq, DeepSeek). Automatically prioritizes critical findings, suggests context-aware payloads, and triages false positives.
- **💉 Massive Payload Database:** Over **2,000+ real-world payloads** meticulously categorized (XSS, SQLi, SSTI, LFI, SSRF, RCE, XXE, JWT, Polyglots, and more), including advanced WAF bypasses.
- **🔌 Extensible Plugin System:** Easily write custom `BaseScanner` plugins and drop them into the `plugins/` folder for auto-discovery.
- **📡 Event-Driven Architecture:** Decoupled Pub/Sub `EventBus` handles real-time inter-module communication.
- **📊 State Management:** Resumable scans and delta reporting. Never lose progress during a long engagement.
- **🔔 Real-time Notifications:** Instant alerts via **Telegram** and **Discord** webhooks when critical vulnerabilities are found.
- **🛠️ Platform Integration:** Direct submission to **HackerOne** and **Bugcrowd** (Draft mode supported), generating professional-grade AI PoC writeups automatically.

## ⚙️ Prerequisites

Snooger is designed and tested exclusively for **Kali Linux**.

```bash
# Clone the repository
git clone https://github.com/yourusername/snooger.git
cd snooger

# Install dependencies
pip install -r requirements.txt
```

### External Tools Required (Kali Linux):
Most of these are pre-installed on Kali Linux. Snooger will automatically detect them.
- `sqlmap` (For automated database takeover)
- `nmap` (For service identification)
- `nuclei` (For template-based scanning)

## 🔧 Configuration

Copy the example configuration to set up your API keys and webhooks.

```bash
cp .env.example .env
```
Edit `.env` to include:
- `GROQ_API_KEY` (Get a free key from console.groq.com for high-speed cloud AI)
- `DISCORD_WEBHOOK_URL` / `TELEGRAM_BOT_TOKEN` for notifications.

## 🚀 Usage

Snooger features a beautiful, interactive CLI powered by Rich.

### Basic Scan
```bash
python snooger.py -t https://example.com
```

### Scan with Specific Profile
```bash
# Use 'stealth' profile to evade WAFs
python snooger.py -t https://example.com -p stealth

# Fast scan, skip exploitation phase
python snooger.py -t https://example.com -p quick --skip-exploit
```

### Manage Plugins & Wordlists
```bash
python snooger.py --list-plugins
python snooger.py --list-wordlists
```

## 🏗️ Architecture Phases

Snooger automates the entire pentesting lifecycle across 8 distinct phases:

1. **Reconnaissance:** DNS enum, Subdomain brute-forcing, tech detection, parameter discovery.
2. **Network/Service:** Port scanning, Nmap version detection, VHost enum.
3. **Crawling:** Spidering, JS analysis, extraction of hidden endpoints.
4. **Vulnerability Scanning:** Active payload injection using 2000+ payloads.
5. **Business Logic:** IDOR, Race Condition testing.
6. **Exploitation:** Automated exploitation of confirmed vulns (e.g., SQLmap wrapping).
7. **Post-Exploitation:** (Optional) Automated PE enum if RCE is achieved.
8. **Reporting & Notification:** HTML/JSON/PDF reports and Platform API push.

## 🤝 Contributing

We welcome contributions! Please review the `CONTRIBUTING.md` guidelines before opening PRs. 

## ⚖️ Legal Disclaimer

Snooger is created for **legal, authorized penetration testing and authorized bug bounty hunting ONLY**. The developers are not responsible for any misuse, damage, or illegal activities performed with this tool. Always obtain written permission before scanning any target.
