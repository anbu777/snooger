"""
AI Engine v4.0 — Multi-provider AI with interactive selection, credit monitoring, and auto-fallback.
Providers: Ollama (free local), Groq (free cloud), DeepSeek (free cloud), OpenRouter (free tier).
"""
import json
import logging
import time
import requests
from typing import Optional, List, Any, Dict

logger = logging.getLogger('snooger')

LIGHT_TASKS = {'classify', 'short_summary', 'wordlist_suggestion', 'triage', 'priority'}

# ─── Provider Definitions ─────────────────────────────────────────────
PROVIDER_INFO = {
    'ollama': {'name': 'Ollama (Local)', 'type': 'local', 'emoji': '🖥️'},
    'groq': {'name': 'Groq Cloud', 'type': 'cloud', 'emoji': '⚡'},
    'deepseek': {'name': 'DeepSeek', 'type': 'cloud', 'emoji': '🧠'},
    'openrouter': {'name': 'OpenRouter', 'type': 'cloud', 'emoji': '🌐'},
}


class AIEngine:
    """Multi-provider AI engine with interactive selection and auto-fallback."""

    def __init__(self, config: dict, interactive: bool = False):
        self.config = config
        self.mode = config['ai']['mode']
        self.primary = config['ai'].get('primary_provider', 'ollama')
        self.fallback_chain = config['ai'].get('fallback_chain', ['groq', 'deepseek', 'openrouter'])
        self._providers = self._init_providers()
        self._exhausted: set = set()  # Providers that hit rate limit
        self._call_counts: Dict[str, int] = {p: 0 for p in self._providers}
        self._last_error: Dict[str, str] = {}

        if interactive and self._providers:
            self._interactive_select()

    # ─── Provider Initialization ──────────────────────────────────────

    def _init_providers(self) -> dict:
        """Initialize available providers."""
        providers = {}
        ai_cfg = self.config['ai']

        # Ollama (local, unlimited)
        ollama_cfg = ai_cfg.get('ollama', {})
        if ollama_cfg.get('host'):
            providers['ollama'] = {
                'host': ollama_cfg['host'],
                'model_smart': ollama_cfg.get('model_smart', 'llama3.2'),
                'model_light': ollama_cfg.get('model_light', 'tinyllama'),
                'timeout': ollama_cfg.get('timeout', 120),
            }

        # Groq
        groq_cfg = ai_cfg.get('groq', {})
        groq_key = groq_cfg.get('api_key', '')
        if groq_key and not groq_key.startswith('${'):
            providers['groq'] = {
                'api_key': groq_key,
                'model': groq_cfg.get('model', 'llama3-8b-8192'),
                'max_tokens': groq_cfg.get('max_tokens', 4096),
                'timeout': groq_cfg.get('timeout', 30),
            }

        # DeepSeek
        ds_cfg = ai_cfg.get('deepseek', {})
        ds_key = ds_cfg.get('api_key', '')
        if ds_key and not ds_key.startswith('${'):
            providers['deepseek'] = {
                'api_key': ds_key,
                'model': ds_cfg.get('model', 'deepseek-chat'),
                'max_tokens': ds_cfg.get('max_tokens', 2000),
                'timeout': ds_cfg.get('timeout', 60),
            }

        # OpenRouter (free tier)
        or_cfg = ai_cfg.get('openrouter', {})
        or_key = or_cfg.get('api_key', '')
        if or_key and not or_key.startswith('${'):
            providers['openrouter'] = {
                'api_key': or_key,
                'model': or_cfg.get('model', 'meta-llama/llama-3-8b-instruct:free'),
                'max_tokens': or_cfg.get('max_tokens', 4096),
                'timeout': or_cfg.get('timeout', 60),
            }

        return providers

    # ─── Interactive Selection & Credit Status ────────────────────────

    def _interactive_select(self) -> None:
        """Interactive AI provider selection with credit status bar."""
        try:
            from rich.console import Console
            from rich.table import Table
            from rich.prompt import IntPrompt
            from rich.panel import Panel
            console = Console()
        except ImportError:
            # Fallback to basic text selection
            self._interactive_select_basic()
            return

        # Build status table
        table = Table(
            title="🤖 AI Provider Status",
            show_header=True, header_style="bold cyan",
            border_style="dim"
        )
        table.add_column("#", style="bold white", width=3)
        table.add_column("Provider", style="white")
        table.add_column("Status", width=14)
        table.add_column("Model", style="dim")
        table.add_column("Credit", width=30)

        available = []
        for i, (key, info) in enumerate(PROVIDER_INFO.items(), 1):
            if key in self._providers:
                status = "[bold green]✅ Ready[/bold green]"
                model = self._get_model_name(key)
                credit = self._get_credit_bar(key)
                available.append(key)
            else:
                status = "[red]❌ No Key[/red]"
                model = "—"
                credit = "[dim]Not configured[/dim]"
            table.add_row(str(i), f"{info['emoji']} {info['name']}", status, model, credit)

        console.print(Panel(table, border_style="cyan"))

        if not available:
            console.print("[yellow]⚠️  No AI providers available. Running without AI.[/yellow]")
            self.mode = 'off'
            return

        # Ask user to choose
        console.print(f"\n[bold cyan]Select primary AI provider:[/bold cyan]")
        for i, key in enumerate(available, 1):
            info = PROVIDER_INFO[key]
            default_mark = " [dim](current)[/dim]" if key == self.primary else ""
            console.print(f"  [bold white][{i}][/bold white] {info['emoji']} {info['name']}{default_mark}")

        try:
            choice = IntPrompt.ask(
                f"[yellow]Choice [1-{len(available)}][/yellow]",
                default=1
            )
            idx = max(0, min(choice - 1, len(available) - 1))
            self.primary = available[idx]
            self.fallback_chain = [p for p in available if p != self.primary]
            console.print(f"\n[green]✅ Primary: {PROVIDER_INFO[self.primary]['name']}[/green]")
            if self.fallback_chain:
                names = ', '.join(PROVIDER_INFO[p]['name'] for p in self.fallback_chain)
                console.print(f"[dim]   Fallback: {names}[/dim]")
        except (KeyboardInterrupt, EOFError):
            pass

    def _interactive_select_basic(self) -> None:
        """Basic text fallback for interactive selection."""
        available = list(self._providers.keys())
        if not available:
            print("[!] No AI providers available.")
            self.mode = 'off'
            return

        print("\n=== AI Provider Selection ===")
        for i, key in enumerate(available, 1):
            print(f"  [{i}] {PROVIDER_INFO.get(key, {}).get('name', key)}")

        try:
            raw = input(f"Choice [1-{len(available)}] (default: 1): ").strip()
            idx = int(raw) - 1 if raw else 0
            idx = max(0, min(idx, len(available) - 1))
            self.primary = available[idx]
            self.fallback_chain = [p for p in available if p != self.primary]
        except (ValueError, KeyboardInterrupt, EOFError):
            pass

    def _get_model_name(self, provider: str) -> str:
        """Get model name for a provider."""
        cfg = self._providers.get(provider, {})
        if provider == 'ollama':
            return cfg.get('model_smart', 'llama3.2')
        return cfg.get('model', 'unknown')

    def _get_credit_bar(self, provider: str) -> str:
        """Generate a Rich-formatted credit usage bar."""
        if provider == 'ollama':
            return "[green]████████████████████ ∞ Local[/green]"

        # Try to check rate limit info from cached calls
        calls = self._call_counts.get(provider, 0)
        if provider in self._exhausted:
            return "[red]████████████████████ EXHAUSTED[/red]"

        # Estimated limits
        limits = {'groq': 30, 'deepseek': 50, 'openrouter': 20}
        limit = limits.get(provider, 50)
        remaining = max(0, limit - calls)
        pct = remaining / limit
        filled = int(pct * 20)
        bar = "█" * filled + "░" * (20 - filled)

        if pct > 0.5:
            color = "green"
        elif pct > 0.2:
            color = "yellow"
        else:
            color = "red"

        return f"[{color}]{bar} ~{remaining}/{limit} calls[/{color}]"

    def check_all_credits(self) -> Dict[str, dict]:
        """Check credit status for all providers. Returns dict of provider -> status."""
        status = {}
        for provider in self._providers:
            exhausted = provider in self._exhausted
            calls = self._call_counts.get(provider, 0)
            status[provider] = {
                'available': not exhausted,
                'calls_made': calls,
                'last_error': self._last_error.get(provider, ''),
            }
        return status

    # ─── Core Ask Methods ─────────────────────────────────────────────

    def ask(self, prompt: str, task_type: str = 'general',
            system: Optional[str] = None, json_mode: bool = False) -> Optional[str]:
        """Ask AI with auto-fallback. Skips exhausted providers."""
        if self.mode == 'off':
            return None

        order = [self.primary] + [p for p in self.fallback_chain if p != self.primary]

        for provider in order:
            if provider not in self._providers or provider in self._exhausted:
                continue
            try:
                result = self._ask_provider(provider, prompt, task_type, system)
                if result:
                    self._call_counts[provider] = self._call_counts.get(provider, 0) + 1
                    return result
            except Exception as e:
                error_str = str(e)
                self._last_error[provider] = error_str
                # Detect rate limit / quota exhaustion
                if '429' in error_str or 'quota' in error_str.lower() or 'rate' in error_str.lower():
                    self._exhausted.add(provider)
                    logger.warning(f"AI provider '{provider}' credit exhausted. Switching to next.")
                else:
                    logger.warning(f"AI provider '{provider}' failed: {e}")
                continue

        logger.warning("All AI providers failed or exhausted")
        return None

    def _ask_provider(self, provider: str, prompt: str,
                      task_type: str, system: Optional[str]) -> Optional[str]:
        if provider == 'ollama':
            return self._ask_ollama(prompt, task_type, system)
        elif provider == 'groq':
            return self._ask_groq(prompt, system)
        elif provider == 'deepseek':
            return self._ask_deepseek(prompt, system)
        elif provider == 'openrouter':
            return self._ask_openrouter(prompt, system)
        return None

    def _select_ollama_model(self, task_type: str) -> str:
        cfg = self._providers.get('ollama', {})
        if self.mode == 'light' or (self.mode == 'auto' and task_type in LIGHT_TASKS):
            return cfg.get('model_light', 'tinyllama')
        return cfg.get('model_smart', 'llama3.2')

    def _ask_ollama(self, prompt: str, task_type: str,
                    system: Optional[str] = None) -> Optional[str]:
        cfg = self._providers.get('ollama')
        if not cfg:
            return None
        model = self._select_ollama_model(task_type)
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.3, "num_predict": 4000}
        }
        if system:
            payload["system"] = system
        try:
            resp = requests.post(
                f"{cfg['host']}/api/generate",
                json=payload,
                timeout=cfg['timeout']
            )
            if resp.status_code == 200:
                return resp.json().get('response', '').strip()
            logger.debug(f"Ollama HTTP {resp.status_code}")
            return None
        except requests.exceptions.ConnectionError:
            logger.debug("Ollama not running")
            return None
        except Exception as e:
            logger.debug(f"Ollama error: {e}")
            return None

    def _ask_groq(self, prompt: str, system: Optional[str] = None) -> Optional[str]:
        """Groq API — free tier."""
        cfg = self._providers.get('groq')
        if not cfg or not cfg.get('api_key'):
            return None
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        try:
            resp = requests.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {cfg['api_key']}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": cfg['model'],
                    "messages": messages,
                    "temperature": 0.3,
                    "max_tokens": cfg['max_tokens'],
                    "stream": False,
                },
                timeout=cfg['timeout']
            )
            if resp.status_code == 429:
                raise Exception("429 Rate limit exceeded")
            if resp.status_code == 200:
                return resp.json()['choices'][0]['message']['content'].strip()
            logger.debug(f"Groq HTTP {resp.status_code}: {resp.text[:200]}")
            return None
        except Exception as e:
            raise  # Re-raise for fallback handling

    def _ask_deepseek(self, prompt: str, system: Optional[str] = None) -> Optional[str]:
        cfg = self._providers.get('deepseek')
        if not cfg or not cfg.get('api_key'):
            return None
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        try:
            resp = requests.post(
                "https://api.deepseek.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {cfg['api_key']}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": cfg['model'],
                    "messages": messages,
                    "temperature": 0.3,
                    "max_tokens": cfg['max_tokens'],
                    "stream": False,
                },
                timeout=cfg['timeout']
            )
            if resp.status_code == 429:
                raise Exception("429 Rate limit exceeded")
            if resp.status_code == 200:
                return resp.json()['choices'][0]['message']['content'].strip()
            logger.debug(f"DeepSeek HTTP {resp.status_code}")
            return None
        except Exception as e:
            raise

    def _ask_openrouter(self, prompt: str, system: Optional[str] = None) -> Optional[str]:
        """OpenRouter API — free tier with many models."""
        cfg = self._providers.get('openrouter')
        if not cfg or not cfg.get('api_key'):
            return None
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        try:
            resp = requests.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {cfg['api_key']}",
                    "Content-Type": "application/json",
                    "HTTP-Referer": "https://github.com/snooger",
                    "X-Title": "Snooger Pentest",
                },
                json={
                    "model": cfg['model'],
                    "messages": messages,
                    "temperature": 0.3,
                    "max_tokens": cfg['max_tokens'],
                    "stream": False,
                },
                timeout=cfg['timeout']
            )
            if resp.status_code == 429:
                raise Exception("429 Rate limit exceeded")
            if resp.status_code == 200:
                data = resp.json()
                if 'choices' in data and data['choices']:
                    return data['choices'][0]['message']['content'].strip()
            logger.debug(f"OpenRouter HTTP {resp.status_code}")
            return None
        except Exception as e:
            raise

    # ─── AI-Powered Security Functions ─────────────────────────────

    def _parse_json_response(self, text: Optional[str]) -> Optional[Any]:
        """Safely parse JSON from AI response, stripping markdown fences."""
        if not text:
            return None
        clean = str(text).strip()
        if clean.startswith('```'):
            clean = clean.split('\n', 1)[-1] if '\n' in clean else clean[3:]
            if clean.endswith('```'):
                clean = clean[:-3]
            clean = clean.strip()
        if clean.startswith('json'):
            clean = clean[4:].strip()
        try:
            return json.loads(clean)
        except json.JSONDecodeError:
            return None

    def prioritize_vulnerabilities(self, vulns: list) -> list:
        """AI-powered vulnerability prioritization for bug bounty."""
        if self.mode == 'off' or not vulns:
            return vulns
        vuln_text = json.dumps([{
            'name': v.get('info', {}).get('name', v.get('type', 'Unknown')),
            'severity': v.get('info', {}).get('severity', v.get('severity', 'unknown')),
            'url': str(v.get('matched-at', v.get('url', v.get('host', ''))))[:100],
            'tags': v.get('info', {}).get('tags', []),
        } for v in vulns[:30]], indent=2)

        prompt = f"""Analyze these vulnerability findings and return a JSON array.
Each item must have: "name", "severity", "url", "ai_priority" (1-10, 10=most critical), "ai_reasoning" (one sentence).

Findings:
{vuln_text}

Return ONLY valid JSON array."""

        result = self.ask(prompt, task_type='classify')
        parsed = self._parse_json_response(result)
        if isinstance(parsed, list):
            return sorted(parsed, key=lambda x: x.get('ai_priority', 0), reverse=True)
        return vulns

    def suggest_payloads(self, tech_stack: list, vuln_type: str,
                         waf: Optional[str] = None) -> list:
        """Generate context-aware payloads based on tech stack and WAF."""
        if self.mode == 'off':
            return []
        waf_note = f"\nTarget is behind {waf} WAF — include evasion payloads." if waf else ""
        prompt = f"""You are an expert pentester. For a web app using: {', '.join(tech_stack)}
Suggest 10 effective {vuln_type} payloads most likely to work.{waf_note}
Return ONLY a JSON array of payload strings."""

        result = self.ask(prompt, task_type='classify')
        parsed = self._parse_json_response(result)
        return parsed if isinstance(parsed, list) else []

    def triage_false_positives(self, finding: dict, response_context: str = '') -> dict:
        """AI-powered false positive triage."""
        if self.mode == 'off':
            finding['ai_confidence'] = 'unknown'
            return finding
        prompt = f"""Evaluate if this security finding is a true positive or false positive.
Finding: {json.dumps(finding, indent=2)[:1500]}
Response context: {response_context[:500]}

Respond with JSON: {{"verdict": "true_positive|false_positive|uncertain", "confidence": 0-100, "reason": "explanation"}}"""

        result = self.ask(prompt, task_type='triage')
        parsed = self._parse_json_response(result)
        if isinstance(parsed, dict):
            finding['ai_triage'] = parsed
            finding['ai_confidence'] = parsed.get('confidence', 50)
        else:
            finding['ai_confidence'] = 50
        return finding

    def analyze_vulnerability_chains(self, findings: list) -> list:
        """AI-powered exploit chain detection."""
        if self.mode == 'off' or not findings:
            return []

        vuln_text = json.dumps([{
            'type': f.get('type', 'unknown'),
            'url': str(f.get('url', ''))[:100],
            'info': str(f.get('evidence', ''))[:200]
        } for f in findings], indent=2)

        prompt = f"""You are a master red teamer. Analyze these security findings and identify potential "Exploit Chains".
A chain combines multiple low/medium findings into a high/critical impact attack (e.g., SSRF + Internal API = RCE).

Findings:
{vuln_text}

Return a JSON array of potential chains. Each chain must have:
"chain_name", "description", "impact" (high/critical), "steps" (list of findings used), "exploit_path" (short explanation).

Return ONLY valid JSON array."""

        result = self.ask(prompt, task_type='summary')
        parsed = self._parse_json_response(result)
        return parsed if isinstance(parsed, list) else []

    def generate_poc_writeup(self, finding: dict) -> str:
        """Generate a professional PoC writeup for bug bounty submission."""
        if self.mode == 'off':
            return ""
        prompt = f"""Write a professional bug bounty PoC report for this finding.
Finding: {json.dumps(finding, indent=2)[:2000]}

Structure:
1. Title
2. Severity (CVSS justification)
3. Description
4. Steps to Reproduce (numbered, specific)
5. Impact (business impact)
6. Remediation
7. References

Professional tone, ready for HackerOne/Bugcrowd submission."""

        return self.ask(prompt, task_type='summary') or ""

    def analyze_attack_surface(self, recon_data: dict) -> dict:
        """AI-powered attack surface analysis from recon data."""
        if self.mode == 'off':
            return {}
        summary = {
            'subdomains': len(recon_data.get('subdomains', [])),
            'technologies': recon_data.get('all_technologies', [])[:20],
            'interesting_params': recon_data.get('interesting_params', [])[:20],
            'js_secrets': len(recon_data.get('secrets', [])),
        }
        prompt = f"""As a senior pentester, analyze this attack surface and recommend high-value testing targets:
{json.dumps(summary, indent=2)}

Return JSON with:
- "priority_targets": top 5 URLs/endpoints to test first
- "recommended_tests": list of test types most likely to yield results
- "technology_risks": known vulnerabilities for detected tech stack
- "overall_risk": "low|medium|high|critical" """

        result = self.ask(prompt, task_type='summary')
        parsed = self._parse_json_response(result)
        return parsed if isinstance(parsed, dict) else {}

    def get_available_providers(self) -> list:
        """Return list of configured and available AI providers."""
        return list(self._providers.keys())
