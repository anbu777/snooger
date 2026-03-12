"""
AI Engine v3.0 — Multi-provider AI with auto-fallback.
Providers: Ollama (free local), Groq (free cloud), DeepSeek (free tier).
"""
import json
import logging
import requests
from typing import Optional, List, Any

logger = logging.getLogger('snooger')

LIGHT_TASKS = {'classify', 'short_summary', 'wordlist_suggestion', 'triage', 'priority'}


class AIEngine:
    """Multi-provider AI engine with auto-fallback chain."""

    def __init__(self, config: dict):
        self.config = config
        self.mode = config['ai']['mode']
        self.primary = config['ai'].get('primary_provider', 'ollama')
        self.fallback_chain = config['ai'].get('fallback_chain', ['groq', 'deepseek'])
        self._providers = self._init_providers()

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

        # Groq (free tier: 14,400 tokens/min on llama3-8b-8192)
        groq_cfg = ai_cfg.get('groq', {})
        if groq_cfg.get('api_key'):
            providers['groq'] = {
                'api_key': groq_cfg['api_key'],
                'model': groq_cfg.get('model', 'llama3-8b-8192'),
                'max_tokens': groq_cfg.get('max_tokens', 4096),
                'timeout': groq_cfg.get('timeout', 30),
            }

        # DeepSeek (free tier available)
        ds_cfg = ai_cfg.get('deepseek', {})
        if ds_cfg.get('api_key'):
            providers['deepseek'] = {
                'api_key': ds_cfg['api_key'],
                'model': ds_cfg.get('model', 'deepseek-chat'),
                'max_tokens': ds_cfg.get('max_tokens', 2000),
                'timeout': ds_cfg.get('timeout', 60),
            }

        return providers

    def ask(self, prompt: str, task_type: str = 'general',
            system: Optional[str] = None, json_mode: bool = False) -> Optional[str]:
        """
        Ask AI with auto-fallback across providers.
        Tries primary → fallback chain until one succeeds.
        """
        if self.mode == 'off':
            return None

        # Build provider order: primary first, then fallback chain
        order = [self.primary] + [p for p in self.fallback_chain if p != self.primary]

        for provider in order:
            if provider not in self._providers:
                continue
            try:
                result = self._ask_provider(provider, prompt, task_type, system)
                if result:
                    return result
            except Exception as e:
                logger.debug(f"AI provider '{provider}' failed: {e}")
                continue

        logger.warning("All AI providers failed")
        return None

    def _ask_provider(self, provider: str, prompt: str,
                      task_type: str, system: Optional[str]) -> Optional[str]:
        if provider == 'ollama':
            return self._ask_ollama(prompt, task_type, system)
        elif provider == 'groq':
            return self._ask_groq(prompt, system)
        elif provider == 'deepseek':
            return self._ask_deepseek(prompt, system)
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
        """Groq API — free tier with generous limits."""
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
            if resp.status_code == 200:
                return resp.json()['choices'][0]['message']['content'].strip()
            logger.debug(f"Groq HTTP {resp.status_code}: {resp.text[:200]}")
            return None
        except Exception as e:
            logger.debug(f"Groq error: {e}")
            return None

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
            if resp.status_code == 200:
                return resp.json()['choices'][0]['message']['content'].strip()
            logger.debug(f"DeepSeek HTTP {resp.status_code}")
            return None
        except Exception as e:
            logger.debug(f"DeepSeek error: {e}")
            return None

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
            'url': v.get('matched-at', v.get('url', v.get('host', '')))[:100],
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
