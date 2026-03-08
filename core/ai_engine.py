import requests
import logging
import json
from typing import Optional

logger = logging.getLogger('snooger')

LIGHT_TASKS = {'classify', 'short_summary', 'wordlist_suggestion', 'triage'}

class AIEngine:
    def __init__(self, config: dict):
        self.config = config
        self.mode = config['ai']['mode']
        self.provider = config['ai'].get('provider', 'ollama')
        self.host = config['ai']['ollama']['host']
        self.smart_model = config['ai']['ollama']['model_smart']
        self.light_model = config['ai']['ollama']['model_light']

    def ask(self, prompt: str, task_type: str = 'general',
            system: Optional[str] = None, structured: bool = False) -> Optional[str]:
        if self.mode == 'off':
            return None
        if self.provider == 'deepseek':
            return self._ask_deepseek(prompt, system)
        elif self.provider == 'huggingface':
            return self._ask_huggingface(prompt)
        else:
            return self._ask_ollama(prompt, task_type, system)

    def _select_model(self, task_type: str) -> str:
        if self.mode == 'light' or (self.mode == 'auto' and task_type in LIGHT_TASKS):
            return self.light_model
        return self.smart_model

    def _ask_ollama(self, prompt: str, task_type: str,
                    system: Optional[str] = None) -> Optional[str]:
        model = self._select_model(task_type)
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.3, "num_predict": 2000}
        }
        if system:
            payload["system"] = system
        try:
            resp = requests.post(
                f"{self.host}/api/generate",
                json=payload,
                timeout=120
            )
            if resp.status_code == 200:
                return resp.json().get('response', '').strip()
            else:
                logger.error(f"Ollama HTTP {resp.status_code}: {resp.text[:200]}")
                return None
        except requests.exceptions.ConnectionError:
            logger.error("Ollama not running. Start with: systemctl start ollama")
            return None
        except Exception as e:
            logger.error(f"Ollama request failed: {e}")
            return None

    def _ask_deepseek(self, prompt: str, system: Optional[str] = None) -> Optional[str]:
        api_key = self.config['ai']['deepseek'].get('api_key', '')
        if not api_key:
            logger.error("DeepSeek API key not set. Set DEEPSEEK_API_KEY env var.")
            return None
        model = self.config['ai']['deepseek']['model']
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        try:
            resp = requests.post(
                "https://api.deepseek.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json={"model": model, "messages": messages, "stream": False,
                      "temperature": 0.3, "max_tokens": 2000},
                timeout=60
            )
            if resp.status_code == 200:
                return resp.json()['choices'][0]['message']['content'].strip()
            else:
                logger.error(f"DeepSeek HTTP {resp.status_code}: {resp.text[:200]}")
                return None
        except Exception as e:
            logger.error(f"DeepSeek request failed: {e}")
            return None

    def _ask_huggingface(self, prompt: str) -> Optional[str]:
        token = self.config['ai']['huggingface'].get('api_token', '')
        if not token:
            logger.error("HuggingFace token not set. Set HUGGINGFACE_API_TOKEN env var.")
            return None
        model = self.config['ai']['huggingface']['model']
        try:
            resp = requests.post(
                f"https://api-inference.huggingface.co/models/{model}",
                headers={"Authorization": f"Bearer {token}"},
                json={"inputs": prompt, "parameters": {"max_new_tokens": 500}},
                timeout=90
            )
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list) and data:
                    return data[0].get('generated_text', '').strip()
                return str(data)
            else:
                logger.error(f"HuggingFace HTTP {resp.status_code}: {resp.text[:200]}")
                return None
        except Exception as e:
            logger.error(f"HuggingFace request failed: {e}")
            return None

    def prioritize_vulnerabilities(self, vulns: list) -> list:
        """Use AI to score and prioritize vulnerability findings."""
        if self.mode == 'off' or not vulns:
            return vulns
        vuln_text = json.dumps([
            {
                'name': v.get('info', {}).get('name', 'Unknown'),
                'severity': v.get('info', {}).get('severity', 'unknown'),
                'url': v.get('matched-at', v.get('host', '')),
                'tags': v.get('info', {}).get('tags', [])
            }
            for v in vulns[:20]
        ], indent=2)
        prompt = f"""You are a senior penetration tester. Analyze these vulnerability findings and return a JSON array with the same items but each augmented with:
- "ai_priority": integer 1-10 (10=most critical for bug bounty)
- "ai_reasoning": one sentence why

Findings:
{vuln_text}

Return ONLY valid JSON array, no explanation."""
        result = self.ask(prompt, task_type='classify')
        if not result:
            return vulns
        try:
            clean = result.strip().lstrip('```json').rstrip('```').strip()
            prioritized = json.loads(clean)
            if isinstance(prioritized, list):
                return sorted(prioritized, key=lambda x: x.get('ai_priority', 0), reverse=True)
        except Exception as e:
            logger.debug(f"AI prioritization parse error: {e}")
        return vulns

    def suggest_payloads(self, tech_stack: list, vuln_type: str) -> list:
        """Get AI-suggested payloads based on detected tech stack."""
        if self.mode == 'off':
            return []
        prompt = f"""You are an expert pentester. For a web application using: {', '.join(tech_stack)}
Suggest 5 effective {vuln_type} payloads most likely to work given this stack.
Return ONLY a JSON array of payload strings."""
        result = self.ask(prompt, task_type='classify')
        if not result:
            return []
        try:
            clean = result.strip().lstrip('```json').rstrip('```').strip()
            return json.loads(clean)
        except Exception:
            return []

    def triage_false_positives(self, finding: dict, context: str) -> dict:
        """AI-assisted false positive triage."""
        if self.mode == 'off':
            finding['ai_confidence'] = 'unknown'
            return finding
        prompt = f"""You are a security analyst. Evaluate if this finding is a true positive or false positive.
Finding: {json.dumps(finding, indent=2)}
Context: {context}

Respond with JSON: {{"verdict": "true_positive|false_positive|uncertain", "confidence": 0-100, "reason": "explanation"}}"""
        result = self.ask(prompt, task_type='triage')
        if result:
            try:
                clean = result.strip().lstrip('```json').rstrip('```').strip()
                triage = json.loads(clean)
                finding['ai_triage'] = triage
                finding['ai_confidence'] = triage.get('confidence', 50)
            except Exception:
                finding['ai_confidence'] = 50
        return finding

    def generate_poc_writeup(self, finding: dict) -> str:
        """Generate a structured PoC writeup for bug bounty submission."""
        if self.mode == 'off':
            return ""
        prompt = f"""Write a professional bug bounty PoC report for this finding.
Finding: {json.dumps(finding, indent=2)}

Structure the report with:
1. Title
2. Severity (with CVSS justification)
3. Description
4. Steps to Reproduce
5. Impact
6. Remediation
7. References

Write in English, professional tone, ready for HackerOne/Bugcrowd submission."""
        return self.ask(prompt, task_type='summary') or ""
