import requests
import json
import logging

logger = logging.getLogger('snooger')

class AIEngine:
    def __init__(self, config):
        self.config = config
        self.mode = config['ai']['mode']
        self.host = config['ai']['ollama_host']
        self.smart_model = config['ai']['model_smart']
        self.light_model = config['ai']['model_light']
        self.current_model = self.smart_model  # default

    def ask(self, prompt, task_type='general'):
        """Kirim prompt ke Ollama, kembalikan respons."""
        if self.mode == 'off':
            return None
        # Pilih model berdasarkan mode dan task_type
        if self.mode == 'light' or (self.mode == 'auto' and self._is_light_task(task_type)):
            model = self.light_model
        else:
            model = self.smart_model
        self.current_model = model
        try:
            response = requests.post(
                f"{self.host}/api/generate",
                json={"model": model, "prompt": prompt, "stream": False},
                timeout=60
            )
            if response.status_code == 200:
                return response.json().get('response', '')
            else:
                logger.error(f"Ollama error: {response.status_code}")
                return None
        except Exception as e:
            logger.error(f"Ollama request failed: {e}")
            return None

    def _is_light_task(self, task_type):
        """Tentukan apakah task ringan bisa pakai model kecil."""
        light_tasks = ['classify', 'short_summary', 'wordlist_suggestion']
        return task_type in light_tasks
    