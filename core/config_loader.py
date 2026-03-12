"""
Config Loader — reads config.yaml, expands environment variables,
validates schema, and applies scan profiles.
"""
import os
import re
import copy
import logging
import yaml
from typing import Any, Optional
from dotenv import load_dotenv

logger = logging.getLogger('snooger')

# Load .env file from project root
_project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(_project_root, '.env'))


def _expand_env_vars(value: Any) -> Any:
    """Recursively expand ${VAR} and $VAR patterns in config values."""
    if isinstance(value, str):
        def _replace(match):
            var_name = match.group(1) or match.group(2)
            return os.environ.get(var_name, '')
        return re.sub(r'\$\{([^}]+)\}|\$([A-Z_][A-Z0-9_]*)', _replace, value)
    elif isinstance(value, dict):
        return {k: _expand_env_vars(v) for k, v in value.items()}
    elif isinstance(value, list):
        return [_expand_env_vars(item) for item in value]
    return value


def load_config(config_path: str) -> dict:
    """Load and validate config from YAML file with env var expansion."""
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Config file not found: {config_path}")

    with open(config_path, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f)

    if not isinstance(config, dict):
        raise ValueError(f"Invalid config format in {config_path}")

    # Expand environment variables
    config = _expand_env_vars(config)

    # Apply defaults for missing sections
    config = _apply_defaults(config)

    logger.debug(f"Config loaded from {config_path}")
    return config


def _apply_defaults(config: dict) -> dict:
    """Ensure all required config sections exist with sane defaults."""
    defaults = {
        'tools': {},
        'ai': {
            'mode': 'auto',
            'primary_provider': 'ollama',
            'fallback_chain': ['groq', 'deepseek'],
            'ollama': {
                'model_smart': 'llama3.2',
                'model_light': 'tinyllama',
                'host': 'http://localhost:11434',
                'timeout': 120,
            },
            'groq': {
                'api_key': '',
                'model': 'llama3-8b-8192',
                'max_tokens': 4096,
                'timeout': 30,
            },
            'deepseek': {
                'api_key': '',
                'model': 'deepseek-chat',
                'max_tokens': 2000,
                'timeout': 60,
            },
        },
        'rate_limit': {
            'requests_per_second': 10,
            'delay_between_phases': 2,
            'adaptive_delay': True,
            'max_retries': 3,
            'backoff_factor': 2.0,
        },
        'stealth': {
            'use_fake_useragent': True,
            'rotate_useragent': True,
            'random_delay_min': 0.3,
            'random_delay_max': 1.5,
            'jitter': True,
        },
        'proxy': {
            'enabled': False,
            'http': '',
            'https': '',
            'socks5': '',
            'rotate': False,
            'proxy_list': '',
        },
        'notifications': {
            'telegram': {'enabled': False},
            'discord': {'enabled': False},
            'webhook': {'enabled': False},
        },
        'platform': {
            'hackerone': {'auto_submit': False, 'draft_mode': True},
            'bugcrowd': {'auto_submit': False, 'draft_mode': True},
        },
        'async': {
            'max_concurrent_scans': 20,
            'max_concurrent_requests': 50,
            'thread_pool_size': 10,
        },
        'plugins': {
            'enabled': True,
            'directory': 'plugins',
            'autoload': True,
        },
        'seclists': {
            'auto_download': True,
            'path': '/usr/share/seclists',
            'fallback_path': '/opt/seclists',
        },
        'workspace': 'workspace',
        'profiles': {},
    }

    def _deep_merge(base: dict, override: dict) -> dict:
        result = copy.deepcopy(base)
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = _deep_merge(result[key], value)
            else:
                result[key] = value
        return result

    return _deep_merge(defaults, config)


def apply_profile(config: dict, profile_name: str) -> dict:
    """Apply a named profile's settings onto config."""
    profiles = config.get('profiles', {})
    profile = profiles.get(profile_name)
    if not profile:
        logger.warning(f"Profile '{profile_name}' not found in config")
        return config

    config = copy.deepcopy(config)

    # Map profile keys to config paths
    profile_mapping = {
        'nuclei_severity': None,  # stored as _profile
        'ffuf_threads': None,
        'ffuf_delay': None,
        'max_subdomains': None,
        'max_crawl_pages': None,
        'skip_post': None,
        'requests_per_second': ('rate_limit', 'requests_per_second'),
        'async_concurrent': ('async', 'max_concurrent_scans'),
    }

    for key, path in profile_mapping.items():
        if key in profile and path:
            section, param = path
            config.setdefault(section, {})[param] = profile[key]

    # Store profile settings for direct access
    config['_profile'] = profile
    config['_profile_name'] = profile_name
    logger.info(f"Applied profile: {profile_name}")
    return config


def get_tool_path(config: dict, tool_name: str) -> str:
    """Get the configured path for an external tool."""
    return config.get('tools', {}).get(tool_name, tool_name)
