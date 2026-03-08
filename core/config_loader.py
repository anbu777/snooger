import os
import re
import yaml
import logging
from typing import Any

logger = logging.getLogger('snooger')

def _resolve_env_vars(value: Any) -> Any:
    """Recursively resolve ${ENV_VAR} placeholders in config values."""
    if isinstance(value, str):
        def replacer(match):
            var_name = match.group(1)
            env_val = os.environ.get(var_name, '')
            if not env_val:
                logger.debug(f"Environment variable {var_name} not set")
            return env_val
        return re.sub(r'\$\{([^}]+)\}', replacer, value)
    elif isinstance(value, dict):
        return {k: _resolve_env_vars(v) for k, v in value.items()}
    elif isinstance(value, list):
        return [_resolve_env_vars(i) for i in value]
    return value

def load_config(config_path: str = 'config.yaml') -> dict:
    """Load config.yaml and resolve environment variables."""
    # Load .env file if present
    env_file = os.path.join(os.path.dirname(config_path), '.env')
    if os.path.exists(env_file):
        try:
            from dotenv import load_dotenv
            load_dotenv(env_file)
            logger.info(f"Loaded .env from {env_file}")
        except ImportError:
            logger.warning("python-dotenv not installed. Cannot load .env file.")

    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Config file not found: {config_path}")

    with open(config_path, 'r', encoding='utf-8') as f:
        raw = yaml.safe_load(f)

    return _resolve_env_vars(raw)

def apply_profile(config: dict, profile_name: str) -> dict:
    """Merge a scan profile into the config."""
    profiles = config.get('profiles', {})
    if profile_name not in profiles:
        logger.warning(f"Profile '{profile_name}' not found. Available: {list(profiles.keys())}")
        return config
    profile = profiles[profile_name]
    config['_active_profile'] = profile_name
    config['_profile'] = profile
    logger.info(f"Applying profile: {profile_name}")
    return config
