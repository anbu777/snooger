import os
import sys
import subprocess
import shutil
import logging
import yaml
from pathlib import Path

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger('health-check')

def check_python_dependencies():
    logger.info("\n[1] Checking Python Dependencies...")
    try:
        import requests
        import aiohttp
        import aiosqlite
        import yaml
        import rich
        import groq
        import ollama
        logger.info("  [✓] All core python libraries found.")
    except ImportError as e:
        logger.error(f"  [✗] Missing python library: {e}")

def check_external_tools():
    logger.info("\n[2] Checking External Binaries (config.yaml)...")
    config_path = Path("config.yaml")
    if not config_path.exists():
        logger.error("  [✗] config.yaml not found!")
        return

    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)

    tools = config.get('tools', {})
    for name, path in tools.items():
        if shutil.which(path):
            logger.info(f"  [✓] {name:15} : Found at {shutil.which(path)}")
        else:
            logger.warning(f"  [!] {name:15} : NOT FOUND (path: {path})")

def check_directories():
    logger.info("\n[3] Checking Essential Directories...")
    dirs = ['core', 'modules', 'data', 'plugins', 'workspace']
    for d in dirs:
        if os.path.isdir(d):
            logger.info(f"  [✓] {d:15} : OK")
        else:
            logger.error(f"  [✗] {d:15} : MISSING")

def check_ai_config():
    logger.info("\n[4] Checking AI Environment...")
    from dotenv import load_dotenv
    load_dotenv()
    
    groq_key = os.getenv("GROQ_API_KEY")
    if groq_key:
        logger.info("  [✓] GROQ_API_KEY : Configured")
    else:
        logger.warning("  [!] GROQ_API_KEY : NOT SET in .env")

    # Check ollama connection
    try:
        import requests
        resp = requests.get("http://localhost:11434/api/tags", timeout=2)
        if resp.status_code == 200:
            logger.info("  [✓] Ollama Service : Running (Local)")
    except:
        logger.warning("  [!] Ollama Service : Not Responding (is it started?)")

def main():
    print("====================================================")
    print("      SNOOGER FRAMEWORK HEALTH CHECK (KALI)         ")
    print("====================================================")
    
    check_python_dependencies()
    check_external_tools()
    check_directories()
    check_ai_config()
    
    print("\n====================================================")
    print("Health Check Complete.")
    print("Note: Some external tools might be in ~/go/bin. ")
    print("Ensure ~/go/bin is in your PATH.")
    print("====================================================")

if __name__ == "__main__":
    main()
