import os
import json
import logging
from typing import List
from core.utils import run_command, save_raw_output, safe_remove, load_jsonl_file
from modules.scope.scope_manager import ScopeManager

logger = logging.getLogger('snooger')

def filter_alive(subdomains: List[str], workspace_dir: str,
                 scope = None) -> List[str]:
    """Filter alive hosts using httpx. Applies scope filtering."""
    if not subdomains:
        return []

    # Apply scope filter first
    if scope and not scope.is_empty():
        subdomains = scope.filter_targets(subdomains)
        if not subdomains:
            logger.warning("All subdomains filtered out by scope rules")
            return []

    logger.info(f"Filtering {len(subdomains)} subdomains with httpx...")
    input_file = os.path.join(workspace_dir, 'temp_subdomains.txt')
    output_file = os.path.join(workspace_dir, 'alive_subdomains.json')

    try:
        with open(input_file, 'w') as f:
            f.write('\n'.join(subdomains))

        cmd = (f"httpx -l {input_file} -json -silent -o {output_file} "
               f"-timeout 10 -retries 2 -follow-redirects -status-code "
               f"-title -web-server -tech-detect")
        stdout, stderr, rc = run_command(cmd, timeout=600)
        save_raw_output(workspace_dir, 'recon', 'httpx_alive', stdout, 'json')

        alive = []
        if os.path.exists(output_file):
            entries = load_jsonl_file(output_file)
            for entry in entries:
                url = entry.get('url', '')
                if url:
                    alive.append(url)

        logger.info(f"Found {len(alive)} alive hosts")
        return alive
    finally:
        safe_remove(input_file)
