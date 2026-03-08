"""
Technology detection with context-aware intelligence.
Returns tech stack and triggers appropriate modules.
"""
import os
import json
import logging
from typing import List, Dict
from core.utils import run_command, save_raw_output, safe_remove, load_jsonl_file

logger = logging.getLogger('snooger')

# Map tech to recommended additional scans
TECH_SCAN_MAP = {
    'wordpress': ['wpscan', 'xmlrpc_check', 'wp_user_enum'],
    'drupal': ['drupal_cve_check', 'drupalgeddon'],
    'joomla': ['joomscan'],
    'laravel': ['laravel_debug_check', 'env_exposure', 'mass_assignment'],
    'spring': ['spring_actuator', 'spel_injection', 'spring_cloud_rce'],
    'django': ['django_debug_check', 'django_admin_check'],
    'php': ['phpinfo_check', 'php_misconfig'],
    'tomcat': ['tomcat_manager_check', 'tomcat_cve'],
    'iis': ['iis_misconfig', 'webdav_check'],
    'nginx': ['nginx_misconfig'],
    'apache': ['apache_misconfig', 'apache_struts'],
    'node.js': ['nodejs_express_check'],
    'graphql': ['graphql_introspection', 'graphql_batch_attack'],
    'jenkins': ['jenkins_rce_check'],
    'elasticsearch': ['elasticsearch_unauth_check'],
    'redis': ['redis_unauth_check'],
    'mongodb': ['mongodb_unauth_check'],
    'kubernetes': ['k8s_api_exposure'],
    'swagger': ['swagger_endpoint_extraction'],
    'react': ['react_debug_check', 'source_map_check'],
    'angular': ['angular_debug_check'],
    'vue': ['vue_debug_check'],
    'aws': ['s3_bucket_check', 'aws_metadata_ssrf'],
    'cloudfront': ['cloudfront_origin_check'],
}

def detect_technologies(targets: List[str], workspace_dir: str) -> Dict[str, dict]:
    """Detect technologies and return structured results with recommendations."""
    if not targets:
        return {}

    logger.info(f"Detecting technologies for {len(targets)} targets...")
    input_file = os.path.join(workspace_dir, 'temp_tech_targets.txt')
    output_file = os.path.join(workspace_dir, 'raw_logs', 'recon', 'httpx_tech.json')
    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    try:
        with open(input_file, 'w') as f:
            for t in targets:
                if not t.startswith('http'):
                    f.write(f"https://{t}\n")
                else:
                    f.write(f"{t}\n")

        cmd = (f"httpx -l {input_file} -tech-detect -json -silent -o {output_file} "
               f"-timeout 10 -follow-redirects -title -web-server "
               f"-status-code -content-length -favicon")
        stdout, stderr, rc = run_command(cmd, timeout=600)
        save_raw_output(workspace_dir, 'recon', 'httpx_tech_stdout', stdout, 'txt')
    finally:
        safe_remove(input_file)

    results = {}
    if os.path.exists(output_file):
        entries = load_jsonl_file(output_file)
        for entry in entries:
            url = entry.get('url', '')
            if not url:
                continue
            techs = entry.get('technologies', entry.get('tech', []))
            tech_names = []
            if isinstance(techs, list):
                for t in techs:
                    if isinstance(t, dict):
                        tech_names.append(t.get('name', ''))
                    elif isinstance(t, str):
                        tech_names.append(t)
            elif isinstance(techs, dict):
                tech_names = list(techs.keys())

            tech_names = [t.lower() for t in tech_names if t]

            # Determine recommended modules
            recommended_modules = set()
            for tech in tech_names:
                for key, modules in TECH_SCAN_MAP.items():
                    if key in tech:
                        recommended_modules.update(modules)

            results[url] = {
                'technologies': tech_names,
                'status_code': entry.get('status_code'),
                'title': entry.get('title', ''),
                'webserver': entry.get('webserver', ''),
                'content_length': entry.get('content_length'),
                'favicon_hash': entry.get('favicon', ''),
                'recommended_modules': list(recommended_modules),
                'raw': entry
            }

    logger.info(f"Technology detection complete for {len(results)} URLs")
    # Log notable findings
    for url, data in results.items():
        if data.get('recommended_modules'):
            logger.info(f"  {url}: {', '.join(data['technologies'][:3])} → modules: {', '.join(data['recommended_modules'][:3])}")

    return results

def get_all_technologies(tech_results: dict) -> List[str]:
    """Get flattened list of all unique technologies detected."""
    all_techs = set()
    for url_data in tech_results.values():
        all_techs.update(url_data.get('technologies', []))
    return list(all_techs)

def get_recommended_modules(tech_results: dict) -> List[str]:
    """Get all recommended modules based on detected technologies."""
    all_modules = set()
    for url_data in tech_results.values():
        all_modules.update(url_data.get('recommended_modules', []))
    return list(all_modules)
