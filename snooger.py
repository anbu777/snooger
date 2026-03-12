"""
Snooger v3.0 — Professional Penetration Testing Framework
Main orchestrator with async execution, plugin system, and event bus.
Target: Kali Linux
"""
import os
import sys
import time
import json
import signal
import asyncio
import logging
import argparse
from datetime import datetime
from typing import Optional

# ─── Project Path Setup ──────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from core.config_loader import load_config, apply_profile, get_tool_path
from core.ai_engine import AIEngine
from core.state_manager import StateManager
from core.scope_manager import ScopeManager
from core.rate_limiter import init_rate_limiter
from core.event_bus import get_event_bus, emit
from core.plugin_loader import init_plugins, ScanContext
from core.async_executor import AsyncExecutor, run_async
from core.http_client import AsyncHTTPClient, SyncHTTPClient
from core.notifications import init_notifications
from core.interactive import (
    print_banner, print_phase_header, print_finding,
    print_summary_table, confirm_action, get_user_input,
    get_user_choice, create_progress, console, HAS_RICH
)
from core.utils import (
    run_command, save_raw_output, write_json, load_json_file,
    random_user_agent, check_tool, sanitize_domain, sanitize_url
)

VERSION = "3.0.0"

# ─── Logging ──────────────────────────────────────────────────────────
def setup_logging(workspace_dir: str, verbose: bool = False) -> logging.Logger:
    logger = logging.getLogger('snooger')
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    # Console handler
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG if verbose else logging.INFO)
    fmt = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s', '%H:%M:%S')
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    # File handler
    os.makedirs(workspace_dir, exist_ok=True)
    fh = logging.FileHandler(os.path.join(workspace_dir, 'snooger.log'), encoding='utf-8')
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
    logger.addHandler(fh)

    return logger


# ─── Phase Execution Functions ────────────────────────────────────────

async def phase_recon(target: str, workspace: str, config: dict,
                      scope, state, ai, executor, context) -> dict:
    """Phase 1: Reconnaissance — subdomain enumeration, alive check, tech detection."""
    from modules.reconnaissance.subdomain import run_full_subdomain_enum
    from modules.reconnaissance.content_discovery import discover_content

    logger = logging.getLogger('snooger')
    results = {}

    # Subdomain enumeration
    logger.info("Starting subdomain enumeration...")
    subdomains = run_full_subdomain_enum(target, workspace)
    results['subdomains'] = subdomains
    state.save_phase_data('recon_subdomains', subdomains)

    # Content discovery on main target
    logger.info("Starting content discovery...")
    try:
        content = discover_content(
            f"https://{target}" if not target.startswith('http') else target,
            workspace,
        )
        results['content'] = content
        state.save_phase_data('recon_content', content)
    except Exception as e:
        logger.warning(f"Content discovery error: {e}")
        results['content'] = {}

    emit('phase_completed', {'phase': 'recon', 'results_summary': {
        'subdomains_found': len(subdomains),
    }}, source='recon')

    return results


async def phase_scanning(target: str, workspace: str, config: dict,
                         scope, state, ai, executor, recon_data: dict) -> dict:
    """Phase 2: Port Scanning & Technology Detection."""
    from modules.scanning.port_scan import scan_ports
    from modules.scanning.tech_detect import run_tech_detection

    logger = logging.getLogger('snooger')
    results = {}

    alive_subs = recon_data.get('subdomains', {}).get('alive_subdomains', [target])

    # Port scanning
    logger.info(f"Port scanning {len(alive_subs)} targets...")
    scan_results = scan_ports(alive_subs[:50], workspace)
    results['port_scan'] = scan_results
    state.save_phase_data('port_scan', scan_results)

    # Tech detection
    logger.info("Running technology detection...")
    tech_results = run_tech_detection(alive_subs[:50], workspace, config)
    results['tech_detect'] = tech_results
    state.save_phase_data('tech_detect', tech_results)

    emit('phase_completed', {'phase': 'scanning'}, source='scanning')
    return results


async def phase_crawl(target: str, workspace: str, config: dict,
                      scope, state, ai, executor, recon_data: dict) -> dict:
    """Phase 3: Web Crawling & JavaScript Analysis."""
    from modules.crawler.web_crawler import crawl_target
    from modules.javascript.js_analyzer import analyze_js_files

    logger = logging.getLogger('snooger')
    results = {}

    target_url = f"https://{target}" if not target.startswith('http') else target

    # Crawl the target
    logger.info("Starting web crawler...")
    crawl = crawl_target(target_url, workspace)
    results['crawler'] = crawl
    state.save_phase_data('crawler', crawl)

    # JS analysis
    js_files = crawl.get('js_files', [])
    if js_files:
        logger.info(f"Analyzing {len(js_files)} JavaScript files...")
        js_results = analyze_js_files(js_files, target_url, workspace)
        results['js_analysis'] = js_results
        state.save_phase_data('js_analysis', js_results)

        secrets = js_results.get('secrets', [])
        if secrets:
            logger.warning(f"Found {len(secrets)} secrets in JavaScript files!")
            for s in secrets[:5]:
                emit('secret_found', s, source='js_analyzer')

    emit('phase_completed', {'phase': 'crawl'}, source='crawl')
    return results


async def phase_vuln_analysis(target: str, workspace: str, config: dict,
                              scope, state, ai, executor,
                              recon_data: dict, crawl_data: dict,
                              scan_data: dict) -> dict:
    """Phase 4: Vulnerability Analysis — Nuclei + Active Testing."""
    from modules.vulnerability.nuclei_runner import run_nuclei
    from modules.vulnerability.active_vulns import run_active_vulnerability_tests

    logger = logging.getLogger('snooger')
    results = {}

    alive_subs = recon_data.get('subdomains', {}).get('alive_subdomains', [target])
    urls_with_params = crawl_data.get('crawler', {}).get('urls_with_params', [])
    forms = crawl_data.get('crawler', {}).get('forms', [])
    tech_stack = scan_data.get('tech_detect', {}).get('all_technologies', [])

    # Nuclei scan
    logger.info("Running Nuclei vulnerability scanner...")
    nuclei_results = run_nuclei(alive_subs[:30], workspace)
    results['nuclei'] = nuclei_results
    state.save_phase_data('nuclei', nuclei_results)

    # Active vulnerability tests
    if urls_with_params:
        logger.info(f"Running active vulnerability tests on {len(urls_with_params)} URLs...")
        active_results = run_active_vulnerability_tests(
            urls_with_params, workspace, auth=None,
            interactsh_url=config.get('interactsh', {}).get('server'),
            forms=forms
        )
        results['active_vulns'] = active_results
        state.save_phase_data('active_vulns', active_results)

        # Emit findings
        for vuln_type, findings in active_results.items():
            for finding in findings:
                severity = finding.get('severity', 'info')
                event_name = 'critical_alert' if severity == 'critical' else 'finding_discovered'
                emit(event_name, finding, source=vuln_type)

    # AI prioritization
    if ai and isinstance(nuclei_results, list) and nuclei_results:
        logger.info("AI prioritizing vulnerability findings...")
        prioritized = ai.prioritize_vulnerabilities(nuclei_results)
        results['ai_prioritized'] = prioritized

    emit('phase_completed', {'phase': 'vuln_analysis'}, source='vuln_analysis')
    return results


async def phase_auth_testing(target: str, workspace: str, config: dict,
                             state, ai, crawl_data: dict) -> dict:
    """Phase 5: Authentication & Authorization Testing."""
    from modules.auth.auth_testing import run_auth_tests

    logger = logging.getLogger('snooger')

    target_url = f"https://{target}" if not target.startswith('http') else target

    logger.info("Running authentication tests...")
    auth_results = run_auth_tests(
        target_url, workspace,
        crawler_results=crawl_data.get('crawler', {})
    )
    state.save_phase_data('auth_testing', auth_results)

    emit('phase_completed', {'phase': 'auth_testing'}, source='auth')
    return auth_results


async def phase_business_logic(target: str, workspace: str, config: dict,
                               state, crawl_data: dict) -> dict:
    """Phase 6: Business Logic Testing — IDOR, Race Conditions."""
    from modules.business_logic.idor import scan_idor

    logger = logging.getLogger('snooger')
    results = {}

    urls = crawl_data.get('crawler', {}).get('urls_with_params', [])
    if urls:
        logger.info("Running IDOR tests...")
        idor_results = scan_idor(None, urls[:20], workspace)
        results['idor'] = idor_results
        state.save_phase_data('idor', idor_results)

    emit('phase_completed', {'phase': 'business_logic'}, source='business_logic')
    return results


async def phase_exploitation(target: str, workspace: str, config: dict,
                             state, ai, vuln_data: dict) -> dict:
    """Phase 7: Exploitation — Chain Detection & PoC Generation."""
    from modules.exploitation.chain_engine import detect_chains

    logger = logging.getLogger('snooger')

    all_findings = []
    for phase_name in ['nuclei', 'active_vulns', 'idor', 'auth_testing']:
        phase_data = state.get_phase_data(phase_name) or {}
        if isinstance(phase_data, dict):
            for key, val in phase_data.items():
                if isinstance(val, list):
                    all_findings.extend(val)

    if not all_findings:
        logger.info("No findings for exploitation phase")
        return {}

    logger.info(f"Analyzing {len(all_findings)} findings for exploit chains...")
    chains = detect_chains(all_findings)

    if chains:
        logger.warning(f"Found {len(chains)} potential exploit chains!")
        for chain in chains:
            emit('chain_detected', chain, source='chain_engine')

    # AI PoC generation for critical findings
    critical: list[dict] = [f for f in all_findings if f.get('severity') == 'critical']
    pocs = []
    if ai and critical:
        logger.info(f"Generating AI PoC writeups for {len(list(critical)[:5])} critical findings...")  # type: ignore
        for finding in list(critical)[:5]:  # type: ignore
            poc = ai.generate_poc_writeup(finding)
            if poc:
                pocs.append({'finding': finding, 'poc': poc})

    results = {'chains': chains, 'pocs': pocs}
    state.save_phase_data('exploitation', results)

    emit('phase_completed', {'phase': 'exploitation'}, source='exploitation')
    return results


async def phase_reporting(target: str, workspace: str, config: dict,
                          state, ai) -> dict:
    """Phase 8: Report Generation."""
    from modules.reporting.json_builder import build_final_report
    from modules.reporting.ai_summary import generate_summary, generate_markdown_report

    logger = logging.getLogger('snooger')

    logger.info("Building final report...")
    report = build_final_report(workspace, target, state)

    logger.info("Generating AI summary and reports...")
    ai_synopsis = generate_summary(ai, report)
    reports = generate_markdown_report(report, ai_synopsis, workspace)

    emit('phase_completed', {'phase': 'reporting'}, source='reporting')
    return {'report': report, 'report_files': reports}


# ─── Main Orchestrator ────────────────────────────────────────────────

async def run_scan(args, config: dict) -> None:
    """Main async scan orchestrator."""
    start_time = time.time()
    target = args.target
    logger = logging.getLogger('snooger')

    # Apply profile
    if args.profile:
        config = apply_profile(config, args.profile)

    # Setup workspace
    domain = target.replace('https://', '').replace('http://', '').split('/')[0]
    workspace = os.path.join(
        config.get('workspace', 'workspace'),
        f"{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    )
    os.makedirs(workspace, exist_ok=True)
    logger.info(f"Workspace: {workspace}")

    # Initialize components
    emit('scan_started', {'target': target, 'workspace': workspace}, source='main')

    rl = init_rate_limiter(config.get('rate_limit', {}))
    state = StateManager(workspace)
    scope = ScopeManager()

    # Scope setup
    if hasattr(args, 'scope') and args.scope:
        scope.load_from_file(args.scope)
    else:
        scope.add_target(domain)

    # AI engine
    ai = None
    if config['ai']['mode'] != 'off':
        try:
            ai = AIEngine(config)
            providers = ai.get_available_providers()
            logger.info(f"AI engine initialized with providers: {providers}")
        except Exception as e:
            logger.warning(f"AI engine init failed: {e}")

    # Async executor
    async_cfg = config.get('async', {})
    executor = AsyncExecutor(
        max_concurrent=async_cfg.get('max_concurrent_scans', 20),
        thread_pool_size=async_cfg.get('thread_pool_size', 10)
    )

    # Plugin system
    plugins = init_plugins(config)
    context = ScanContext(target, workspace, config, scope=scope, state=state,
                          ai=ai, event_bus=get_event_bus())

    # Notifications
    notif = init_notifications(config)

    # ─── Execute Phases ───────────────────────────────────────────

    phase_results = {}

    try:
        # Phase 1: Reconnaissance
        print_phase_header(1, "Reconnaissance")
        recon_data = await phase_recon(target, workspace, config,
                                       scope, state, ai, executor, context)
        phase_results['recon'] = recon_data

        # Plugin: custom recon scanners
        plugin_findings = plugins.run_scanners('recon', target, context)
        if plugin_findings:
            logger.info(f"Plugin recon findings: {len(plugin_findings)}")

        # Phase 2: Scanning
        print_phase_header(2, "Port Scanning & Tech Detection")
        scan_data = await phase_scanning(target, workspace, config,
                                          scope, state, ai, executor, recon_data)
        phase_results['scanning'] = scan_data

        # Phase 3: Crawling
        print_phase_header(3, "Web Crawling & JS Analysis")
        crawl_data = await phase_crawl(target, workspace, config,
                                        scope, state, ai, executor, recon_data)
        phase_results['crawl'] = crawl_data

        # Phase 4: Vulnerability Analysis
        print_phase_header(4, "Vulnerability Analysis")
        vuln_data = await phase_vuln_analysis(target, workspace, config,
                                              scope, state, ai, executor,
                                              recon_data, crawl_data, scan_data)
        phase_results['vuln'] = vuln_data

        # Plugin: custom vulnerability scanners
        plugin_vuln_findings = plugins.run_scanners('vuln', target, context)
        if plugin_vuln_findings:
            logger.info(f"Plugin vuln findings: {len(plugin_vuln_findings)}")

        # Phase 5: Auth Testing
        print_phase_header(5, "Authentication & Authorization Testing")
        auth_data = await phase_auth_testing(target, workspace, config,
                                             state, ai, crawl_data)
        phase_results['auth'] = auth_data

        # Phase 6: Business Logic
        print_phase_header(6, "Business Logic Testing")
        biz_data = await phase_business_logic(target, workspace, config,
                                              state, crawl_data)
        phase_results['business'] = biz_data

        # Phase 7: Exploitation (skip if --skip-exploit)
        if not getattr(args, 'skip_exploit', False):
            print_phase_header(7, "Exploitation & PoC Generation")
            exploit_data = await phase_exploitation(target, workspace, config,
                                                     state, ai, vuln_data)
            phase_results['exploit'] = exploit_data

        # Phase 8: Reporting
        print_phase_header(8, "Report Generation")
        report_data = await phase_reporting(target, workspace, config, state, ai)
        phase_results['report'] = report_data

    except KeyboardInterrupt:
        logger.warning("\nScan interrupted by user. Generating partial report...")
        try:
            await phase_reporting(target, workspace, config, state, ai)
        except Exception:
            pass

    except Exception as e:
        logger.error(f"Scan error: {e}")
        import traceback
        traceback.print_exc()

    finally:
        executor.shutdown()

    # ─── Summary ──────────────────────────────────────────────────
    findings_count = state.findings_count() if hasattr(state, 'findings_count') else 0

    summary = {
        'Target': target,
        'Workspace': workspace,
        'Duration': f"{time.time() - start_time:.0f}s" if 'start_time' in locals() else "N/A",
        'Total Findings': findings_count,
    }

    print_summary_table(summary)

    emit('scan_completed', {
        'target': target, 'workspace': workspace,
        'summary': {'total_findings': findings_count},
    }, source='main')

    logger.info(f"\n✅ Scan complete! Reports saved to: {workspace}")
    
    # Close state manager last
    state.close()


# ─── CLI Arguments ────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description='Snooger v3.0 — Professional Penetration Testing Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python snooger.py -t example.com
  python snooger.py -t example.com -p thorough
  python snooger.py -t example.com -p stealth --scope scope.txt
  python snooger.py -t https://app.example.com --skip-exploit
  python snooger.py --list-plugins
        """
    )

    # Required
    parser.add_argument('-t', '--target', help='Target domain or URL')

    # Profiles
    parser.add_argument('-p', '--profile', choices=['quick', 'stealth', 'thorough'],
                        default=None, help='Scan profile (default: thorough)')

    # Scope
    parser.add_argument('-s', '--scope', help='Scope file (txt/json)')
    parser.add_argument('--exclude', nargs='+', help='Exclude domains/patterns')

    # Config
    parser.add_argument('-c', '--config', default='config.yaml', help='Config file path')
    parser.add_argument('-w', '--workspace', help='Custom workspace directory')

    # Phases
    parser.add_argument('--skip-exploit', action='store_true', help='Skip exploitation phase')
    parser.add_argument('--skip-post', action='store_true', help='Skip post-exploitation')
    parser.add_argument('--recon-only', action='store_true', help='Only run reconnaissance')
    parser.add_argument('--vuln-only', action='store_true', help='Only run vulnerability analysis')

    # Auth
    parser.add_argument('--cookie', help='Session cookie for authenticated scanning')
    parser.add_argument('--header', nargs='+', help='Custom headers (key:value)')
    parser.add_argument('--jwt', help='JWT token for authenticated scanning')
    parser.add_argument('--login-url', help='Login URL for auth testing')

    # AI
    parser.add_argument('--ai-mode', choices=['auto', 'smart', 'light', 'off'],
                        help='Override AI mode')

    # Output
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-q', '--quiet', action='store_true', help='Quiet mode')
    parser.add_argument('--json-output', help='Output results as JSON to file')

    # Plugins
    parser.add_argument('--list-plugins', action='store_true', help='List loaded plugins')
    parser.add_argument('--no-plugins', action='store_true', help='Disable plugins')

    # Resume
    parser.add_argument('--resume', help='Resume scan from workspace directory')

    return parser.parse_args()


# ─── Entry Point ──────────────────────────────────────────────────────

def main():
    args = parse_args()

    # Banner
    print_banner(VERSION)

    # Load config
    config_path = os.path.join(BASE_DIR, args.config) if not os.path.isabs(args.config) else args.config
    try:
        config = load_config(config_path)
    except FileNotFoundError:
        print(f"[!] Config not found: {config_path}")
        print(f"    Create one from config.yaml.example or run with defaults")
        config = load_config.__wrapped__(config_path) if hasattr(load_config, '__wrapped__') else {}
        from core.config_loader import _apply_defaults
        config = _apply_defaults({})

    # Override workspace
    if args.workspace:
        config['workspace'] = args.workspace

    # Override AI mode
    if args.ai_mode:
        config['ai']['mode'] = args.ai_mode

    # Disable plugins
    if getattr(args, 'no_plugins', False):
        config['plugins']['enabled'] = False

    # List plugins
    if args.list_plugins:
        plugins = init_plugins(config)
        plugin_list = plugins.list_plugins()
        if plugin_list:
            print(f"\n📦 Loaded {len(plugin_list)} plugins:\n")
            for p in plugin_list:
                print(f"  [{p['category']}] {p['name']} v{p['version']} — {p['description']}")
        else:
            print("\n📦 No plugins found. Add .py files to the plugins/ directory.\n")
        return

    # Target validation
    if not args.target and not args.resume:
        print("[!] Target required. Use -t <domain> or --resume <workspace>")
        return

    # Setup
    workspace_base = config.get('workspace', 'workspace')
    os.makedirs(workspace_base, exist_ok=True)
    logger = setup_logging(workspace_base, args.verbose)

    # Suppress warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    logger.info(f"Snooger v{VERSION} starting...")
    logger.info(f"Target: {args.target}")
    if args.profile:
        logger.info(f"Profile: {args.profile}")

    # Run async
    try:
        asyncio.run(run_scan(args, config))
    except KeyboardInterrupt:
        logger.info("\n[!] Scan aborted by user.")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()
