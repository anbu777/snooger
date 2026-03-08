#!/usr/bin/env python3
"""
Snooger v2.0 - Professional All-in-One Penetration Testing Framework
Designed for bug bounty platforms: HackerOne, Bugcrowd, Intigriti
"""
import os
import sys
import argparse
import json
import time
import logging
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.config_loader import load_config, apply_profile
from core.logger import setup_logger, get_logger
from core.dependency_checker import check_dependencies, print_dependency_report
from core.ai_engine import AIEngine
from core import interactive
from core.rate_limiter import init_rate_limiter
from core.state_manager import StateManager
from core.utils import sanitize_domain, write_json

BANNER = r"""
 ░▒▓███████▓▒░▒▓███████▓▒░ ░▒▓██████▓▒░ ░▒▓██████▓▒░ ░▒▓██████▓▒░░▒▓████████▓▒░▒▓███████▓▒░
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░
 ░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒▒▓███▓▒░▒▓██████▓▒░ ░▒▓███████▓▒░
       ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░
       ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░
░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░ ░▒▓██████▓▒░ ░▒▓██████▓▒░░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░

         v2.0 Professional | Bug Bounty Edition | HackerOne & Bugcrowd Ready
"""

def parse_args():
    parser = argparse.ArgumentParser(
        description='Snooger v2.0 - Professional Penetration Testing Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('domain', help='Target domain or URL (e.g., example.com)')
    parser.add_argument('--scope-file', help='Scope file (plain text, Bugcrowd/HackerOne JSON)')
    parser.add_argument('--scope', help='Additional in-scope IPs/CIDRs (comma-separated)')
    parser.add_argument('--out-of-scope', help='Out-of-scope domains (comma-separated)')
    parser.add_argument('--config', default='config.yaml', help='Config file')
    parser.add_argument('--profile', choices=['quick', 'stealth', 'thorough'],
                        help='Scan profile preset')
    parser.add_argument('--rate-limit', type=float, help='Requests per second (overrides config)')
    parser.add_argument('--skip-recon', action='store_true')
    parser.add_argument('--skip-scan', action='store_true')
    parser.add_argument('--skip-vuln', action='store_true')
    parser.add_argument('--skip-exploit', action='store_true')
    parser.add_argument('--skip-post', action='store_true')
    parser.add_argument('--skip-api', action='store_true')
    parser.add_argument('--skip-js', action='store_true')
    parser.add_argument('--resume', action='store_true', help='Resume incomplete scan')
    parser.add_argument('--targets-file', help='File with multiple targets (one per line)')
    parser.add_argument('--output-dir', help='Custom output directory')
    parser.add_argument('--no-ai', action='store_true', help='Disable AI features')
    parser.add_argument('--severity', default='critical,high,medium',
                        help='Nuclei severity filter (default: critical,high,medium)')
    parser.add_argument('--monitor', action='store_true',
                        help='Enable continuous monitoring mode after scan')
    parser.add_argument('--monitor-interval', type=int, default=60,
                        help='Monitor rescan interval in minutes (default: 60)')
    parser.add_argument('--skip-cloud', action='store_true',
                        help='Skip cloud/S3/Azure/GCS infrastructure scan')
    parser.add_argument('--skip-upload', action='store_true',
                        help='Skip file upload testing')
    parser.add_argument('--skip-race', action='store_true',
                        help='Skip race condition testing')
    parser.add_argument('--jwt-token', help='JWT token to analyze for vulnerabilities')
    parser.add_argument('--login-url', help='Login URL for brute-force protection testing')
    return parser.parse_args()

def setup_workspace(target: str, base_dir: str, custom_dir: str = None) -> str:
    safe = target.replace('/', '_').replace(':', '_').replace('.', '_')
    target_dir = custom_dir or os.path.join(base_dir, safe)
    for subdir in ['raw_logs/recon', 'raw_logs/scan', 'raw_logs/vuln',
                   'raw_logs/exploit', 'raw_logs/post_exploit',
                   'raw_logs/javascript', 'submissions']:
        os.makedirs(os.path.join(target_dir, subdir), exist_ok=True)
    return target_dir

def main():
    print(BANNER)
    args = parse_args()
    start_time = datetime.utcnow().isoformat()

    # ─── Multiple targets mode ─────────────────────────────────────
    if args.targets_file:
        if not os.path.exists(args.targets_file):
            print(f"[!] Targets file not found: {args.targets_file}")
            sys.exit(1)
        with open(args.targets_file) as f:
            targets = [l.strip() for l in f if l.strip() and not l.startswith('#')]
        print(f"[*] Multiple targets mode: {len(targets)} targets from {args.targets_file}")
        results_summary = []
        for i, target in enumerate(targets, 1):
            print(f"\n{'='*60}")
            print(f"  TARGET {i}/{len(targets)}: {target}")
            print(f"{'='*60}")
            # Run each target as its own scan using subprocess
            import subprocess, shlex
            cmd = [sys.executable, __file__, target] + [
                a for a in sys.argv[1:]
                if '--targets-file' not in a and target not in a
            ]
            ret = subprocess.run(cmd, timeout=7200)
            results_summary.append({'target': target, 'exit_code': ret.returncode})
        print(f"\n[*] All {len(targets)} targets complete.")
        for r in results_summary:
            status = "✅" if r['exit_code'] == 0 else "❌"
            print(f"  {status} {r['target']}")
        return

    # Validate target
    try:
        domain = sanitize_domain(args.domain)
    except ValueError as e:
        print(f"[!] Invalid target: {e}")
        sys.exit(1)

    # Load config
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), args.config)
    try:
        config = load_config(config_path)
    except FileNotFoundError:
        print(f"[!] Config file not found: {config_path}")
        sys.exit(1)

    # Apply profile
    if args.profile:
        config = apply_profile(config, args.profile)

    # Override rate limit
    if args.rate_limit:
        config.setdefault('rate_limit', {})['requests_per_second'] = args.rate_limit

    # Setup workspace
    workspace_base = config.get('workspace', 'workspace')
    target_dir = setup_workspace(domain, workspace_base, args.output_dir)

    # Setup logging
    logger = setup_logger(target_dir)
    logger.info(f"Snooger v2.0 starting for target: {domain}")
    logger.info(f"Workspace: {target_dir}")

    # Init rate limiter
    rl = init_rate_limiter(config)

    # Init state manager
    state = StateManager(target_dir, domain)
    if args.resume:
        scan_id = state.get_or_create_scan()
        logger.info(f"Resuming scan ID {scan_id}")
    else:
        scan_id = state.create_scan()

    # Dependency check
    missing_req, missing_opt = check_dependencies(config)
    print_dependency_report(missing_req, missing_opt)
    if missing_req:
        logger.warning(f"{len(missing_req)} required tools missing")
        if not interactive.confirm_action("Continue anyway?", default=False):
            sys.exit(1)

    # AI Engine
    if args.no_ai:
        config['ai']['mode'] = 'off'
    ai = AIEngine(config)
    if config['ai']['mode'] == 'auto' and not args.no_ai:
        mode_choice = interactive.get_user_choice(
            "Select AI mode:",
            ["Smart (Llama3.2 — 8GB+ RAM recommended)",
             "Light (TinyLlama — 4GB RAM)",
             "Off (rule-based only)"],
            default=2
        )
        if 'Smart' in mode_choice:
            config['ai']['mode'] = 'smart'
        elif 'Light' in mode_choice:
            config['ai']['mode'] = 'light'
        else:
            config['ai']['mode'] = 'off'
        ai.mode = config['ai']['mode']
    logger.info(f"AI mode: {config['ai']['mode']}")

    # Scope Manager
    from modules.scope.scope_manager import ScopeManager
    scope = ScopeManager()
    if args.scope_file:
        scope.load_from_file(args.scope_file)
        logger.info(f"Scope loaded from {args.scope_file}")
    scope.add_domain(domain)
    if args.scope:
        for s in args.scope.split(','):
            scope.add_domain(s.strip())
    if args.out_of_scope:
        for s in args.out_of_scope.split(','):
            scope.add_out_of_scope(s.strip())

    # Authentication
    from modules.auth.auth_handler import AuthManager
    auth = AuthManager(target_dir, config)
    target_url = domain if domain.startswith('http') else f"https://{domain}"
    auth.set_base_url(target_url)

    if interactive.confirm_action("Does the target require authentication?", default=False):
        auth_choice = interactive.get_user_choice(
            "Authentication method:",
            ["Form-based login", "HTTP Basic Auth",
             "Bearer/JWT Token", "Cookies (paste)", "Load saved session"],
            default=1
        )
        if auth_choice == "Form-based login":
            login_url = interactive.get_user_input("Login URL", f"{target_url}/login")
            username = interactive.get_user_input("Username")
            password = interactive.get_user_input("Password")
            user_field = interactive.get_user_input("Username field name", "username")
            pass_field = interactive.get_user_input("Password field name", "password")
            csrf_field = interactive.get_user_input("CSRF field name (leave blank if none)", "")
            auth.login_form(login_url, username, password, user_field, pass_field,
                            csrf_field=csrf_field or None)
        elif auth_choice == "HTTP Basic Auth":
            u = interactive.get_user_input("Username")
            p = interactive.get_user_input("Password")
            auth.login_basic(u, p)
        elif auth_choice == "Bearer/JWT Token":
            token = interactive.get_user_input("Token value")
            header = interactive.get_user_input("Header name", "Authorization")
            scheme = interactive.get_user_input("Scheme", "Bearer")
            auth.set_token(token, header, scheme)
        elif auth_choice == "Cookies (paste)":
            raw = interactive.get_user_input("Cookies (name=value, separated by ;)")
            cookies = {}
            for part in raw.split(';'):
                if '=' in part:
                    k, v = part.split('=', 1)
                    cookies[k.strip()] = v.strip()
            auth.set_cookies(cookies)
        elif auth_choice == "Load saved session":
            if not auth.load_session():
                logger.warning("No saved session found")
    else:
        auth.load_session()

    cookies_file = None
    if auth.is_logged_in():
        cookies_file = os.path.join(target_dir, 'cookies.txt')
        auth.export_cookies_netscape(cookies_file)
        logger.info(f"Cookies exported to {cookies_file}")

    # Profile settings
    profile = config.get('_profile', {})
    ffuf_threads = profile.get('ffuf_threads', 20)
    ffuf_delay = profile.get('ffuf_delay', 0.5)

    # ─── PHASE 1: RECONNAISSANCE ──────────────────────────────────
    recon_summary = {}
    if not args.skip_recon and not (args.resume and state.is_phase_completed('recon')):
        print(f"\n{'='*60}")
        print(f"  [PHASE 1] RECONNAISSANCE")
        print(f"{'='*60}")
        state.checkpoint_phase('recon', 'started')

        from modules.reconnaissance.subdomain import run_full_subdomain_enum
        from modules.reconnaissance.filter_alive import filter_alive
        from modules.reconnaissance.tech_detect import detect_technologies, get_all_technologies, get_recommended_modules
        from modules.reconnaissance.content_discovery import discover_content
        from modules.reconnaissance.historical_urls import get_all_historical_urls, extract_interesting_params
        from modules.reconnaissance.subdomain_takeover import check_subdomain_takeovers
        from modules.reconnaissance.tech_specific import run_tech_specific_scans

        # Subdomain enumeration
        subdomains = run_full_subdomain_enum(domain, target_dir)
        logger.info(f"Total subdomains: {len(subdomains)}")

        # Filter alive (with scope)
        alive = filter_alive(subdomains, target_dir, scope=scope)

        # Technology detection
        max_targets = profile.get('max_subdomains', 100)
        all_targets = list(set([target_url] + alive))[:max_targets]
        tech_results = detect_technologies(all_targets, target_dir)
        all_techs = get_all_technologies(tech_results)
        recommended_modules = get_recommended_modules(tech_results)

        # Content discovery
        content_results = discover_content(
            domain, target_dir,
            tech_stack=all_techs,
            threads=ffuf_threads,
            delay=ffuf_delay,
            cookies_file=cookies_file
        )

        # Historical URLs
        historical_urls = get_all_historical_urls(domain, target_dir)
        interesting_params = extract_interesting_params(historical_urls)

        # Subdomain takeover
        takeover_findings = check_subdomain_takeovers(subdomains, target_dir)

        # Tech-specific scanning
        time.sleep(config.get('rate_limit', {}).get('delay_between_phases', 2))
        tech_specific = run_tech_specific_scans(all_targets, tech_results, target_dir, auth)

        recon_summary = {
            'subdomains': subdomains,
            'alive_subdomains': alive,
            'technologies': tech_results,
            'all_technologies': all_techs,
            'recommended_modules': recommended_modules,
            'content_discovery': content_results,
            'historical_urls_count': len(historical_urls),
            'interesting_params': interesting_params,
            'subdomain_takeovers': takeover_findings,
        }
        write_json(os.path.join(target_dir, 'recon_summary.json'), recon_summary)
        state.save_subdomains([{'domain': s, 'alive': s in alive} for s in subdomains])
        state.checkpoint_phase('recon', 'completed', {
            'subdomains': len(subdomains), 'alive': len(alive),
            'takeovers': len(takeover_findings)
        })
        print(f"\n[+] Recon complete: {len(subdomains)} subdomains, {len(alive)} alive, "
              f"{len(takeover_findings)} takeovers")
    else:
        print("\n[SKIP] Reconnaissance phase skipped.")
        from core.utils import load_json_file
        recon_summary = load_json_file(os.path.join(target_dir, 'recon_summary.json')) or {}

    alive_hosts = recon_summary.get('alive_subdomains', [])
    all_targets = list(set([target_url] + alive_hosts))
    all_techs = recon_summary.get('all_technologies', [])
    recommended_modules = recon_summary.get('recommended_modules', [])

    # ─── CRAWL + JS ANALYSIS + PARAM DISCOVERY ────────────────────
    crawler_results = {}
    js_results = {}
    if not args.skip_js and not (args.resume and state.is_phase_completed('crawl')):
        print(f"\n{'='*60}")
        print(f"  [PHASE 1b] CRAWL + JS ANALYSIS + PARAMETER DISCOVERY")
        print(f"{'='*60}")
        state.checkpoint_phase('crawl', 'started')

        from modules.crawler.web_crawler import crawl_target
        from modules.javascript.js_analyzer import analyze_js_files
        from modules.reconnaissance.parameter_discovery import run_parameter_discovery

        crawler_results = crawl_target(target_url, target_dir, auth=auth,
                                        scope=scope, config=config)
        all_urls = crawler_results.get('visited_urls', [])

        js_files = crawler_results.get('js_files', [])
        if js_files:
            js_results = analyze_js_files(js_files, target_url, target_dir, auth)
            # Add JS-discovered endpoints to URL pool
            all_urls.extend(js_results.get('endpoints_found', []))

        # Historical URL parameter extraction
        from core.utils import load_json_file
        hist_file = os.path.join(target_dir, 'historical_urls.txt')
        hist_urls = []
        if os.path.exists(hist_file):
            with open(hist_file, 'r') as f:
                hist_urls = [l.strip() for l in f if l.strip()]
        all_urls.extend(hist_urls[:500])
        all_urls = list(set(all_urls))

        # Parameter discovery
        run_parameter_discovery(all_urls, target_dir, auth)

        state.checkpoint_phase('crawl', 'completed', {
            'urls': len(all_urls), 'js_files': len(js_files),
            'secrets': len(js_results.get('secrets', []))
        })
        print(f"\n[+] Crawl complete: {len(crawler_results.get('visited_urls',[]))} pages, "
              f"{len(js_files)} JS files")
        if js_results.get('secrets'):
            print(f"[!] {len(js_results['secrets'])} potential secrets found in JS files!")
    else:
        print("\n[SKIP] Crawl/JS phase skipped.")

    # ─── PHASE 2: PORT SCANNING ───────────────────────────────────
    if not args.skip_scan and not (args.resume and state.is_phase_completed('scan')):
        print(f"\n{'='*60}")
        print(f"  [PHASE 2] PORT SCANNING + SSL/TLS")
        print(f"{'='*60}")
        state.checkpoint_phase('scan', 'started')
        time.sleep(config.get('rate_limit', {}).get('delay_between_phases', 2))

        from modules.scanning.port_scan import scan_ports, scan_ssl_tls
        scan_targets = [t.replace('http://', '').replace('https://', '').split('/')[0]
                        for t in all_targets[:30]]
        port_results = scan_ports(scan_targets, target_dir)

        ssl_results = scan_ssl_tls(domain, target_dir)
        write_json(os.path.join(target_dir, 'testssl_results.json'), ssl_results)

        if ssl_results.get('findings'):
            print(f"[!] {len(ssl_results['findings'])} SSL/TLS issues found")

        state.checkpoint_phase('scan', 'completed', {'hosts': len(port_results)})
        print(f"\n[+] Port scan complete: {len(port_results)} hosts")
    else:
        print("\n[SKIP] Port scanning phase skipped.")

    # ─── PHASE 3: VULNERABILITY ANALYSIS ─────────────────────────
    vulnerabilities = []
    if not args.skip_vuln and not (args.resume and state.is_phase_completed('vuln')):
        print(f"\n{'='*60}")
        print(f"  [PHASE 3] VULNERABILITY ANALYSIS")
        print(f"{'='*60}")
        state.checkpoint_phase('vuln', 'started')
        time.sleep(config.get('rate_limit', {}).get('delay_between_phases', 2))

        from modules.vulnerability.nuclei_runner import run_nuclei
        from modules.vulnerability.active_vulns import run_active_vulnerability_tests
        from modules.reconnaissance.info_disclosure import run_info_disclosure_tests
        from modules.api.api_tester import run_api_tests

        # Nuclei scan
        nuclei_targets = scope.filter_targets(all_targets[:50])
        extra_headers = auth.get_auth_headers_for_tool() if auth.is_logged_in() else None
        vulnerabilities = run_nuclei(
            nuclei_targets, target_dir,
            severity=args.severity,
            cookies_file=cookies_file,
            tech_stack=all_techs,
            extra_headers=extra_headers
        )

        # Active vulnerability tests on URLs with parameters
        all_test_urls = []
        if crawler_results:
            all_test_urls.extend(crawler_results.get('visited_urls', []))
        from core.utils import load_json_file
        hist_file = os.path.join(target_dir, 'historical_urls.txt')
        if os.path.exists(hist_file):
            with open(hist_file) as f:
                all_test_urls.extend([l.strip() for l in f if l.strip() and '?' in l])
        all_test_urls = list(set(all_test_urls))

        active_findings = run_active_vulnerability_tests(
            all_test_urls, target_dir, auth=auth,
            forms=crawler_results.get('forms', []) if crawler_results else []
        )

        # Information disclosure
        run_info_disclosure_tests(nuclei_targets[:15], target_dir, auth)

        # API security testing
        if not args.skip_api:
            run_api_tests(target_url, target_dir, auth=auth, crawler_results=crawler_results)

        # AI-powered prioritization
        if ai.mode != 'off' and vulnerabilities:
            print("[AI] Prioritizing vulnerabilities...")
            vulnerabilities = ai.prioritize_vulnerabilities(vulnerabilities)

        state.checkpoint_phase('vuln', 'completed', {'findings': len(vulnerabilities)})
        print(f"\n[+] Vulnerability analysis complete: {len(vulnerabilities)} findings")
    else:
        print("\n[SKIP] Vulnerability analysis phase skipped.")

    # ─── PHASE 3b: BUSINESS LOGIC (IDOR + Race Condition + Upload) ──
    if not args.skip_vuln:
        print(f"\n[*] Business Logic Testing (IDOR)...")
        from modules.business_logic.idor import scan_idor
        idor_urls = []
        if crawler_results:
            idor_urls.extend(crawler_results.get('visited_urls', []))
        hist_file = os.path.join(target_dir, 'historical_urls.txt')
        hist_url_list = []
        if os.path.exists(hist_file):
            with open(hist_file) as f:
                hist_url_list = [l.strip() for l in f if l.strip()]
            idor_urls.extend(hist_url_list)
        idor_urls = scope.filter_targets(list(set(idor_urls)))
        idor_findings = scan_idor(auth, idor_urls, target_dir)
        if idor_findings:
            print(f"[!] {len(idor_findings)} IDOR vulnerability candidates found!")

        # Race condition testing
        if not args.skip_race:
            print(f"\n[*] Race Condition Testing...")
            from modules.business_logic.race_condition import run_race_condition_tests
            race_findings = run_race_condition_tests(
                target_dir, auth=auth,
                crawler_results=crawler_results or {},
                historical_urls=hist_url_list
            )
            if race_findings:
                print(f"[!] {len(race_findings)} race condition candidates found!")

        # File upload testing
        if not args.skip_upload:
            print(f"\n[*] File Upload Testing...")
            from modules.vulnerability.file_upload_tester import run_file_upload_tests
            upload_findings = run_file_upload_tests(
                target_dir, auth=auth,
                crawler_results=crawler_results or {},
                historical_urls=hist_url_list
            )
            if upload_findings:
                print(f"[!] {len(upload_findings)} file upload vulnerabilities found!")

        # Cloud / infrastructure scanning
        if not args.skip_cloud:
            print(f"\n[*] Cloud Infrastructure Scanning (S3/Azure/GCS/DB)...")
            from modules.scanning.cloud_scanner import run_cloud_scans
            cloud_findings = run_cloud_scans(domain, target_dir, alive_hosts=all_targets)
            s3_count = len(cloud_findings.get('s3_buckets', []))
            db_count = len(cloud_findings.get('database_exposures', []))
            if s3_count or db_count:
                print(f"[!] Cloud: {s3_count} S3/blob issues, {db_count} DB exposures!")

        # Auth / JWT / OAuth / Forceful Browsing testing
        print(f"\n[*] Authentication Security Testing...")
        from modules.auth.auth_testing import run_auth_tests
        run_auth_tests(
            target_url, target_dir, auth=auth,
            crawler_results=crawler_results or {},
            login_url=args.login_url or f"{target_url}/login",
            jwt_token=args.jwt_token
        )

    # ─── PHASE 4: EXPLOITATION ────────────────────────────────────
    if not args.skip_exploit and not (args.resume and state.is_phase_completed('exploit')):
        print(f"\n{'='*60}")
        print(f"  [PHASE 4] EXPLOITATION")
        print(f"{'='*60}")
        if interactive.confirm_action("Proceed with exploitation phase?", default=True):
            state.checkpoint_phase('exploit', 'started')
            from modules.exploitation.exploit_selector import select_vulnerabilities
            from modules.exploitation.sqlmap_wrapper import run_sqlmap
            from modules.exploitation.chain_engine import detect_chains, generate_chain_report

            selected = select_vulnerabilities(target_dir)
            if selected:
                for vuln in selected:
                    if 'original' in vuln:
                        name = vuln['original'].get('info', {}).get('name', '').lower()
                        url = vuln['original'].get('matched-at', vuln['original'].get('host', ''))
                    else:
                        name = vuln.get('info', {}).get('name', vuln.get('type', '')).lower()
                        url = vuln.get('matched-at', vuln.get('host', vuln.get('url', '')))

                    if 'sql' in name:
                        run_sqlmap(url, target_dir, cookies_file=cookies_file)
                    elif 'xss' in name:
                        print(f"[*] XSS confirmed at {url} — use browser/Burp for full PoC")
                    elif 'ssrf' in name:
                        print(f"[*] SSRF confirmed at {url} — attempt cloud metadata access manually")
                    else:
                        print(f"[*] Manual exploitation required for: {name} @ {url}")

            # Detect exploit chains
            all_findings = vulnerabilities.copy()
            from core.utils import load_json_file
            active = load_json_file(os.path.join(target_dir, 'active_vuln_findings.json'))
            if active:
                for cat_findings in active.values():
                    if isinstance(cat_findings, list):
                        all_findings.extend(cat_findings)
            chains = detect_chains(all_findings)
            if chains:
                print(generate_chain_report(chains))

            state.checkpoint_phase('exploit', 'completed')
        else:
            print("[SKIP] Exploitation skipped by user.")
    else:
        print("\n[SKIP] Exploitation phase skipped.")

    # ─── PHASE 5: POST-EXPLOITATION ───────────────────────────────
    if not args.skip_post:
        print(f"\n{'='*60}")
        print(f"  [PHASE 5] POST-EXPLOITATION")
        print(f"{'='*60}")
        if interactive.confirm_action(
            "Do you have a web shell / RCE access for post-exploitation?", default=False):
            shell_url = interactive.get_user_input(
                "Shell URL (e.g., http://target/shell.php?cmd=COMMAND)")
            if shell_url:
                from modules.post_exploitation.linux_pe import upload_and_run_linpeas
                pe_result = upload_and_run_linpeas(auth, target_dir, shell_url)
                if pe_result.get('suggestions'):
                    print(f"\n[!] {len(pe_result['suggestions'])} privilege escalation vectors found!")
                    for s in pe_result['suggestions']:
                        sev = s.get('severity', 'unknown')
                        note = s.get('note', s.get('name', str(s)))
                        print(f"  [{sev.upper()}] {note}")
        else:
            print("[*] No shell access. Skipping post-exploitation.")

    # ─── PHASE 6: REPORTING ───────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"  [PHASE 6] REPORTING")
    print(f"{'='*60}")

    from modules.reporting.json_builder import build_final_report
    from modules.reporting.ai_summary import (generate_summary, generate_html_report,
                                               generate_markdown_report,
                                               generate_hackerone_submission)

    final_report = build_final_report(target_dir, domain,
                                       start_time=start_time, state_manager=state)

    # AI summary
    ai_summary = ""
    if ai.mode != 'off':
        print("[AI] Generating executive summary...")
        ai_summary = generate_summary(ai, final_report)
        if ai_summary:
            with open(os.path.join(target_dir, 'ai_summary.txt'), 'w') as f:
                f.write(ai_summary)
            print(f"\n{'─'*60}")
            print("[AI EXECUTIVE SUMMARY]")
            print(ai_summary[:800] + ("..." if len(ai_summary) > 800 else ""))
            print(f"{'─'*60}")

    # Generate reports
    html_path = generate_html_report(final_report, ai_summary, target_dir)
    md_path = generate_markdown_report(final_report, ai_summary, target_dir)

    # Generate HackerOne submissions for top findings
    top_findings = [v for v in final_report.get('vulnerabilities', [])
                    if v.get('severity', v.get('info', {}).get('severity', '')) in ('critical', 'high')]
    for finding in top_findings[:3]:
        generate_hackerone_submission(finding, ai, target_dir)

    # New findings vs last scan
    new_findings = state.get_new_findings_vs_last_scan()
    if new_findings:
        print(f"\n[!] {len(new_findings)} NEW findings compared to last scan (delta report)")

    state.complete_scan()
    state.close()

    # Final summary
    summary = final_report.get('summary', {})
    sev = summary.get('by_severity', {})
    print(f"\n{'='*60}")
    print("  SCAN COMPLETE")
    print(f"{'='*60}")
    print(f"  Target:   {domain}")
    print(f"  Critical: {sev.get('critical', 0)}")
    print(f"  High:     {sev.get('high', 0)}")
    print(f"  Medium:   {sev.get('medium', 0)}")
    print(f"  Low:      {sev.get('low', 0)}")
    print(f"  IDOR:     {summary.get('idor_findings', 0)}")
    print(f"  Takeover: {summary.get('subdomain_takeovers', 0)}")
    print(f"  Chains:   {summary.get('exploit_chains', 0)}")
    print(f"\n  Reports saved to: {target_dir}/")
    print(f"    JSON:   final_report.json")
    print(f"    HTML:   report.html")
    print(f"    MD:     report.md")
    print(f"    AI:     ai_summary.txt")
    if top_findings:
        print(f"    Submissions: submissions/ ({len(top_findings[:3])} HackerOne drafts)")
    print(f"{'='*60}")
    logger.info("Snooger v2.0 completed successfully.")

    # ─── Monitor Mode ──────────────────────────────────────────────
    if args.monitor:
        print(f"\n[*] Starting continuous monitor mode (interval: {args.monitor_interval}min)")
        from modules.scanning.monitor_mode import MonitorMode
        from modules.reporting.json_builder import build_final_report as _build_report

        def _rescan():
            """Mini rescan function for monitor mode — runs nuclei + active vulns."""
            from modules.vulnerability.nuclei_runner import run_nuclei
            from modules.vulnerability.active_vulns import run_active_vulnerability_tests
            new_vulns = run_nuclei(
                scope.filter_targets(all_targets[:30]), target_dir,
                severity=args.severity, cookies_file=cookies_file,
                tech_stack=all_techs
            )
            report = _build_report(target_dir, domain, state_manager=state)
            return report.get('vulnerabilities', [])

        monitor_config = dict(config)
        monitor_config['monitor'] = {
            'interval_minutes': args.monitor_interval,
            'max_rounds': 0
        }
        monitor = MonitorMode(domain, target_dir, monitor_config, _rescan)
        try:
            monitor.run()
        except KeyboardInterrupt:
            print("\n[*] Monitor mode stopped by user.")

if __name__ == '__main__':
    main()
