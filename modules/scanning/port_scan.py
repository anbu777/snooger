import os
import json
import logging
from typing import List, Dict
from core.utils import run_command, save_raw_output, safe_remove

logger = logging.getLogger('snooger')

def scan_ports(targets: List[str], workspace_dir: str, ports: str = "top1000") -> Dict:
    """Run nmap port scan with proper JSON output parsing."""
    if not targets:
        return {}
    logger.info(f"Running nmap port scan on {len(targets)} targets...")

    input_file = os.path.join(workspace_dir, 'temp_nmap_targets.txt')
    output_xml = os.path.join(workspace_dir, 'nmap_results.xml')

    try:
        with open(input_file, 'w') as f:
            for t in targets:
                # Strip protocol
                host = t.replace('http://', '').replace('https://', '').split('/')[0]
                f.write(host + '\n')

        cmd = (f"sudo nmap -sS -sV -T4 --top-ports 1000 "
               f"-iL {input_file} -oX {output_xml} --open "
               f"--script=http-headers,banner,ssl-cert "
               f"--max-retries 2 --host-timeout 120s")
        stdout, stderr, rc = run_command(cmd, timeout=3600)
        save_raw_output(workspace_dir, 'scan', 'nmap', stdout + stderr, 'txt')

    finally:
        safe_remove(input_file)

    results = {}
    if os.path.exists(output_xml):
        results = _parse_nmap_xml(output_xml)
    else:
        # Fallback: try parsing stdout
        results = _parse_nmap_stdout(stdout)

    logger.info(f"Port scan complete: {len(results)} hosts")
    return results

def _parse_nmap_xml(xml_file: str) -> Dict:
    """Parse nmap XML output."""
    results = {}
    try:
        import xml.etree.ElementTree as ET
        tree = ET.parse(xml_file)
        root = tree.getroot()
        for host in root.findall('host'):
            if host.find('status').get('state') != 'up':
                continue
            # Get hostname/IP
            address = ''
            for addr in host.findall('address'):
                if addr.get('addrtype') == 'ipv4':
                    address = addr.get('addr', '')
                    break
            hostname = address
            for hn in host.findall('.//hostname'):
                if hn.get('type') == 'PTR':
                    hostname = hn.get('name', address)
                    break

            ports_info = []
            for port in host.findall('.//port'):
                state = port.find('state')
                if state is None or state.get('state') != 'open':
                    continue
                service = port.find('service')
                port_info = {
                    'port': port.get('portid'),
                    'protocol': port.get('protocol'),
                    'service': service.get('name', '') if service is not None else '',
                    'product': service.get('product', '') if service is not None else '',
                    'version': service.get('version', '') if service is not None else '',
                    'extra_info': service.get('extrainfo', '') if service is not None else '',
                }
                ports_info.append(port_info)

            if ports_info:
                results[hostname] = {
                    'ip': address,
                    'ports': ports_info,
                    'os_guess': _extract_os_guess(host)
                }
    except Exception as e:
        logger.error(f"Nmap XML parse error: {e}")
    return results

def _extract_os_guess(host_element) -> str:
    try:
        os_elem = host_element.find('.//osmatch')
        if os_elem is not None:
            return f"{os_elem.get('name', '')} ({os_elem.get('accuracy', '')}%)"
    except Exception:
        pass
    return 'unknown'

def _parse_nmap_stdout(stdout: str) -> Dict:
    """Fallback parser for nmap text output."""
    results = {}
    current_host = None
    for line in stdout.splitlines():
        if 'Nmap scan report for' in line:
            current_host = line.split()[-1].strip('()')
            results[current_host] = {'ports': []}
        elif current_host and '/tcp' in line and 'open' in line:
            parts = line.split()
            if len(parts) >= 3:
                port_proto = parts[0]
                service = parts[2] if len(parts) > 2 else ''
                results[current_host]['ports'].append({
                    'port': port_proto.split('/')[0],
                    'protocol': port_proto.split('/')[1],
                    'service': service
                })
    return results

def scan_ssl_tls(target: str, workspace_dir: str) -> dict:
    """Run testssl.sh for SSL/TLS analysis."""
    logger.info(f"Running testssl.sh on {target}")
    output_file = os.path.join(workspace_dir, 'testssl_results.json')
    cmd = f"testssl.sh --jsonfile {output_file} --quiet {target}"
    stdout, stderr, rc = run_command(cmd, timeout=600)
    save_raw_output(workspace_dir, 'scan', 'testssl', stdout + stderr, 'txt')

    if os.path.exists(output_file):
        try:
            with open(output_file, 'r') as f:
                data = json.load(f)
            findings = []
            for item in data if isinstance(data, list) else [data]:
                severity = item.get('severity', '').lower()
                if severity in ('critical', 'high', 'medium', 'warn'):
                    findings.append({
                        'id': item.get('id', ''),
                        'finding': item.get('finding', ''),
                        'severity': severity,
                        'cve': item.get('cve', '')
                    })
            if findings:
                logger.warning(f"testssl: {len(findings)} SSL/TLS issues found")
            return {'target': target, 'findings': findings}
        except Exception as e:
            logger.error(f"testssl output parse error: {e}")
    return {'target': target, 'findings': []}
