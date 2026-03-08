"""
Cloud & Infrastructure Testing — Point 32/44 dari perbaikan.
Tests: S3 buckets, Azure Blob, GCS, Redis, Elasticsearch, MongoDB, exposed services.
"""
import re
import logging
import requests
from typing import List, Optional
from core.utils import write_json, run_command, random_user_agent
from core.rate_limiter import get_rate_limiter

logger = logging.getLogger('snooger')

# ─── S3 Bucket Testing ────────────────────────────────────────────────────────

S3_SUFFIXES = [
    '', '-dev', '-staging', '-prod', '-backup', '-data', '-assets',
    '-static', '-media', '-files', '-uploads', '-images', '-logs',
    '-public', '-private', '-internal', '-external', '.com', '-web'
]

def _generate_bucket_names(domain: str) -> List[str]:
    """Generate likely S3 bucket names from domain."""
    base = domain.split('.')[0]
    company = domain.rsplit('.', 1)[0].replace('.', '-')
    names = set()
    for sfx in S3_SUFFIXES:
        names.add(f"{base}{sfx}")
        names.add(f"{company}{sfx}")
    return list(names)[:30]

def check_s3_bucket(bucket_name: str) -> Optional[dict]:
    """Check S3 bucket for public access, listing, and write permissions."""
    rl = get_rate_limiter()
    results = {}
    regions = ['', 'us-east-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1']
    found_url = None

    # Try to find bucket URL
    for region in regions:
        if region:
            url = f"https://{bucket_name}.s3.{region}.amazonaws.com/"
        else:
            url = f"https://{bucket_name}.s3.amazonaws.com/"
        try:
            rl.wait(url)
            resp = requests.get(url, timeout=8, verify=False,
                               headers={'User-Agent': random_user_agent()})
            if resp.status_code in (200, 403):
                found_url = url
                results['status'] = resp.status_code
                results['region'] = region or 'us-east-1'
                break
            elif resp.status_code == 301:
                # May redirect to correct region URL
                new_url = resp.headers.get('Location', '')
                if new_url:
                    resp2 = requests.get(new_url, timeout=8, verify=False)
                    if resp2.status_code in (200, 403):
                        found_url = new_url
                        results['status'] = resp2.status_code
                        break
        except Exception:
            continue

    if not found_url:
        return None

    finding = {
        'type': 's3_bucket_found',
        'bucket': bucket_name,
        'url': found_url,
        'status': results.get('status'),
        'region': results.get('region', 'unknown'),
        'public_read': False,
        'public_list': False,
        'public_write': False,
        'severity': 'info'
    }

    # Check if listing is enabled (200 + XML with ListBucketResult)
    if results.get('status') == 200:
        try:
            rl.wait(found_url)
            resp = requests.get(found_url, timeout=8, verify=False)
            if 'ListBucketResult' in resp.text or '<Key>' in resp.text:
                finding['public_list'] = True
                finding['public_read'] = True
                finding['severity'] = 'high'
                # Count objects
                keys = re.findall(r'<Key>([^<]+)</Key>', resp.text)
                finding['exposed_objects'] = len(keys)
                finding['sample_objects'] = keys[:5]
                logger.warning(f"[S3] Public bucket with listing: {bucket_name} ({len(keys)} objects)")
        except Exception:
            pass

    # Check write access (PUT a test object)
    if finding.get('public_list'):
        try:
            test_key = 'snooger_write_test.txt'
            rl.wait(found_url)
            put_resp = requests.put(
                f"{found_url}{test_key}",
                data=b'snooger write test',
                headers={'Content-Type': 'text/plain'},
                timeout=8, verify=False
            )
            if put_resp.status_code in (200, 204):
                finding['public_write'] = True
                finding['severity'] = 'critical'
                # Cleanup
                requests.delete(f"{found_url}{test_key}", timeout=5, verify=False)
                logger.warning(f"[S3] PUBLIC WRITE on bucket: {bucket_name}")
        except Exception:
            pass

    # 403 = bucket exists but access denied (still useful info)
    if results.get('status') == 403:
        finding['severity'] = 'info'
        finding['note'] = 'Bucket exists but access is restricted'

    return finding

def check_azure_blob(domain: str) -> List[dict]:
    """Check for exposed Azure Blob Storage containers."""
    rl = get_rate_limiter()
    findings = []
    base = domain.split('.')[0]
    company = domain.rsplit('.', 1)[0].replace('.', '')

    storage_names = [base, company, f"{base}storage", f"{company}blob"]
    containers = ['public', 'files', 'images', 'uploads', 'media', 'data',
                  'backup', 'assets', 'static', '$web']

    for storage in storage_names[:3]:
        for container in containers[:5]:
            url = f"https://{storage}.blob.core.windows.net/{container}?restype=container&comp=list"
            try:
                rl.wait(url)
                resp = requests.get(url, timeout=8, verify=False,
                                   headers={'User-Agent': random_user_agent()})
                if resp.status_code == 200 and 'EnumerationResults' in resp.text:
                    blobs = re.findall(r'<Name>([^<]+)</Name>', resp.text)
                    findings.append({
                        'type': 'azure_blob_public',
                        'url': url,
                        'storage_account': storage,
                        'container': container,
                        'severity': 'high',
                        'exposed_blobs': len(blobs),
                        'sample_blobs': blobs[:5],
                        'evidence': f"Azure Blob container public listing enabled ({len(blobs)} blobs)"
                    })
                    logger.warning(f"[AZURE] Public blob container: {storage}/{container}")
            except Exception:
                pass

    return findings

def check_gcs_bucket(domain: str) -> List[dict]:
    """Check for exposed Google Cloud Storage buckets."""
    rl = get_rate_limiter()
    findings = []
    base = domain.split('.')[0]
    company = domain.rsplit('.', 1)[0].replace('.', '-')

    bucket_names = [base, company, f"{base}-assets", f"{company}-backup",
                    f"{base}-prod", f"{base}-staging"]

    for bucket in bucket_names[:5]:
        url = f"https://storage.googleapis.com/{bucket}/"
        try:
            rl.wait(url)
            resp = requests.get(url, timeout=8, verify=False,
                               headers={'User-Agent': random_user_agent()})
            if resp.status_code == 200:
                items = re.findall(r'"name"\s*:\s*"([^"]+)"', resp.text)
                findings.append({
                    'type': 'gcs_bucket_public',
                    'url': url,
                    'bucket': bucket,
                    'severity': 'high',
                    'exposed_objects': len(items),
                    'sample_objects': items[:5],
                    'evidence': f"GCS bucket publicly accessible ({len(items)} objects)"
                })
                logger.warning(f"[GCS] Public bucket: {bucket}")
        except Exception:
            pass

    return findings

# ─── Database Exposure Testing ───────────────────────────────────────────────

def check_redis_exposure(ip: str, port: int = 6379) -> Optional[dict]:
    """Check for unauthenticated Redis access."""
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((ip, port))
        s.send(b"PING\r\n")
        data = s.recv(128)
        s.close()
        if b'+PONG' in data or b'PONG' in data:
            # Try to get config info
            s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s2.settimeout(5)
            s2.connect((ip, port))
            s2.send(b"INFO server\r\n")
            info = s2.recv(2048).decode('utf-8', errors='ignore')
            s2.close()
            version = re.search(r'redis_version:([^\r\n]+)', info)
            return {
                'type': 'redis_no_auth',
                'host': ip,
                'port': port,
                'severity': 'critical',
                'version': version.group(1).strip() if version else 'unknown',
                'evidence': 'Redis PING returned PONG — no authentication required',
                'impact': 'Full Redis access: read all keys, write arbitrary data, potential RCE via config'
            }
    except Exception:
        pass
    return None

def check_elasticsearch_exposure(ip: str, port: int = 9200) -> Optional[dict]:
    """Check for unauthenticated Elasticsearch access."""
    rl = get_rate_limiter()
    url = f"http://{ip}:{port}/"
    try:
        rl.wait(url)
        resp = requests.get(url, timeout=5, verify=False)
        if resp.status_code == 200 and 'cluster_name' in resp.text:
            data = resp.json()
            # Get indices
            indices_resp = requests.get(f"http://{ip}:{port}/_cat/indices?format=json",
                                        timeout=5, verify=False)
            indices = []
            if indices_resp.status_code == 200:
                idx_data = indices_resp.json()
                indices = [i.get('index', '') for i in idx_data[:10]]

            return {
                'type': 'elasticsearch_no_auth',
                'host': ip,
                'port': port,
                'severity': 'critical',
                'version': data.get('version', {}).get('number', 'unknown'),
                'cluster': data.get('cluster_name', 'unknown'),
                'exposed_indices': indices,
                'evidence': f"Elasticsearch accessible without auth (cluster: {data.get('cluster_name', '?')})",
                'impact': 'Full data access — all indices readable/writable'
            }
    except Exception:
        pass
    return None

def check_mongodb_exposure(ip: str, port: int = 27017) -> Optional[dict]:
    """Check for unauthenticated MongoDB access."""
    import socket
    try:
        # MongoDB wire protocol: isMaster command
        isMaster = (
            b'\x41\x00\x00\x00'  # message length
            b'\x01\x00\x00\x00'  # requestID
            b'\x00\x00\x00\x00'  # responseTo
            b'\xd4\x07\x00\x00'  # opCode: OP_QUERY
            b'\x00\x00\x00\x00'  # flags
            b'\x61\x64\x6d\x69\x6e\x2e\x24\x63\x6d\x64\x00'  # admin.$cmd\0
            b'\x00\x00\x00\x00'  # numberToSkip
            b'\x01\x00\x00\x00'  # numberToReturn
            b'\x13\x00\x00\x00'  # document start
            b'\x10\x69\x73\x4d\x61\x73\x74\x65\x72\x00\x01\x00\x00\x00\x00'
        )
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((ip, port))
        s.send(isMaster)
        resp = s.recv(1024)
        s.close()
        if len(resp) > 20 and b'ismaster' in resp.lower():
            return {
                'type': 'mongodb_no_auth',
                'host': ip,
                'port': port,
                'severity': 'critical',
                'evidence': 'MongoDB responding to isMaster without authentication',
                'impact': 'Full database access — read/write all collections'
            }
    except Exception:
        pass
    return None

def run_cloud_scans(domain: str, workspace_dir: str,
                    alive_hosts: List[str] = None) -> dict:
    """Run all cloud and infrastructure exposure checks."""
    logger.info(f"Starting cloud/infrastructure scanning for {domain}")
    results = {
        's3_buckets': [],
        'azure_blobs': [],
        'gcs_buckets': [],
        'database_exposures': []
    }

    # S3 bucket enumeration
    bucket_names = _generate_bucket_names(domain)
    logger.info(f"Testing {len(bucket_names)} S3 bucket names...")
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_s3_bucket, name): name
                   for name in bucket_names}
        for future in futures:
            result = future.result()
            if result:
                results['s3_buckets'].append(result)

    # Azure Blob Storage
    azure_findings = check_azure_blob(domain)
    results['azure_blobs'].extend(azure_findings)

    # Google Cloud Storage
    gcs_findings = check_gcs_bucket(domain)
    results['gcs_buckets'].extend(gcs_findings)

    # Database exposure on alive hosts
    if alive_hosts:
        import ipaddress
        for host in alive_hosts[:20]:
            # Extract IP/hostname
            host_clean = host.replace('https://', '').replace('http://', '').split('/')[0].split(':')[0]
            # Check common database ports
            for checker, port, name in [
                (check_redis_exposure, 6379, 'Redis'),
                (check_elasticsearch_exposure, 9200, 'Elasticsearch'),
                (check_mongodb_exposure, 27017, 'MongoDB'),
            ]:
                result = checker(host_clean, port)
                if result:
                    results['database_exposures'].append(result)
                    logger.warning(f"[DB] {name} exposed: {host_clean}:{port}")

    # Summary
    total = (len(results['s3_buckets']) + len(results['azure_blobs']) +
             len(results['gcs_buckets']) + len(results['database_exposures']))

    if total > 0:
        logger.warning(f"Cloud scan: {total} exposures found")
        write_json(f"{workspace_dir}/cloud_findings.json", results)

    return results
