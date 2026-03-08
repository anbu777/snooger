"""
Continuous/Scheduled Scanning — Point 42 dari perbaikan.
Monitor mode: re-scan at intervals, delta reporting, alert on new findings.
"""
import os
import json
import time
import logging
import smtplib
import hashlib
from datetime import datetime
from email.mime.text import MIMEText
from typing import List, Optional, Callable
from core.utils import write_json, load_json_file

logger = logging.getLogger('snooger')


def _fingerprint_finding(finding: dict) -> str:
    """Create a unique fingerprint for deduplication."""
    key = json.dumps({
        'type': finding.get('type', finding.get('info', {}).get('name', '')),
        'url': finding.get('url', finding.get('matched-at', finding.get('host', ''))),
    }, sort_keys=True)
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def compute_delta(old_findings: List[dict], new_findings: List[dict]) -> dict:
    """
    Compare two sets of findings and return new/resolved/persisting.
    """
    old_fps = {_fingerprint_finding(f): f for f in old_findings}
    new_fps = {_fingerprint_finding(f): f for f in new_findings}

    new = [f for fp, f in new_fps.items() if fp not in old_fps]
    resolved = [f for fp, f in old_fps.items() if fp not in new_fps]
    persisting = [f for fp, f in new_fps.items() if fp in old_fps]

    return {
        'new': new,
        'resolved': resolved,
        'persisting': persisting,
        'new_count': len(new),
        'resolved_count': len(resolved),
        'total_current': len(new_findings),
    }


def send_alert_email(findings: List[dict], target: str,
                      smtp_config: dict) -> bool:
    """Send email alert for new findings."""
    if not smtp_config.get('host') or not smtp_config.get('to'):
        return False

    critical_high = [f for f in findings
                     if f.get('severity', f.get('info', {}).get('severity', ''))
                     in ('critical', 'high')]

    if not critical_high:
        return False

    lines = [
        f"Snooger Monitor Alert — {target}",
        f"Time: {datetime.utcnow().isoformat()}",
        f"New critical/high findings: {len(critical_high)}",
        "",
    ]
    for f in critical_high[:10]:
        name = f.get('type', f.get('info', {}).get('name', 'Unknown'))
        url = f.get('url', f.get('matched-at', f.get('host', 'unknown')))
        sev = f.get('severity', f.get('info', {}).get('severity', 'unknown'))
        lines.append(f"  [{sev.upper()}] {name} @ {url}")

    body = '\n'.join(lines)
    try:
        msg = MIMEText(body)
        msg['Subject'] = f"[Snooger] {len(critical_high)} new findings on {target}"
        msg['From'] = smtp_config.get('from', 'snooger@localhost')
        msg['To'] = smtp_config['to']

        with smtplib.SMTP(smtp_config['host'],
                           int(smtp_config.get('port', 587))) as s:
            if smtp_config.get('tls', True):
                s.starttls()
            if smtp_config.get('user') and smtp_config.get('password'):
                s.login(smtp_config['user'], smtp_config['password'])
            s.sendmail(msg['From'], [msg['To']], msg.as_string())

        logger.info(f"Alert email sent: {len(critical_high)} new findings")
        return True
    except Exception as e:
        logger.error(f"Failed to send alert email: {e}")
        return False


def send_telegram_alert(findings: List[dict], target: str,
                         telegram_config: dict) -> bool:
    """Send Telegram alert for new findings."""
    import requests as req
    token = telegram_config.get('bot_token', '')
    chat_id = telegram_config.get('chat_id', '')
    if not token or not chat_id:
        return False

    critical_high = [f for f in findings
                     if f.get('severity', f.get('info', {}).get('severity', ''))
                     in ('critical', 'high')]
    if not critical_high:
        return False

    lines = [
        f"🚨 *Snooger Monitor Alert*",
        f"Target: `{target}`",
        f"New findings: *{len(critical_high)}* critical/high",
        "",
    ]
    for f in critical_high[:5]:
        name = f.get('type', f.get('info', {}).get('name', 'Unknown'))
        url = f.get('url', f.get('matched-at', ''))[:60]
        sev = f.get('severity', f.get('info', {}).get('severity', '?')).upper()
        lines.append(f"• [{sev}] {name} @ `{url}`")

    text = '\n'.join(lines)
    try:
        resp = req.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={'chat_id': chat_id, 'text': text, 'parse_mode': 'Markdown'},
            timeout=10
        )
        if resp.status_code == 200:
            logger.info("Telegram alert sent")
            return True
    except Exception as e:
        logger.error(f"Telegram alert error: {e}")
    return False


class MonitorMode:
    """
    Continuous scanning monitor.
    Runs scans at a configured interval and alerts on new findings.
    """

    def __init__(self, target: str, workspace_dir: str, config: dict,
                  scan_fn: Callable):
        self.target = target
        self.workspace_dir = workspace_dir
        self.config = config
        self.scan_fn = scan_fn
        self.interval_minutes = config.get('monitor', {}).get('interval_minutes', 60)
        self.max_rounds = config.get('monitor', {}).get('max_rounds', 0)  # 0=infinite
        self.alert_config = config.get('notifications', {})
        self.history_file = os.path.join(workspace_dir, 'monitor_history.json')
        self._round = 0

    def _load_previous_findings(self) -> List[dict]:
        data = load_json_file(self.history_file)
        if data:
            return data.get('last_findings', [])
        return []

    def _save_history(self, findings: List[dict], delta: dict):
        history = load_json_file(self.history_file) or {'rounds': []}
        history['last_findings'] = findings
        history['rounds'].append({
            'round': self._round,
            'timestamp': datetime.utcnow().isoformat(),
            'total': len(findings),
            'new': delta.get('new_count', 0),
            'resolved': delta.get('resolved_count', 0),
        })
        # Keep last 100 rounds
        history['rounds'] = history['rounds'][-100:]
        write_json(self.history_file, history)

    def run(self):
        """Start the monitoring loop."""
        logger.info(f"Monitor mode started: {self.target} "
                   f"(interval={self.interval_minutes}min)")

        while True:
            self._round += 1
            ts = datetime.utcnow().isoformat()
            logger.info(f"[Monitor] Round {self._round} started at {ts}")
            print(f"\n[Monitor] Round {self._round} — {ts}")

            # Run the scan
            try:
                new_findings = self.scan_fn() or []
            except Exception as e:
                logger.error(f"Monitor scan error: {e}")
                new_findings = []

            # Compare with previous
            prev_findings = self._load_previous_findings()
            delta = compute_delta(prev_findings, new_findings)
            self._save_history(new_findings, delta)

            # Report delta
            print(f"  New: {delta['new_count']} | "
                  f"Resolved: {delta['resolved_count']} | "
                  f"Total: {delta['total_current']}")

            # Save delta report
            if delta['new']:
                delta_path = os.path.join(
                    self.workspace_dir,
                    f"delta_round_{self._round:04d}_{datetime.utcnow().strftime('%Y%m%d_%H%M')}.json"
                )
                write_json(delta_path, delta)
                logger.warning(f"Delta report saved: {delta_path}")

                # Send alerts
                smtp_config = self.alert_config.get('email', {})
                if smtp_config:
                    send_alert_email(delta['new'], self.target, smtp_config)

                telegram_config = self.alert_config.get('telegram', {})
                if telegram_config:
                    send_telegram_alert(delta['new'], self.target, telegram_config)

            # Check if max rounds reached
            if self.max_rounds > 0 and self._round >= self.max_rounds:
                logger.info(f"Monitor complete: {self._round} rounds finished")
                break

            # Wait for next interval
            next_run = datetime.utcfromtimestamp(
                time.time() + self.interval_minutes * 60
            ).strftime('%H:%M:%S UTC')
            print(f"  Next scan at {next_run} (in {self.interval_minutes} minutes)")
            logger.info(f"Monitor sleeping {self.interval_minutes} minutes")
            time.sleep(self.interval_minutes * 60)
