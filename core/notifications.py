"""
Notifications — real-time alerts via Telegram, Discord, and webhooks.
Subscribes to event bus for automatic notification on critical findings.
"""
import logging
import json
import requests
from typing import Optional, Dict, Any
from core.event_bus import get_event_bus, Event

logger = logging.getLogger('snooger')


class TelegramNotifier:
    """Send alerts via Telegram Bot API (free)."""

    API_BASE = "https://api.telegram.org/bot{token}"

    def __init__(self, bot_token: str, chat_id: str, min_severity: str = 'high'):
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.min_severity = min_severity
        self._severity_rank = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        self.enabled = bool(bot_token and chat_id)

    def send(self, message: str) -> bool:
        if not self.enabled:
            return False
        url = f"{self.API_BASE.format(token=self.bot_token)}/sendMessage"
        try:
            resp = requests.post(url, json={
                'chat_id': self.chat_id,
                'text': message,
                'parse_mode': 'Markdown',
                'disable_web_page_preview': True,
            }, timeout=10)
            if resp.status_code == 200:
                return True
            logger.debug(f"Telegram API error: {resp.status_code}")
            return False
        except Exception as e:
            logger.debug(f"Telegram send failed: {e}")
            return False

    def format_finding(self, event: Event) -> Optional[str]:
        data = event.data
        severity = data.get('severity', 'info')
        if self._severity_rank.get(severity, 0) < self._severity_rank.get(self.min_severity, 3):
            return None

        emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}.get(severity, '⚪')
        vuln_type = data.get('type', 'Unknown')
        url = data.get('url', data.get('matched-at', 'N/A'))
        evidence = str(data.get('evidence', ''))[:200]

        return (
            f"{emoji} *Snooger Alert*\n"
            f"*Severity:* {severity.upper()}\n"
            f"*Type:* {vuln_type}\n"
            f"*URL:* `{url}`\n"
            f"*Evidence:* {evidence}"
        )


class DiscordNotifier:
    """Send alerts via Discord Webhook (free)."""

    def __init__(self, webhook_url: str, min_severity: str = 'high'):
        self.webhook_url = webhook_url
        self.min_severity = min_severity
        self._severity_rank = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        self.enabled = bool(webhook_url)

    def send(self, message: str, color: int = 0xFF0000) -> bool:
        if not self.enabled:
            return False
        try:
            resp = requests.post(self.webhook_url, json={
                'embeds': [{
                    'title': '🔒 Snooger Alert',
                    'description': message,
                    'color': color,
                }]
            }, timeout=10)
            return resp.status_code in (200, 204)
        except Exception as e:
            logger.debug(f"Discord send failed: {e}")
            return False

    def format_finding(self, event: Event) -> Optional[str]:
        data = event.data
        severity = data.get('severity', 'info')
        if self._severity_rank.get(severity, 0) < self._severity_rank.get(self.min_severity, 3):
            return None

        vuln_type = data.get('type', 'Unknown')
        url = data.get('url', data.get('matched-at', 'N/A'))
        evidence = str(data.get('evidence', ''))[:300]

        return (
            f"**Severity:** {severity.upper()}\n"
            f"**Type:** {vuln_type}\n"
            f"**URL:** {url}\n"
            f"**Evidence:** {evidence}"
        )


class WebhookNotifier:
    """Send alerts to any generic webhook endpoint."""

    def __init__(self, url: str, min_severity: str = 'critical'):
        self.url = url
        self.min_severity = min_severity
        self._severity_rank = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        self.enabled = bool(url)

    def send(self, data: dict) -> bool:
        if not self.enabled:
            return False
        try:
            resp = requests.post(self.url, json=data, timeout=10,
                                 headers={'Content-Type': 'application/json'})
            return resp.status_code in (200, 201, 204)
        except Exception as e:
            logger.debug(f"Webhook send failed: {e}")
            return False


class NotificationManager:
    """Manages all notification channels and routes events."""

    def __init__(self, config: dict):
        self.notifiers = []
        notif_cfg = config.get('notifications', {})

        # Telegram
        tg = notif_cfg.get('telegram', {})
        if tg.get('enabled') and tg.get('bot_token') and tg.get('chat_id'):
            self.notifiers.append(('telegram', TelegramNotifier(
                tg['bot_token'], tg['chat_id'], tg.get('min_severity', 'high')
            )))

        # Discord
        dc = notif_cfg.get('discord', {})
        if dc.get('enabled') and dc.get('webhook_url'):
            self.notifiers.append(('discord', DiscordNotifier(
                dc['webhook_url'], dc.get('min_severity', 'high')
            )))

        # Webhook
        wh = notif_cfg.get('webhook', {})
        if wh.get('enabled') and wh.get('url'):
            self.notifiers.append(('webhook', WebhookNotifier(
                wh['url'], wh.get('min_severity', 'critical')
            )))

        if self.notifiers:
            logger.info(f"Notifications enabled: {[n[0] for n in self.notifiers]}")

    def on_finding(self, event: Event) -> None:
        """Event handler for findings — routes to all configured notifiers."""
        for name, notifier in self.notifiers:
            try:
                if isinstance(notifier, (TelegramNotifier, DiscordNotifier)):
                    message = notifier.format_finding(event)
                    if message:
                        notifier.send(message)
                elif isinstance(notifier, WebhookNotifier):
                    data = event.data
                    severity = data.get('severity', 'info')
                    rank = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
                    if rank.get(severity, 0) >= rank.get(notifier.min_severity, 4):
                        notifier.send(event.to_dict())
            except Exception as e:
                logger.debug(f"Notification [{name}] error: {e}")

    def on_scan_complete(self, event: Event) -> None:
        """Send scan completion summary."""
        data = event.data
        summary = data.get('summary', {})
        sev = summary.get('by_severity', {})
        target = data.get('target', 'Unknown')

        message = (
            f"✅ *Scan Complete: {target}*\n"
            f"Critical: {sev.get('critical', 0)} | "
            f"High: {sev.get('high', 0)} | "
            f"Medium: {sev.get('medium', 0)} | "
            f"Low: {sev.get('low', 0)}"
        )
        for name, notifier in self.notifiers:
            if isinstance(notifier, TelegramNotifier):
                notifier.send(message)
            elif isinstance(notifier, DiscordNotifier):
                notifier.send(message.replace('*', '**'), color=0x00FF00)

    def register_with_event_bus(self) -> None:
        """Subscribe to relevant events on the global event bus."""
        bus = get_event_bus()
        bus.subscribe('finding_discovered', self.on_finding)
        bus.subscribe('critical_alert', self.on_finding)
        bus.subscribe('scan_completed', self.on_scan_complete)
        bus.subscribe('takeover_found', self.on_finding)
        bus.subscribe('secret_found', self.on_finding)


def init_notifications(config: dict) -> NotificationManager:
    """Initialize and register notifications with the event bus."""
    manager = NotificationManager(config)
    if manager.notifiers:
        manager.register_with_event_bus()
    return manager
