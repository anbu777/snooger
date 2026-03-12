"""
Event Bus — publish/subscribe system for real-time framework events.
Enables decoupled communication between scanner modules, notifications, and state manager.
"""
import asyncio
import logging
import threading
from collections import defaultdict
from typing import Callable, Any, Dict, List, Optional
from datetime import datetime

logger = logging.getLogger('snooger')


class Event:
    """Represents a framework event."""
    __slots__ = ('name', 'data', 'timestamp', 'source')

    def __init__(self, name: str, data = None, source: str = ''):
        self.name = name
        self.data = data or {}
        self.timestamp = datetime.utcnow().isoformat()
        self.source = source

    def __repr__(self):
        return f"Event({self.name}, source={self.source})"

    def to_dict(self) -> dict:
        return {
            'event': self.name,
            'data': self.data,
            'timestamp': self.timestamp,
            'source': self.source,
        }


# Standard event names
EVENTS = {
    'scan_started': 'Scan has begun',
    'scan_completed': 'Scan finished',
    'phase_started': 'A scan phase started',
    'phase_completed': 'A scan phase completed',
    'phase_failed': 'A scan phase failed',
    'finding_discovered': 'New vulnerability finding',
    'critical_alert': 'Critical severity finding',
    'subdomain_found': 'New subdomain discovered',
    'takeover_found': 'Subdomain takeover detected',
    'secret_found': 'Secret/credential found in JS',
    'chain_detected': 'Exploit chain opportunity detected',
    'rate_limited': 'Target rate-limited our requests',
    'auth_required': 'Authentication needed',
    'tool_missing': 'Required external tool not found',
}


class EventBus:
    """
    Thread-safe and async-compatible event bus.
    Supports both sync and async subscribers.
    """

    def __init__(self):
        self._sync_subscribers: Dict[str, List[Callable]] = defaultdict(list)
        self._async_subscribers: Dict[str, List[Callable]] = defaultdict(list)
        self._lock = threading.Lock()
        self._event_log: List[Event] = []
        self._max_log_size = 5000

    def subscribe(self, event_name: str, callback: Callable) -> None:
        """Subscribe a sync callback to an event."""
        with self._lock:
            if asyncio.iscoroutinefunction(callback):
                self._async_subscribers[event_name].append(callback)
            else:
                self._sync_subscribers[event_name].append(callback)

    def subscribe_all(self, callback: Callable) -> None:
        """Subscribe to ALL events (wildcard)."""
        self.subscribe('*', callback)

    def unsubscribe(self, event_name: str, callback: Callable) -> None:
        """Remove a subscriber."""
        with self._lock:
            if callback in self._sync_subscribers.get(event_name, []):
                self._sync_subscribers[event_name].remove(callback)
            if callback in self._async_subscribers.get(event_name, []):
                self._async_subscribers[event_name].remove(callback)

    def emit(self, event_name: str, data = None,
             source: str = '') -> Event:
        """Emit an event synchronously. Calls all sync subscribers."""
        event = Event(event_name, data, source)
        self._log_event(event)

        with self._lock:
            subscribers = list(self._sync_subscribers.get(event_name, []))
            wildcard = list(self._sync_subscribers.get('*', []))

        for callback in subscribers + wildcard:
            try:
                callback(event)
            except Exception as e:
                logger.error(f"Event subscriber error [{event_name}]: {e}")

        return event

    async def emit_async(self, event_name: str, data = None,
                         source: str = '') -> Event:
        """Emit an event asynchronously. Calls both sync and async subscribers."""
        event = Event(event_name, data, source)
        self._log_event(event)

        with self._lock:
            sync_subs = list(self._sync_subscribers.get(event_name, []))
            async_subs = list(self._async_subscribers.get(event_name, []))
            sync_wild = list(self._sync_subscribers.get('*', []))
            async_wild = list(self._async_subscribers.get('*', []))

        for callback in sync_subs + sync_wild:
            try:
                callback(event)
            except Exception as e:
                logger.error(f"Sync subscriber error [{event_name}]: {e}")

        tasks = []
        for callback in async_subs + async_wild:
            tasks.append(asyncio.ensure_future(callback(event)))
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, Exception):
                    logger.error(f"Async subscriber error [{event_name}]: {r}")

        return event

    def _log_event(self, event: Event) -> None:
        """Keep an in-memory event log for debugging."""
        self._event_log.append(event)
        if len(self._event_log) > self._max_log_size:
            self._event_log = self._event_log[-self._max_log_size:]

    def get_event_log(self, event_name: Optional[str] = None,
                      last_n: int = 100) -> List[dict]:
        """Retrieve recent events from the log."""
        events = self._event_log
        if event_name:
            events = [e for e in events if e.name == event_name]
        return [e.to_dict() for e in events[-last_n:]]

    def clear(self) -> None:
        """Clear all subscribers and logs."""
        with self._lock:
            self._sync_subscribers.clear()
            self._async_subscribers.clear()
            self._event_log.clear()


# ─── Global singleton ────────────────────────────────────────
_bus: Optional[EventBus] = None


def get_event_bus() -> EventBus:
    global _bus
    if _bus is None:
        _bus = EventBus()
    return _bus


def emit(event_name: str, data = None, source: str = '') -> Event:
    """Shortcut to emit an event on the global bus."""
    return get_event_bus().emit(event_name, data, source)


async def emit_async(event_name: str, data = None,
                     source: str = '') -> Event:
    """Shortcut to async emit on the global bus."""
    return await get_event_bus().emit_async(event_name, data, source)
