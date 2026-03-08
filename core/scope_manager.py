"""
Scope Manager — poin 1 dari perbaikan.
Mengelola whitelist/blacklist domain dan memvalidasi setiap request sebelum dikirim.
Mendukung format scope Bugcrowd (JSON) dan HackerOne.
"""
import json
import re
import ipaddress
import logging
from urllib.parse import urlparse
from fnmatch import fnmatch
from typing import List, Optional

logger = logging.getLogger('snooger')


class ScopeManager:
    """
    Validates targets against program scope before any request is made.
    Prevents accidental out-of-scope testing that could cause account bans.
    """

    def __init__(self):
        self.include_patterns: List[str] = []   # Wildcards like *.example.com
        self.include_ranges: List[ipaddress.IPv4Network] = []
        self.exclude_patterns: List[str] = []
        self.exclude_ranges: List[ipaddress.IPv4Network] = []
        self.strict: bool = True
        self._loaded: bool = False

    # ─── Loaders ─────────────────────────────────────────────────────────────

    def load_from_config(self, config: dict):
        """Load scope from config.yaml scope section."""
        scope_cfg = config.get('scope', {})
        self.strict = scope_cfg.get('strict', True)

        for pattern in scope_cfg.get('include', []):
            self._add_include(pattern)
        for pattern in scope_cfg.get('exclude', []):
            self._add_exclude(pattern)

        self._loaded = True

    def load_from_file(self, filepath: str):
        """
        Load scope from a file.
        Supports:
          - Bugcrowd scope JSON (array of {target, type, in_scope})
          - HackerOne scope JSON ({in_scope: [], out_of_scope: []})
          - Plain text (one pattern per line, prefix '!' for exclusion)
        """
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read().strip()
        except OSError as e:
            logger.error(f"[Scope] Cannot read scope file: {e}")
            return

        # Try JSON first
        try:
            data = json.loads(content)
            if isinstance(data, list):
                # Bugcrowd format
                self._parse_bugcrowd_scope(data)
            elif isinstance(data, dict):
                # HackerOne format
                self._parse_hackerone_scope(data)
            logger.info("[Scope] Loaded scope from JSON file")
            self._loaded = True
            return
        except json.JSONDecodeError:
            pass

        # Plain text format
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if line.startswith('!'):
                self._add_exclude(line[1:].strip())
            else:
                self._add_include(line)
        self._loaded = True
        logger.info(f"[Scope] Loaded {len(self.include_patterns)} include / "
                    f"{len(self.exclude_patterns)} exclude patterns")

    def add_target(self, target: str):
        """Manually add a single target to scope."""
        self._add_include(target)
        self._loaded = True

    # ─── Parsers ─────────────────────────────────────────────────────────────

    def _parse_bugcrowd_scope(self, data: list):
        """Parse Bugcrowd scope JSON array."""
        for item in data:
            if not isinstance(item, dict):
                continue
            target = item.get('target', item.get('domain', ''))
            in_scope = item.get('in_scope', True)
            if not target:
                continue
            if in_scope:
                self._add_include(target)
            else:
                self._add_exclude(target)

    def _parse_hackerone_scope(self, data: dict):
        """Parse HackerOne scope JSON dict."""
        for item in data.get('in_scope', []):
            target = item.get('asset_identifier', item.get('target', ''))
            if target:
                self._add_include(target)
        for item in data.get('out_of_scope', []):
            target = item.get('asset_identifier', item.get('target', ''))
            if target:
                self._add_exclude(target)

    # ─── Pattern Registration ─────────────────────────────────────────────────

    def _add_include(self, pattern: str):
        pattern = pattern.strip().lower()
        if not pattern:
            return
        # Strip URL scheme if present
        pattern = re.sub(r'^https?://', '', pattern).rstrip('/')
        try:
            net = ipaddress.ip_network(pattern, strict=False)
            self.include_ranges.append(net)
        except ValueError:
            self.include_patterns.append(pattern)

    def _add_exclude(self, pattern: str):
        pattern = pattern.strip().lower()
        if not pattern:
            return
        pattern = re.sub(r'^https?://', '', pattern).rstrip('/')
        try:
            net = ipaddress.ip_network(pattern, strict=False)
            self.exclude_ranges.append(net)
        except ValueError:
            self.exclude_patterns.append(pattern)

    # ─── Validation ──────────────────────────────────────────────────────────

    def is_in_scope(self, target: str) -> bool:
        """
        Returns True if target is in scope, False otherwise.
        If no scope loaded and strict=False, returns True (allow all).
        If strict=True and no scope loaded, still requires explicit inclusion.
        """
        if not target:
            return False

        # Extract hostname from URL
        parsed = urlparse(target if '://' in target else f'http://{target}')
        host = parsed.netloc.split(':')[0].lower() or parsed.path.lower()

        # Always check exclusions first
        if self._is_excluded(host):
            logger.debug(f"[Scope] EXCLUDED: {host}")
            return False

        # If no includes defined and not strict, allow
        if not self.include_patterns and not self.include_ranges:
            return not self.strict

        # Check IP ranges
        try:
            ip = ipaddress.ip_address(host)
            for net in self.include_ranges:
                if ip in net:
                    return True
            return False
        except ValueError:
            pass

        # Check domain patterns
        return self._is_included_domain(host)

    def _is_excluded(self, host: str) -> bool:
        """Check if host matches any exclusion pattern."""
        try:
            ip = ipaddress.ip_address(host)
            for net in self.exclude_ranges:
                if ip in net:
                    return True
            return False
        except ValueError:
            pass
        for pattern in self.exclude_patterns:
            if fnmatch(host, pattern) or fnmatch(host, f'*.{pattern}'):
                return True
        return False

    def _is_included_domain(self, host: str) -> bool:
        """Check if host matches any inclusion pattern."""
        for pattern in self.include_patterns:
            # Exact match
            if host == pattern:
                return True
            # Wildcard match: *.example.com matches sub.example.com
            if pattern.startswith('*.'):
                base = pattern[2:]
                if host == base or host.endswith(f'.{base}'):
                    return True
            # fnmatch as fallback
            if fnmatch(host, pattern):
                return True
        return False

    def filter_in_scope(self, targets: list) -> list:
        """Filter a list of targets, keeping only in-scope ones."""
        if not self._loaded:
            return targets
        result = []
        for t in targets:
            if self.is_in_scope(t):
                result.append(t)
            else:
                logger.debug(f"[Scope] Out-of-scope filtered: {t}")
        removed = len(targets) - len(result)
        if removed:
            logger.warning(f"[Scope] Filtered {removed} out-of-scope targets")
        return result

    def assert_in_scope(self, target: str):
        """Raise ScopeViolationError if target is out of scope."""
        if self._loaded and not self.is_in_scope(target):
            raise ScopeViolationError(f"Target out of scope: {target}")

    def summary(self) -> str:
        total_inc = len(self.include_patterns) + len(self.include_ranges)
        total_exc = len(self.exclude_patterns) + len(self.exclude_ranges)
        return (f"Scope: {total_inc} include, {total_exc} exclude patterns "
                f"(strict={self.strict}, loaded={self._loaded})")


class ScopeViolationError(Exception):
    """Raised when a request would go out of scope."""
    pass


# Global singleton
_scope_manager: Optional[ScopeManager] = None


def get_scope_manager() -> ScopeManager:
    global _scope_manager
    if _scope_manager is None:
        _scope_manager = ScopeManager()
    return _scope_manager


def init_scope(config: dict, scope_file: Optional[str] = None, extra_targets: List[str] = None):
    """Initialize the global scope manager."""
    sm = get_scope_manager()
    sm.load_from_config(config)
    if scope_file:
        sm.load_from_file(scope_file)
    if extra_targets:
        for t in extra_targets:
            sm.add_target(t)
    logger.info(f"[Scope] {sm.summary()}")
    return sm
