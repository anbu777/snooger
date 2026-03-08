"""
Scope management with Bugcrowd/HackerOne format support.
Ensures no out-of-scope requests are made.
"""
import json
import re
import logging
import fnmatch
from urllib.parse import urlparse
from typing import List, Optional

logger = logging.getLogger('snooger')

class ScopeManager:
    def __init__(self):
        self.in_scope: List[str] = []
        self.out_of_scope: List[str] = []
        self._compiled_in: List = []
        self._compiled_out: List = []

    def load_from_file(self, scope_file: str) -> None:
        """Load scope from file. Supports:
        - Plain text: one domain/CIDR per line
        - Bugcrowd JSON format
        - HackerOne JSON format
        """
        try:
            with open(scope_file, 'r', encoding='utf-8') as f:
                content = f.read().strip()
        except OSError as e:
            logger.error(f"Cannot read scope file {scope_file}: {e}")
            return

        try:
            data = json.loads(content)
            self._parse_platform_scope(data)
        except json.JSONDecodeError:
            # Plain text format
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if line.startswith('!') or line.lower().startswith('out:'):
                    target = line.lstrip('!').replace('out:', '').strip()
                    self.out_of_scope.append(target)
                else:
                    self.in_scope.append(line)
        self._compile_patterns()
        logger.info(f"Scope loaded: {len(self.in_scope)} in-scope, {len(self.out_of_scope)} out-of-scope")

    def _parse_platform_scope(self, data: dict) -> None:
        """Parse Bugcrowd or HackerOne JSON scope format."""
        # HackerOne format
        if 'relationships' in data:
            for item in data.get('relationships', {}).get('structured_scopes', {}).get('data', []):
                attrs = item.get('attributes', {})
                asset = attrs.get('asset_identifier', '')
                eligible = attrs.get('eligible_for_submission', True)
                if eligible:
                    self.in_scope.append(asset)
                else:
                    self.out_of_scope.append(asset)
        # Bugcrowd format
        elif 'targets' in data:
            for target_group in data.get('targets', {}).get('in_scope', []):
                self.in_scope.append(target_group.get('target', ''))
            for target_group in data.get('targets', {}).get('out_of_scope', []):
                self.out_of_scope.append(target_group.get('target', ''))
        # Generic list format
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    t = item.get('target', item.get('domain', item.get('url', '')))
                    if item.get('in_scope', True):
                        self.in_scope.append(t)
                    else:
                        self.out_of_scope.append(t)
                elif isinstance(item, str):
                    self.in_scope.append(item)

    def add_domain(self, domain: str) -> None:
        self.in_scope.append(domain)
        self._compile_patterns()

    def add_out_of_scope(self, pattern: str) -> None:
        self.out_of_scope.append(pattern)
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        self._compiled_in = [self._to_pattern(p) for p in self.in_scope if p]
        self._compiled_out = [self._to_pattern(p) for p in self.out_of_scope if p]

    def _to_pattern(self, pattern: str) -> str:
        """Normalize pattern: strip protocol, handle wildcards."""
        pattern = pattern.strip()
        pattern = re.sub(r'^https?://', '', pattern)
        pattern = pattern.split('/')[0]  # take only the host part
        return pattern.lower()

    def _extract_host(self, url_or_domain: str) -> str:
        """Extract hostname from URL or domain string."""
        url_or_domain = url_or_domain.strip()
        if '://' in url_or_domain:
            return urlparse(url_or_domain).hostname or url_or_domain
        return url_or_domain.split('/')[0].split(':')[0].lower()

    def is_in_scope(self, target: str) -> bool:
        """
        Check if a target (URL or domain) is in scope.
        Returns True if in-scope patterns match AND out-of-scope patterns don't.
        """
        host = self._extract_host(target)
        if not host:
            return False

        # Check out-of-scope first
        for pat in self._compiled_out:
            if fnmatch.fnmatch(host, pat):
                logger.debug(f"Out-of-scope: {host} matches {pat}")
                return False

        # If no in_scope defined, allow everything not out-of-scope
        if not self._compiled_in:
            return True

        for pat in self._compiled_in:
            if fnmatch.fnmatch(host, pat):
                return True
            # Subdomains of an in-scope domain are also in scope
            if host.endswith('.' + pat):
                return True
            # Check parent domain: *.example.com should match sub.example.com
            if pat.startswith('*.'):
                base = pat[2:]
                if host == base or host.endswith('.' + base):
                    return True

        logger.debug(f"Not in scope: {host}")
        return False

    def filter_targets(self, targets: List[str]) -> List[str]:
        """Filter a list of targets to only in-scope ones."""
        filtered = [t for t in targets if self.is_in_scope(t)]
        removed = len(targets) - len(filtered)
        if removed > 0:
            logger.warning(f"Scope filter removed {removed} out-of-scope targets")
        return filtered

    def is_empty(self) -> bool:
        return len(self.in_scope) == 0
