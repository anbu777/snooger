"""
Plugin Loader — extensible scanner architecture.
Discovers and loads plugins from the plugins/ directory.
Each plugin must expose a register(framework) function.
"""
import os
import sys
import importlib
import importlib.util
import logging
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional

logger = logging.getLogger('snooger')


class BaseScanner(ABC):
    """Base class for all scanner plugins."""

    name: str = "unnamed"
    category: str = "custom"  # recon, vuln, exploit, post, report
    description: str = ""
    author: str = ""
    version: str = "1.0"
    priority: int = 50  # 0=first, 100=last

    @abstractmethod
    def run(self, target: str, context: 'ScanContext') -> List[dict]:
        """
        Execute the scanner.
        Args:
            target: The target URL or domain
            context: ScanContext with access to auth, config, workspace, etc.
        Returns:
            List of finding dicts
        """
        pass

    def should_run(self, context: 'ScanContext') -> bool:
        """Override to conditionally skip this scanner."""
        return True

    def get_info(self) -> dict:
        return {
            'name': self.name,
            'category': self.category,
            'description': self.description,
            'author': self.author,
            'version': self.version,
            'priority': self.priority,
        }


class ScanContext:
    """Shared context passed to all scanners/plugins."""

    def __init__(self, target: str, workspace_dir: str, config: dict,
                 auth=None, scope=None, state=None, ai=None, event_bus=None):
        self.target = target
        self.workspace_dir = workspace_dir
        self.config = config
        self.auth = auth
        self.scope = scope
        self.state = state
        self.ai = ai
        self.event_bus = event_bus
        self.shared_data: Dict[str, Any] = {}
        self.findings: List[dict] = []

    def add_finding(self, finding: dict) -> None:
        self.findings.append(finding)
        if self.event_bus:
            severity = finding.get('severity', 'info')
            event_name = 'critical_alert' if severity == 'critical' else 'finding_discovered'
            self.event_bus.emit(event_name, finding, source=finding.get('type', 'unknown'))

    def get_shared(self, key: str, default=None):
        return self.shared_data.get(key, default)

    def set_shared(self, key: str, value: Any):
        self.shared_data[key] = value


class PluginManager:
    """Discovers, loads, and manages scanner plugins."""

    def __init__(self, plugin_dirs: Optional[List[str]] = None):
        self.plugin_dirs = plugin_dirs or []
        self.scanners: Dict[str, BaseScanner] = {}
        self._loaded = False

    def discover(self) -> int:
        """Discover plugin files from configured directories."""
        count = 0
        for plugin_dir in self.plugin_dirs:
            if not os.path.isdir(plugin_dir):
                os.makedirs(plugin_dir, exist_ok=True)
                self._create_example_plugin(plugin_dir)
                continue

            for filename in os.listdir(plugin_dir):
                if filename.endswith('.py') and not filename.startswith('_'):
                    filepath = os.path.join(plugin_dir, filename)
                    try:
                        self._load_plugin_file(filepath)
                        count += 1
                    except Exception as e:
                        logger.error(f"Failed to load plugin {filename}: {e}")

        self._loaded = True
        logger.info(f"Loaded {count} plugins, {len(self.scanners)} scanners registered")
        return count

    def _load_plugin_file(self, filepath: str) -> None:
        """Load a single plugin file."""
        module_name = os.path.splitext(os.path.basename(filepath))[0]
        spec = importlib.util.spec_from_file_location(f"snooger_plugin_{module_name}", filepath)
        if spec is None or spec.loader is None:
            return

        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)

        # Look for register() function
        if hasattr(module, 'register'):
            module.register(self)
        # Also auto-discover BaseScanner subclasses
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if (isinstance(attr, type) and issubclass(attr, BaseScanner)
                    and attr is not BaseScanner and attr.name != 'unnamed'):
                self.register_scanner(attr())

    def register_scanner(self, scanner: BaseScanner) -> None:
        """Register a scanner instance."""
        if scanner.name in self.scanners:
            logger.warning(f"Plugin '{scanner.name}' already registered, overwriting")
        self.scanners[scanner.name] = scanner
        logger.debug(f"Registered plugin: {scanner.name} [{scanner.category}]")

    def get_scanners(self, category: Optional[str] = None) -> List[BaseScanner]:
        """Get scanners, optionally filtered by category, sorted by priority."""
        scanners = list(self.scanners.values())
        if category:
            scanners = [s for s in scanners if s.category == category]
        return sorted(scanners, key=lambda s: s.priority)

    def run_scanners(self, category: str, target: str,
                     context: ScanContext) -> List[dict]:
        """Run all scanners in a category and collect findings."""
        scanners = self.get_scanners(category)
        all_findings = []

        for scanner in scanners:
            if not scanner.should_run(context):
                logger.debug(f"Skipping plugin {scanner.name} (should_run=False)")
                continue
            try:
                logger.info(f"Running plugin: {scanner.name}")
                findings = scanner.run(target, context)
                if findings:
                    all_findings.extend(findings)
                    logger.info(f"Plugin {scanner.name}: {len(findings)} findings")
            except Exception as e:
                logger.error(f"Plugin {scanner.name} error: {e}")

        return all_findings

    def list_plugins(self) -> List[dict]:
        """Return info about all loaded plugins."""
        return [s.get_info() for s in self.scanners.values()]

    def _create_example_plugin(self, plugin_dir: str) -> None:
        """Create an example plugin file for users."""
        example = os.path.join(plugin_dir, '_example_plugin.py')
        if os.path.exists(example):
            return
        content = '''"""
Example Snooger Plugin — Custom Scanner Template
Place your .py files in this directory to auto-load them.
"""
from core.plugin_loader import BaseScanner, ScanContext
from typing import List


class ExampleScanner(BaseScanner):
    name = "example_custom_check"
    category = "vuln"  # recon, vuln, exploit, post, report
    description = "Example: checks for a custom vulnerability"
    author = "Your Name"
    version = "1.0"
    priority = 90  # 0=runs first, 100=runs last

    def should_run(self, context: ScanContext) -> bool:
        # Return False to skip this scanner conditionally
        return True

    def run(self, target: str, context: ScanContext) -> List[dict]:
        findings = []
        # Your scanning logic here
        # Example:
        # import requests
        # resp = requests.get(f"{target}/admin")
        # if resp.status_code == 200:
        #     findings.append({
        #         'type': 'exposed_admin_panel',
        #         'url': f"{target}/admin",
        #         'severity': 'medium',
        #         'evidence': f"Admin panel accessible (HTTP {resp.status_code})"
        #     })
        return findings
'''
        try:
            with open(example, 'w') as f:
                f.write(content)
        except OSError:
            pass


# ─── Global singleton ────────────────────────────────────────
_manager: Optional[PluginManager] = None


def init_plugins(config: dict) -> PluginManager:
    global _manager
    plugin_cfg = config.get('plugins', {})
    if not plugin_cfg.get('enabled', True):
        _manager = PluginManager([])
        return _manager

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    plugin_dir = os.path.join(base_dir, plugin_cfg.get('directory', 'plugins'))
    _manager = PluginManager([plugin_dir])

    if plugin_cfg.get('autoload', True):
        _manager.discover()

    return _manager


def get_plugin_manager() -> PluginManager:
    global _manager
    if _manager is None:
        _manager = PluginManager([])
    return _manager
