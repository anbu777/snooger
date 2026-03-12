"""
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
