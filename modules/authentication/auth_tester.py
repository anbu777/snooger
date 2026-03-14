"""
Compatibility alias: modules.authentication.auth_tester
Redirects to the canonical location at modules.auth.auth_testing
"""
from modules.auth.auth_testing import (
    run_auth_tests,
    test_brute_force_protection,
    test_jwt_vulnerabilities,
    test_oauth_misconfigurations,
    test_forceful_browsing,
    test_session_fixation,
    analyze_form_security,
)

__all__ = [
    'run_auth_tests',
    'test_brute_force_protection',
    'test_jwt_vulnerabilities',
    'test_oauth_misconfigurations',
    'test_forceful_browsing',
    'test_session_fixation',
    'analyze_form_security',
]
