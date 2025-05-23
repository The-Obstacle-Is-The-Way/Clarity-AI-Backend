"""
Pytest marker registration module.

This module registers all custom pytest markers used in the test suite
to avoid warnings during test collection and execution.
"""


def pytest_configure(config) -> None:
    """
    Register custom markers for pytest.

    This function registers all custom markers used in the test suite
    to avoid warnings during test collection and execution.
    """
    # Register all custom markers
    config.addinivalue_line("markers", "standalone: Tests that have no external dependencies")
    config.addinivalue_line("markers", "db_required: Tests that require database connections")
    config.addinivalue_line(
        "markers",
        "venv_only: Tests that require Python packages but no external services",
    )
    config.addinivalue_line("markers", "unit: Unit tests")
    config.addinivalue_line("markers", "ml: Machine learning related tests")
    config.addinivalue_line("markers", "phi: Protected Health Information related tests")
    config.addinivalue_line("markers", "integration: Integration tests")
    config.addinivalue_line("markers", "e2e: End-to-end tests")
    config.addinivalue_line("markers", "security: Tests specifically validating security features")
    config.addinivalue_line("markers", "slow: Tests that take longer than 1 second to execute")
    config.addinivalue_line(
        "markers", "flaky: Tests with occasional failures that are being investigated"
    )
    config.addinivalue_line(
        "markers", "smoke: Critical functionality tests used for rapid verification"
    )
    config.addinivalue_line("markers", "network_required: Tests that require network connections")
