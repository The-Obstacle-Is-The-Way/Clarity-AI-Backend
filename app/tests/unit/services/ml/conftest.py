"""
Configuration for ML service tests.

This conftest.py contains hooks to ensure proper test collection and module patching
for machine learning service tests, following clean architecture principles.
"""

import sys


def pytest_collect_file(parent, path):
    """
    Custom collection hook to prevent pytest from trying to collect
    the xgboost directory as if it were the actual xgboost package.
    """
    if "xgboost" in str(path) and "__pycache__" not in str(path):
        # Return None for any files in the xgboost directory to prevent collection conflicts
        return None
    # Let pytest handle all other files normally
    return None  # Use default collection mechanism


# Ensure PYTHONPATH does not try to import test modules as packages
for key in list(sys.modules.keys()):
    if key.startswith("xgboost.") and "tests" in key:
        del sys.modules[key]


# Apply YAML mocking for XGBoost tests if needed
def setup_yaml_mocking():
    """Set up YAML mocking for XGBoost tests."""
    try:
        # Import the mocks first so they're in scope
        from app.tests.unit.services.ml.xgboost_service.mock_yaml import dump as mock_dump
        from app.tests.unit.services.ml.xgboost_service.mock_yaml import safe_load as mock_safe_load
        
        class MockYamlModule:
            safe_load = mock_safe_load
            dump = mock_dump
            _is_mocked = True
        
        if 'yaml' in sys.modules and not hasattr(sys.modules['yaml'], '_is_mocked'):
            sys.modules['yaml'] = MockYamlModule
    except ImportError:
        pass  # Skip if mock_yaml module not found


setup_yaml_mocking()
