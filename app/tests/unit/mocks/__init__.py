"""
Global mock implementations for test dependencies.

This module provides centralized mocking of external libraries to enable
test collection and execution without requiring all dependencies to be installed.
"""

import sys
from unittest.mock import MagicMock

# Create mock modules for common dependencies
MOCK_MODULES = [
    'numpy',
    'yaml',
    'pandas', 
    'sklearn',
    'tensorflow',
    'torch',
    'xgboost',
    'matplotlib',
    'scipy'
]

# Create mocks for each module
for mod_name in MOCK_MODULES:
    if mod_name not in sys.modules:
        sys.modules[mod_name] = MagicMock()

# Special handling for numpy
numpy_mock = sys.modules['numpy']
numpy_mock.ndarray = type('ndarray', (), {})
numpy_mock.array = lambda x, *args, **kwargs: x
numpy_mock.zeros = lambda *args, **kwargs: []
numpy_mock.ones = lambda *args, **kwargs: []

# Special handling for yaml
yaml_mock = sys.modules['yaml']
yaml_mock.safe_load = lambda stream: {"mock": "config"}
yaml_mock.dump = lambda data, stream=None, **kwargs: str(data)
