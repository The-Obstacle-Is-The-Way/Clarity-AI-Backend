"""
Global test configuration for the entire test suite.

This module contains fixtures and configurations that should be available
to all tests in the application. It is automatically loaded by pytest.
"""

import os
import sys
import pytest
import pytest_asyncio
import logging
from typing import Dict, Any, Generator

# Make the module available to be imported by tests
sys.modules['pytest_asyncio'] = pytest_asyncio

# Configure logging for tests
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@pytest.fixture(scope="session")
def base_test_config() -> Dict[str, Any]:
    """
    Returns a basic configuration dictionary for tests.
    This can be used as a base for other fixtures.
    """
    return {
        "testing": True,
        "debug": True,
    }

# Setup other global fixtures if needed
