"""
Pytest configuration for async tests.

This module provides fixtures and configuration for correctly handling
async tests with mock objects throughout the test suite.
"""

import pytest
from unittest.mock import patch

from app.tests.utils.async_test_helpers import SafeAsyncMock


@pytest.fixture(autouse=True)
def patch_async_mock():
    """
    Automatically patch AsyncMock with SafeAsyncMock throughout all tests.
    
    This fixture ensures all AsyncMock instances are SafeAsyncMock instances
    that support awaitable assertions, preventing "coroutine was never awaited"
    warnings.
    """
    with patch('unittest.mock.AsyncMock', SafeAsyncMock):
        yield
