"""
Central conftest.py for all unit tests in the app.

This file contains fixtures that are common to all unit tests.
"""

import asyncio
import pytest


@pytest.fixture(scope="function")
def event_loop():
    """Create an instance of the default event loop for each test case.
    
    This fixture ensures that each test gets a clean event loop, which helps prevent
    test isolation issues where one test could affect another's event loop.
    
    Returns:
        asyncio.AbstractEventLoop: A new event loop for the test.
    """
    loop = asyncio.get_event_loop_policy().new_event_loop()
    asyncio.set_event_loop(loop)
    yield loop
    # The loop should be closed at the end of the test
    loop.close() 