"""
Central conftest.py for all unit tests in the app.

This file contains fixtures that are common to all unit tests.
"""

import asyncio

import pytest

from app.tests.utils.asyncio_helpers import (
    cleanup_event_loop,
    configure_test_event_loop,
)


# Instead of redefining the event_loop fixture, which causes deprecation warnings,
# we'll define an event_loop_policy fixture which is the recommended approach
@pytest.fixture(scope="session")
def event_loop_policy():
    """Return the event loop policy to use."""
    return asyncio.DefaultEventLoopPolicy()


# These fixtures are for backward compatibility during migration
# They should be gradually phased out in favor of using @pytest.mark.asyncio directly
@pytest.fixture(scope="function")
def setup_test_event_loop():
    """Set up a test event loop without yielding it.

    This is a non-yielding helper fixture that can be used by tests that
    need to set up an event loop but don't need the loop itself.
    """
    loop = configure_test_event_loop()
    return loop


@pytest.fixture(scope="function")
def cleanup_test_loop(request) -> None:
    """Clean up the event loop after a test.

    This is a finalizer fixture that ensures the event loop is properly
    cleaned up, even if the test fails.
    """

    def fin() -> None:
        loop = asyncio.get_event_loop()
        cleanup_event_loop(loop)

    request.addfinalizer(fin)
    return None
