"""
Asyncio helpers for testing.

This module provides utility functions for configuring and managing asyncio
event loops in tests, addressing common issues with asyncio tests.
"""

import asyncio
import pytest
from typing import AsyncGenerator, Generator, Any, Callable, TypeVar, Awaitable

T = TypeVar('T')

def configure_test_event_loop() -> asyncio.AbstractEventLoop:
    """Create and configure a test event loop.
    
    This function creates a new event loop, sets it as the current event loop,
    and returns it. This is useful for tests that need to create an event loop
    outside of a pytest fixture.
    
    Returns:
        asyncio.AbstractEventLoop: The configured event loop
    """
    loop = asyncio.get_event_loop_policy().new_event_loop()
    asyncio.set_event_loop(loop)
    return loop

def cleanup_event_loop(loop: asyncio.AbstractEventLoop) -> None:
    """Clean up an event loop.
    
    This function closes an event loop and handles any pending tasks.
    
    Args:
        loop: The event loop to clean up
    """
    # Cancel all pending tasks
    pending = asyncio.all_tasks(loop)
    if pending:
        for task in pending:
            task.cancel()
        # Allow them to be cancelled
        loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
    
    # Close the loop
    loop.close()

async def run_with_timeout(
    awaitable: Any, 
    timeout: float = 5.0,
) -> T:
    """Run an async function or awaitable with a timeout.
    
    This function accepts either an awaitable object (coroutine) or a callable
    that returns an awaitable. It runs the awaitable with a timeout.
    
    Args:
        awaitable: The awaitable object (coroutine) or callable that returns an awaitable
        timeout: Timeout in seconds
        
    Returns:
        The result of the awaitable
        
    Raises:
        asyncio.TimeoutError: If the operation doesn't complete within the timeout
    """
    if callable(awaitable):
        # If a callable was passed, call it to get the coroutine
        awaitable = awaitable()
    
    # Now we should have a coroutine object
    return await asyncio.wait_for(awaitable, timeout=timeout)

# Alias for backward compatibility with code that imports run_with_timeout_asyncio
run_with_timeout_asyncio = run_with_timeout

@pytest.fixture
async def async_test_timeout() -> float:
    """Return the default timeout for async tests."""
    return 5.0

async def ensure_event_loop() -> asyncio.AbstractEventLoop:
    """Ensure an event loop is available and return it.
    
    This function tries to get the current event loop, and if none exists,
    it creates a new one and sets it as the current event loop.
    
    Returns:
        asyncio.AbstractEventLoop: The current or newly created event loop
    """
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = configure_test_event_loop()
    return loop

@pytest.fixture
async def ensure_test_event_loop() -> asyncio.AbstractEventLoop:
    """Ensure a test event loop is available and return it.
    
    This fixture tries to get the current event loop, and if none exists,
    it creates a new one and sets it as the current event loop.
    
    Returns:
        asyncio.AbstractEventLoop: The current or newly created event loop
    """
    return await ensure_event_loop()

# Pre-defined fixtures that can be imported and used in test modules
@pytest.fixture
def standard_event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    """Create a standard event loop fixture with proper cleanup.
    
    This fixture creates a new event loop, sets it as the current event loop,
    and yields it. After the test completes, it cleans up the event loop.
    
    Yields:
        asyncio.AbstractEventLoop: The event loop for the test
    """
    loop = configure_test_event_loop()
    yield loop
    cleanup_event_loop(loop)

# For when the default scope doesn't work properly
@pytest.fixture(scope="function")
def function_scoped_event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    """Create a function-scoped event loop fixture.
    
    This fixture has explicit function scope, which helps when the default
    scope causes issues.
    
    Yields:
        asyncio.AbstractEventLoop: The event loop for the test
    """
    loop = configure_test_event_loop()
    yield loop
    cleanup_event_loop(loop)

@pytest.fixture(scope="module")
def module_scoped_event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    """Create a module-scoped event loop fixture.
    
    This fixture has module scope, which can be more efficient when multiple
    tests in a module need the same event loop configuration.
    
    Yields:
        asyncio.AbstractEventLoop: The event loop for the test
    """
    loop = configure_test_event_loop()
    yield loop
    cleanup_event_loop(loop) 