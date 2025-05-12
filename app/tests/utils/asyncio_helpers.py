"""
Asyncio helpers for testing.

This module provides utility functions for configuring and managing asyncio
event loops in tests, addressing common issues with asyncio tests.
"""

import asyncio
import pytest
from typing import AsyncGenerator, Generator, Any

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

async def run_with_timeout(coro: AsyncGenerator[Any, None], timeout: float = 5.0) -> Any:
    """Run a coroutine with a timeout.
    
    This function runs a coroutine with a timeout, and raises an exception if
    the coroutine doesn't complete within the timeout.
    
    Args:
        coro: The coroutine to run
        timeout: The timeout in seconds
        
    Returns:
        The result of the coroutine
        
    Raises:
        asyncio.TimeoutError: If the coroutine doesn't complete within the timeout
    """
    return await asyncio.wait_for(coro, timeout)

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