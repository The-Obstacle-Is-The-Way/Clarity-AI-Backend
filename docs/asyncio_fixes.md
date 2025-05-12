# Asyncio Testing Fixes

This document explains the asyncio testing patterns and fixes implemented in the Clarity AI Backend codebase to address event loop and asyncio-related testing issues.

## Problem Statement

The test suite was experiencing widespread asyncio event loop errors, primarily:

1. `RuntimeError: There is no current event loop in thread 'MainThread'`
2. Coroutine object handling issues (passing coroutines vs. callables)
3. Missing pytest_asyncio imports
4. Cleanup of event loops between tests

## Solutions Implemented

### 1. Central Event Loop Fixture

A central event loop fixture was created in `app/tests/conftest.py` to ensure all tests have access to a properly configured event loop.

```python
# app/tests/conftest.py
import pytest_asyncio
import sys

# Make the module available to be imported by tests
sys.modules['pytest_asyncio'] = pytest_asyncio
```

### 2. Asyncio Utilities

We created a dedicated utilities package (`app/tests/utils/asyncio_helpers.py`) with functions for properly managing event loops:

- `configure_test_event_loop()`: Create a new event loop for tests
- `cleanup_event_loop()`: Properly close and clean up event loops
- `run_with_timeout()`: Run async operations with timeouts
- Various event loop fixtures with different scopes

### 3. Decorator-Based Approach

We standardized on the pytest-asyncio decorator approach:

```python
@pytest.mark.asyncio
async def test_example():
    # Test implementation
```

### 4. Fixed run_with_timeout Function

The `run_with_timeout` function has been improved to handle both:
- Awaitable objects (coroutines)
- Callable functions that return awaitables

```python
async def run_with_timeout(
    awaitable: Any, 
    timeout: float = 5.0,
) -> T:
    """Run an async function or awaitable with a timeout."""
    if callable(awaitable):
        # If a callable was passed, call it to get the coroutine
        awaitable = awaitable()
    
    # Now we should have a coroutine object
    return await asyncio.wait_for(awaitable, timeout=timeout)
```

### 5. Pytest Configuration

Updated `pytest.ini` to use modern asyncio mode settings:

```ini
[pytest]
asyncio_mode = auto
```

## Usage Guidelines

### Basic Test Pattern

```python
import pytest
import pytest_asyncio

@pytest.mark.asyncio
async def test_my_async_function():
    # Test implementation
    result = await some_async_function()
    assert result == expected_value
```

### Using run_with_timeout

```python
from app.tests.utils.asyncio_helpers import run_with_timeout

@pytest.mark.asyncio
async def test_with_timeout():
    # Pass a coroutine directly
    result = await run_with_timeout(some_async_function(), timeout=1.0)
    
    # OR pass a callable function
    result = await run_with_timeout(some_async_function, timeout=1.0)
```

### Using Custom Event Loop Fixtures

```python
from app.tests.utils.asyncio_helpers import standard_event_loop

def test_with_loop(standard_event_loop):
    # The loop is set as the current event loop
    # Run sync code that calls async code internally
    result = standard_event_loop.run_until_complete(some_async_function())
    assert result == expected_value
```

## Troubleshooting

If you encounter asyncio-related errors in tests:

1. Ensure your test module imports `pytest_asyncio`
2. Use the `@pytest.mark.asyncio` decorator for async tests
3. For tests that mix sync and async code, consider using an event loop fixture
4. For complex async operations, use `run_with_timeout` to prevent hanging tests

## Future Maintenance

As the codebase evolves:

1. Maintain the central event loop fixture in `conftest.py`
2. Keep the asyncio helper utilities up to date with any pytest or asyncio changes
3. Use the standard testing patterns described above for all new tests
4. Consider periodically running the `scripts/fix_pytest_asyncio_imports.py` script to catch missing imports 