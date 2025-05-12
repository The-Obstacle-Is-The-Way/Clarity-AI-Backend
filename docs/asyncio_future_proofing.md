# Asyncio Future-Proofing Guide

This document outlines best practices for asyncio testing and development in the Clarity AI Backend codebase to prevent future issues and ensure consistent patterns.

## Core Principles

1. **Consistent Test Patterns**: Use standardized approaches for all asyncio-based tests
2. **Proper Fixture Management**: Handle event loops with appropriate fixtures and scopes
3. **Error Handling**: Ensure timeout mechanisms for all async operations in tests
4. **Import Discipline**: Maintain correct asyncio-related imports in all test modules

## Modern Asyncio Testing Pattern

```python
import pytest
import pytest_asyncio
import asyncio
from app.tests.utils.asyncio_helpers import run_with_timeout

@pytest.mark.asyncio
async def test_async_operation():
    # Simple async operation
    result = await some_async_function()
    assert result == expected_value
    
    # Async operation with timeout
    result = await run_with_timeout(some_async_function(), timeout=1.0)
    assert result == expected_value
```

## Test Class Pattern

For test classes, apply the decorator at the class level for all methods:

```python
import pytest
import pytest_asyncio

@pytest.mark.asyncio
class TestAsyncService:
    async def test_method_one(self):
        # Test implementation
        pass
        
    async def test_method_two(self):
        # Test implementation
        pass
```

## Advanced Patterns

### Mixing Sync and Async Code

When a test needs to mix synchronous and asynchronous code:

```python
import pytest
import pytest_asyncio
from app.tests.utils.asyncio_helpers import standard_event_loop

def test_mixed_sync_async(standard_event_loop):
    # Synchronous code
    service = SomeService()
    
    # Run async code from sync context
    result = standard_event_loop.run_until_complete(service.async_method())
    assert result == expected_value
```

### Parallel Async Operations

For testing parallel operations:

```python
@pytest.mark.asyncio
async def test_parallel_operations():
    tasks = [some_async_function(i) for i in range(5)]
    results = await asyncio.gather(*tasks)
    assert len(results) == 5
```

### Mocking Async Functions

```python
@pytest.mark.asyncio
async def test_with_async_mock(mocker):
    # Create an async mock
    mock_async_func = mocker.AsyncMock(return_value="mocked_result")
    
    # Patch the function
    with mocker.patch("module.async_function", mock_async_func):
        result = await function_under_test()
        assert result == "mocked_result"
        mock_async_func.assert_called_once()
```

## HIPAA-Compliant Error Handling

For HIPAA compliance, ensure no PHI leaks in error states:

```python
@pytest.mark.asyncio
async def test_error_handling():
    with pytest.raises(SomeError) as excinfo:
        await service.method_that_raises()
    
    # Ensure no PHI in error message
    error_message = str(excinfo.value)
    assert not contains_phi(error_message)
    
    # Use pattern matching for error validation instead of exact messages
    assert re.search(r"Error pattern without PHI", error_message)
```

## Performance Considerations

To ensure tests don't hang or slow down CI/CD pipelines:

1. Always use timeouts with `run_with_timeout` for external dependencies
2. Use appropriate mocks for third-party services
3. Configure reasonable timeouts for all async operations

```python
@pytest.mark.asyncio
async def test_with_external_dependency():
    # Use a short timeout for testing
    result = await run_with_timeout(
        external_service.slow_method(), 
        timeout=0.5
    )
```

## Debugging Asyncio Tests

When debugging asyncio-related failures:

1. Check for the correct imports
2. Ensure proper event loop creation and cleanup
3. Look for unhandled coroutines (common in test failures)
4. Verify timeouts are appropriate for the operations

Debug logging for asyncio can be enabled with:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
logging.getLogger('asyncio').setLevel(logging.DEBUG)
```

## Recommended Migration Path

As you update existing code:

1. Replace any custom event loop fixtures with `@pytest.mark.asyncio`
2. Use the helpers in `app/tests/utils/asyncio_helpers.py` for common patterns
3. Add timeouts to all external service calls in tests
4. Ensure proper error handling for HIPAA compliance

## Quality Checklist for New Asyncio Tests

- [ ] Imports pytest_asyncio module
- [ ] Uses @pytest.mark.asyncio decorator
- [ ] Uses run_with_timeout for operations that could hang
- [ ] Properly handles event loops (no manual loop creation unless needed)
- [ ] Avoids leaking PHI in error messages
- [ ] Follows the test patterns in this document 