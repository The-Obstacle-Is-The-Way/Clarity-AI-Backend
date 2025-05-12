# Future-Proofing Asyncio Test Handling

This document outlines the strategy for future-proofing our asyncio test handling to address deprecation warnings and create a more sustainable testing infrastructure.

## Current Issues

1. **Deprecation Warnings**: We're seeing many warnings about redefined event loop fixtures
2. **Inconsistent Event Loop Handling**: Different test files handle event loops differently
3. **Object Comparison Issues**: Complex objects like `BiometricRule` lack proper equality methods
4. **Multiple Event Loop Fixtures**: We have redundant event loop definitions

## Implementation Plan

### 1. Normalize pytest-asyncio Configuration

Update `pytest.ini` to use the most modern configuration approach:

```ini
[pytest]
asyncio_mode = auto
```

### 2. Use Decorator-Based Approach

Replace custom event loop fixtures with the more modern decorator-based approach:

```python
# Before:
@pytest.fixture(scope="function")
def event_loop():
    loop = asyncio.get_event_loop_policy().new_event_loop()
    asyncio.set_event_loop(loop)
    yield loop
    loop.close()

# After:
@pytest.mark.asyncio(scope="function")
async def test_something():
    # test code here
```

### 3. Implement Proper Object Comparison

Add `__eq__` and `__hash__` methods to domain entities to enable proper comparison:

```python
def __eq__(self, other):
    if not isinstance(other, self.__class__):
        return False
    return self.id == other.id

def __hash__(self):
    return hash(self.id)
```

### 4. Create a Common Test Utils Module

Create a common test utilities module for shared test functionality:

```python
# app/tests/utils/asyncio_helpers.py
import asyncio
import pytest

def configure_test_event_loop():
    """Configure event loop for tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    asyncio.set_event_loop(loop)
    return loop
```

### 5. Phase Out Custom Event Loop Fixtures

Gradually remove custom event loop fixtures from individual test files, relying on the centralized configuration.

## Implementation Timeline

1. Start with enhancing domain entities with proper equality methods
2. Update the pytest.ini file with proper asyncio configuration
3. Create a test utilities package
4. Update one test category at a time (infrastructure, then domain, then application)
5. Test thoroughly after each phase

## Expected Benefits

1. Elimination of deprecation warnings
2. More consistent test behavior
3. Better maintainability
4. Future compatibility with newer pytest and pytest-asyncio versions
5. Improved test reliability 