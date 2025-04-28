#!/usr/bin/env python3
"""
Fix indentation and syntax issues in the rate limiter test file
"""

with open('app/tests/unit/infrastructure/security/test_rate_limiter.py', 'r') as file:
    content = file.read()

# Fix the fixture function
content = content.replace(
    '@pytest.fixture\ndef mock_cache_service():\n                """Create a mock Redis cache service for testing."""\n    mock_cache = AsyncMock()',
    '@pytest.fixture\ndef mock_cache_service():\n    """Create a mock Redis cache service for testing."""\n    mock_cache = AsyncMock()'
)

# Fix parentheses issues
content = content.replace('mock_cache.exists = AsyncMock(return_value=False))', 'mock_cache.exists = AsyncMock(return_value=False)')
content = content.replace('mock_cache.get = AsyncMock(return_value=None))', 'mock_cache.get = AsyncMock(return_value=None)')
content = content.replace('mock_cache.set = AsyncMock(return_value=True))', 'mock_cache.set = AsyncMock(return_value=True)')

with open('app/tests/unit/infrastructure/security/test_rate_limiter.py', 'w') as file:
    file.write(content)

print("Fixed indentation and syntax issues in test_rate_limiter.py")
