# Standalone Test Migration Guide

## Overview

This document outlines the strategy and process for migrating standalone tests to proper unit tests that use the actual implementations from the codebase. Standalone tests create maintenance issues because they:

1. Duplicate implementations that already exist in the main codebase
2. Create confusion about which implementation is correct
3. Allow tests to pass even when the actual implementations are broken
4. Violate DRY principles and increase maintenance burden

## Migration Process

### Step 1: Analyze Standalone Tests

Run the analysis script to categorize standalone tests:

```bash
./scripts/migrate_standalone_tests.sh
```

This will analyze all standalone tests and categorize them as:

- **Valuable Tests**: Good candidates for migration (many imports from main codebase)
- **Problematic Tests**: Heavily depend on other standalone code (need complex migration)
- **Duplicate Tests**: Already have corresponding unit tests
- **Candidate Tests**: Need manual review

### Step 2: Prioritize Tests for Migration

1. Start with valuable tests that use the actual domain models/services
2. Focus on failing tests in the test suite
3. Group related tests together (e.g., all BiometricProcessor tests)
4. Prioritize tests for core functionality

### Step 3: Migrate Test Files

For each test file to migrate:

1. Create a new file in the proper unit test directory with the same name
2. Import the actual implementations instead of duplicate code
3. Adapt the tests to work with the actual implementations
4. Fix any assertions or test logic that expects different behavior
5. Run the new tests to ensure they pass

Example:

```bash
# For biometric event processor tests:
./scripts/migrate_biometric_tests.sh
```

### Step 4: Verify Migrations

1. Run the migrated tests to ensure they pass
2. Verify coverage is maintained or improved
3. Check that all functionality is tested properly
4. Update documentation to reflect the migration status

### Step 5: Delete Standalone Tests

After verification:

1. Create a final PR to delete the standalone tests
2. Ensure all functionality is now tested in proper unit tests
3. Update any references to the standalone tests in documentation

## Migration Templates

### Test File Template

```python
"""
Migrated unit test for [component].

These tests verify the actual implementation.
"""

import pytest
from unittest.mock import MagicMock, patch

# Import actual implementations (not standalone versions)
from app.domain... import ...
from app.core... import ...

# Test fixtures

@pytest.fixture
def fixture_name():
    """Fixture description."""
    return ...

# Test classes

class TestClassName:
    """Tests for the actual implementation of ClassName."""
    
    def test_method_name(self):
        """Test method_name functionality."""
        # Setup
        ...
        
        # Execute
        ...
        
        # Assert
        ...
```

## Common Patterns for Migration

### Fixture Adaptation

```python
# Standalone test fixture (using duplicate implementation)
@pytest.fixture
def engine():
    return StandaloneEngine()

# Migrated fixture (using actual implementation)
@pytest.fixture
def engine():
    return ActualEngine()
```

### Mock Service Patterns

```python
# Standalone test often directly calls methods
result = service.process(data)
assert result.status == "success"

# Migrated test may need more mocking
mock_dependency = MagicMock()
service = ActualService(dependency=mock_dependency)
result = service.process(data)
assert result.status == "success"
mock_dependency.method.assert_called_once_with(data)
```

### Assertion Adaptation

```python
# Standalone test assertion (might use simplified implementation)
assert len(processor.rules) == 1
assert processor.rules[0] == rule

# Migrated test assertion (must match actual implementation)
assert len(processor.rules) == 1
assert processor.rules[rule.rule_id] == rule
```

## Example Migration: Biometric Event Processor

The `test_biometric_event_processor.py` standalone test was migrated to a proper unit test:

1. Original test used hard-coded rule lists, but actual implementation uses a dict
2. Alert creation API was different in the standalone vs actual implementation
3. Notification logic needed proper mocking in the actual implementation

Key changes:

```python
# Original assertion (incorrect - assumes rules is a list)
assert rule in processor.rules

# Migrated assertion (correct - rules is a dict with rule_id keys)
assert rule.rule_id in processor.rules
assert processor.rules[rule.rule_id] == rule
```

## Tips for Successful Migration

1. **Understand the actual implementation** before migrating tests
2. **Read the existing unit tests** for the same components to understand patterns
3. **Use appropriate mocking** to isolate the component under test
4. **Maintain test coverage** when migrating - don't lose test cases
5. **Run tests frequently** during migration to catch issues early
6. **Adapt assertions** to match the actual implementation's behavior
7. **Use proper error handling** for exceptions that may differ

## Conclusion

Migrating standalone tests to proper unit tests improves the codebase by:

1. Ensuring tests verify the actual implementations
2. Eliminating duplicate code and maintenance burden
3. Providing better test coverage for the actual code
4. Making tests more reliable indicators of system health

Track migration progress in the [Standalone Test Migration Status](./standalone_test_migration_status.md) document. 