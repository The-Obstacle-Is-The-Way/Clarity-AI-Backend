# Standalone Test Migration Guide

## Background

The Clarity AI Backend includes a "standalone" test suite with approximately 255 tests that have their own implementations of key components instead of testing the actual codebase implementations. This guide outlines the process for migrating these standalone tests to proper unit and integration tests that test the actual codebase.

## Migration Goals

1. **Preserve test coverage:** Ensure no loss of test cases during migration
2. **Eliminate duplicate code:** Remove redundant implementations in favor of actual code
3. **Improve maintainability:** Tests should test the actual implementations, not parallel ones
4. **Follow clean architecture principles:** Properly organize tests according to domain layers

## Migration Process

### 1. Assessment Phase

For each standalone test:
- Determine if there's a corresponding actual implementation
- Check if it already has unit/integration test coverage
- Identify any special cases or assumptions in the standalone implementation

### 2. Migration Strategy Selection

Choose one of these approaches based on assessment:

A. **Simple Migration:** For tests that are already well-structured and just need import updates
   - Update imports to use actual implementations
   - Adjust test assertions if needed
   - Rerun tests to verify functionality

B. **Merge Tests:** For components with both standalone and unit tests
   - Compare coverage between standalone and existing unit tests
   - Identify unique test cases in the standalone tests
   - Add those test cases to the existing unit tests

C. **Full Migration:** For components that only have standalone tests
   - Create new unit/integration test files in the proper location
   - Convert to use actual implementations
   - Adapt test fixtures and assertions

D. **Custom Migration:** For complex components or special cases
   - May require additional refactoring
   - May need domain expert input

### 3. Step-by-Step Migration Guide

1. **Use the migration script to analyze the test suite:**
   ```bash
   ./scripts/migrate_standalone_tests.sh
   ```

2. **Review the migration log:**
   - Focus first on "needs_migration" status tests
   - Prioritize core components (biometric processor, entities, etc.)

3. **For each test to migrate:**
   ```bash
   # Generate a migration template
   ./scripts/migrate_standalone_tests.sh --create-template app/tests/standalone/path/to/test.py
   ```

4. **Edit the template to implement the migration:**
   - Replace imports with actual implementation imports
   - Update test fixtures to match actual implementation requirements
   - Adjust assertions to match expected behavior

5. **Run the migrated test to verify it works:**
   ```bash
   python -m pytest <migrated_test_file> -v
   ```

6. **Run the original test to ensure coverage is maintained:**
   ```bash
   python -m pytest <original_standalone_test> -v
   ```

7. **Track migration progress in the migration log**

## Example: Biometric Processor Migration

### Before: Standalone Implementation

```python
# In app/tests/standalone/core/test_standalone_biometric_processor.py

"""Self-contained test for Biometric Event Processor."""

class BiometricType(str, Enum):
    """Types of biometric data."""
    HEART_RATE = "heart_rate"
    # ...

class AlertRule:
    """Alert rule for biometric data."""
    
    def __init__(self, name, data_type, operator, threshold, ...):
        # Implementation specific to standalone test
        # ...

# Test cases
@pytest.mark.standalone()
class TestAlertRule(unittest.TestCase):
    def test_evaluate_greater_than_or_equal(self):
        # Test using standalone implementation
        # ...
```

### After: Migrated Test

```python
# In app/tests/unit/domain/services/test_biometric_event_processor.py

"""
Unit tests for the BiometricEventProcessor.
"""

from app.domain.entities.biometric_twin import BiometricDataPoint
from app.domain.services.biometric_event_processor import (
    AlertRule,
    BiometricEventProcessor,
    AlertPriority
)

@pytest.fixture
def sample_rule(sample_clinician_id):
    """Create a sample alert rule."""
    return AlertRule(
        rule_id="test-rule-1",
        name="High Heart Rate",
        description="Alert when heart rate exceeds 100 bpm",
        priority=AlertPriority.WARNING,
        condition={
            "data_type": "heart_rate",
            "operator": ">",
            "threshold": 100.0
        },
        created_by=sample_clinician_id,
        is_active=True
    )

class TestAlertRule:
    def test_evaluate_greater_than_or_equal(self, sample_rule, sample_data_point):
        # Test using actual implementation
        # ...
```

## Common Migration Challenges

1. **Parameter differences:** Standalone implementations may have different parameter requirements
   - Check constructor signatures carefully
   - May need to add/remove parameters

2. **Behavior differences:** Standalone implementations may have slightly different behavior
   - Adjust test assertions to match actual implementation behavior
   - Document any significant differences

3. **Missing features:** Standalone implementations may include features not in the actual code
   - Consider whether these features should be added to the main code
   - May need to remove or adapt test cases

4. **Import dependencies:** Standalone tests may have fewer dependencies
   - Add necessary mocks for external dependencies
   - Use pytest fixtures to simplify test setup

## Best Practices

1. **Migrate one component at a time:** Focus on completing one component before moving to the next
2. **Run tests frequently:** Verify each change to catch issues early
3. **Update documentation:** Ensure test documentation reflects the actual implementation
4. **Preserve test coverage:** Don't remove test cases without ensuring coverage is maintained
5. **Use clear commit messages:** Document what was migrated and any challenges

## Phased Migration Plan

1. **Phase 1: Core Domain Components**
   - Biometric Processor
   - Alert Rules
   - Entity Models

2. **Phase 2: Services and Utilities**
   - Mock Services
   - Utility Functions
   - Helper Classes

3. **Phase 3: API and Integration Tests**
   - API Endpoints
   - External Interfaces
   - Integration Flows

4. **Phase 4: Cleanup**
   - Remove standalone test directory
   - Update CI/CD configuration
   - Finalize documentation

## Resources

- Migration script: `scripts/migrate_standalone_tests.sh`
- Migration log: `test_migration_log.csv`
- Example migrated test: `app/tests/unit/domain/services/test_biometric_event_processor_migrated.py` 