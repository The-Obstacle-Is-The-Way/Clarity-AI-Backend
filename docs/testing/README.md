# Clarity AI Testing Strategy

## Overview

The Clarity AI Backend implements a comprehensive testing strategy to ensure code quality, HIPAA compliance, and proper functionality across all layers of the application. This document outlines our testing approach and standards.

## Test Organization

The test suite is organized into three main categories:

1. **Unit Tests**: Test individual components in isolation
   - Location: `app/tests/unit/`
   - Focus: Domain models, services, utilities
   - Run with: `python -m pytest app/tests/unit/`

2. **Integration Tests**: Test how components work together
   - Location: `app/tests/integration/`
   - Focus: API endpoints, repositories, external services
   - Run with: `python -m pytest app/tests/integration/`

3. **Standalone Tests** (Legacy - In Migration):
   - Location: `app/tests/standalone/`
   - Focus: Self-contained tests with their own implementations
   - Run with: `python -m pytest app/tests/standalone/`
   - Note: These tests are being migrated to unit/integration tests

## Test Standards

All tests should follow these standards:

1. **HIPAA Compliance Testing**:
   - No PHI in logs or error messages
   - Test encryption for data at rest and in transit
   - Verify authentication and authorization
   - Validate audit logging

2. **Test Coverage**:
   - Aim for >90% code coverage
   - Cover edge cases and error conditions
   - Include both positive and negative test cases

3. **Test Organization**:
   - Follow domain-driven testing structure
   - Align test files with application structure
   - Use clear test class and method names

4. **Test Quality**:
   - Use pytest fixtures for test setup
   - Implement proper mocking of external dependencies
   - Ensure tests are deterministic and repeatable

## Standalone Test Migration

We are currently migrating our standalone test suite to proper unit and integration tests. See the [Standalone Test Migration Guide](./standalone_test_migration_guide.md) for details on this process.

### Migration Schedule

1. **Phase 1 (Current)**: Core Domain Components
   - Biometric Processor
   - Alert Rules
   - Entity Models

2. **Phase 2**: Services and Utilities
3. **Phase 3**: API and Integration Tests
4. **Phase 4**: Final Cleanup

### Migration Tools

- Migration Script: `scripts/migrate_standalone_tests.sh`
- Migration Log: `test_migration_log.csv`
- Migration Guide: `docs/testing/standalone_test_migration_guide.md`

## Running Tests

To run all tests:
```bash
python -m pytest
```

To run specific test categories:
```bash
# Unit tests only
python -m pytest app/tests/unit/

# Integration tests only
python -m pytest app/tests/integration/

# Standalone tests only
python -m pytest app/tests/standalone/
```

To run with coverage:
```bash
python -m pytest --cov=app
```

## Test Development Guidelines

1. **New Features**: Always write tests before or alongside new feature development
2. **Bug Fixes**: Create a test that reproduces the bug before fixing it
3. **Test Independence**: Tests should not depend on each other
4. **Clean Code**: Keep test code clean and maintainable
5. **Test Names**: Use descriptive test names that explain what is being tested

## Testing CI/CD Integration

Our CI/CD pipeline runs all tests on every pull request:
- Unit and integration tests must pass for PR approval
- Coverage reports are generated automatically
- Security and HIPAA compliance scans are performed 