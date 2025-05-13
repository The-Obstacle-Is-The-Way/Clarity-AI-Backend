# Integration Tests Reorganization Plan

## Issues Identified

1. **Redundancy**: Multiple test files testing similar functionality (e.g., `test_actigraphy_api_integration.py` and `test_actigraphy_endpoints.py`)
2. **Inconsistent Naming**: Test files use inconsistent naming patterns (`_integration`, `_int`, or no suffix)
3. **Import Problems**: Issues with missing imports and undefined functions in core fixtures
4. **Empty Directories**: Some directories were created but contain no test files
5. **Failing Tests**: Several test failures due to misconfigurations and dependency issues
6. **PHI Standards Not Met**: One test is failing due to improper PHI handling (returning 500 instead of 400/422)

## Clean Architecture Principles for Test Structure

Each layer should have its own integration tests properly isolated:

1. **Domain Layer Tests**: Test domain entities and business logic  
2. **Application Layer Tests**: Test use cases and coordination logic
3. **Infrastructure Layer Tests**: Test persistence, external services integration
4. **API Layer Tests**: Test HTTP interface, validation, error handling
5. **Cross-Cutting Tests**: Test security boundaries, middleware, etc.

## Reorganization Plan

### 1. Fix Core Fixtures (Priority)

1. Fix `conftest.py` to properly import and configure application factory
2. Remove duplicate test fixtures
3. Standardize authentication and mock handling

### 2. Standardize Directory Structure

```
app/tests/
├── integration/
│   ├── api/                 # API layer tests (HTTP interface)
│   │   ├── v1/              # Tests for API v1
│   │   │   ├── endpoints/   # Specific endpoint tests
│   │   │   └── test_api_auth.py   # API auth tests
│   ├── application/         # Application layer (use cases)
│   │   ├── services/        # Service tests
│   │   └── workflows/       # Workflow tests
│   ├── domain/              # Domain layer tests
│   │   ├── entities/        # Entity tests
│   │   └── services/        # Domain service tests
│   ├── infrastructure/      # Infrastructure tests
│   │   ├── persistence/     # Database/repository tests
│   │   ├── security/        # Security component tests
│   │   └── external/        # External service integration tests
│   ├── conftest.py          # Shared fixtures for integration tests
│   └── test_helpers.py      # Helper functions for testing
│
└── unit/                    # Unit tests
```

### 3. Test File Naming Convention

Use consistent naming pattern across all test files:

- `test_[component]_[optional_specific_aspect].py`
- Remove redundant suffixes (`_integration`, `_int`)
- Suffix is provided by directory location (`integration/` or `unit/`)

### 4. Merge Redundant Tests

Specifically for actigraphy:
- Merge `test_actigraphy_api_integration.py` and `test_actigraphy_endpoints.py` into a single `api/v1/endpoints/test_actigraphy.py` file
- Organize tests by functionality rather than file location

### 5. Consolidate Empty Directories

- Remove empty module directories
- Ensure `__init__.py` files are consistent and maintain proper imports

### 6. Fix Authentication and Security Patterns

- Standardize authentication mechanisms
- Implement proper HIPAA-compliant error responses (in test_xgboost_api_integration.py)
- Ensure PHI data sanitization follows consistent patterns

### 7. Ensure Test Coverage of Core Functionality

- Validate that after reorganization, test coverage is maintained or improved
- Document key test areas requiring additional coverage

## Implementation Plan - Steps in Order

1. Fix the core fixtures in conftest.py
2. Create the new directory structure
3. Move and merge tests to follow the new structure
4. Fix failing tests
5. Delete redundant files
6. Update imports and references
7. Verify all tests pass

## Quality Standards

- **DRY**: Remove duplicate test fixtures and mocks
- **SOLID**: Ensure layers are properly isolated in tests
- **HIPAA**: Ensure proper PHI handling, auth, and audit logging
- **Security**: Validate security boundaries and sanitization in tests 