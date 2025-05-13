# Integration Tests

This directory contains integration tests that verify the interaction between multiple components of the system. These tests are organized according to clean architecture principles.

## Directory Structure

```
integration/
├── api/             # API-related integration tests 
│   └── v1/          # API v1 endpoint tests
│       └── endpoints/
│           ├── mentallama/  # MentaLLaMA API tests
│           ├── patient/     # Patient API tests
│           └── xgboost/     # XGBoost risk prediction tests
├── application/     # Application layer tests
├── core/            # Core domain logic tests
├── domain/          # Domain layer tests
│   └── digital_twin/  # Digital twin domain tests
├── infrastructure/  # Infrastructure layer tests
│   ├── ml/          # Machine learning integration tests
│   └── persistence/ # Database and repository tests
└── conftest.py      # Shared test fixtures
```

## Test Organization Principles

1. Tests are organized by architectural layer following clean architecture principles
2. API tests follow the same versioning as the actual API (v1)
3. Each test focuses on a specific integration point between components
4. Repository tests verify the interaction between domain models and the database
5. Infrastructure tests verify the interaction with external systems

## Running Integration Tests

To run all integration tests:

```bash
python -m pytest app/tests/integration/
```

To run tests for a specific component:

```bash
python -m pytest app/tests/integration/api/v1/endpoints/patient/
```

## Test Fixtures

Common test fixtures are located in `conftest.py` and include:

- Database test fixtures
- API test clients
- Authentication test utilities
- Mock services for external dependencies

## Writing New Integration Tests

When writing new integration tests:

1. Place tests in the appropriate layer directory
2. Use proper test isolation and dependency injection
3. Avoid tight coupling between tests
4. Mock external dependencies appropriately
5. Maintain HIPAA compliance in test data 