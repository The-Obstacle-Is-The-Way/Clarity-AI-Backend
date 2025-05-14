# Testing Guide

This document provides a comprehensive guide to testing the Novamind Digital Twin platform. It covers testing strategies, tools, frameworks, and best practices for ensuring the quality, reliability, and security of the system.

---

## 1. Testing Philosophy

The Novamind platform follows a comprehensive testing strategy that emphasizes:

- **Completeness**: Thorough testing across all components and layers
- **Automation**: Automated testing at all levels for consistent validation
- **Security-First**: Special attention to security and HIPAA compliance testing
- **Shift-Left**: Testing early in the development process
- **Continuous Validation**: Regular testing through CI/CD pipelines

## 2. Test Types and Organization

The platform uses a diverse set of test types organized primarily by architectural layer and scope. The main test directory (`/backend/app/tests/`) contains the following key subdirectories:

- **`/unit/`**: Contains unit tests validating individual components (e.g., domain models, service logic, utilities) in isolation, often using mocks and stubs. Subdirectories may further organize tests by layer (e.g., `unit/domain/`, `unit/application/`).
- **`/integration/`**: Contains integration tests validating the interaction between components (e.g., repositories with test databases, services with infrastructure).
- **`/e2e/`** (End-to-End): Contains tests validating complete features or workflows, simulating user interactions from the API boundary inwards. This corresponds to what might traditionally be called functional tests.
- **`/security/`**: Contains tests specifically focused on verifying security controls, access policies, and HIPAA compliance mechanisms (e.g., PHI sanitization, authentication checks).
- **`/api/`**: Contains tests specifically targeting the API layer (FastAPI routes), validating request/response contracts, input validation, and status codes. Often involves mocking the application layer beneath.
- **`/application/`**, **`/core/`**, **`/domain/`**, **`/infrastructure/`**: These directories often contain tests specific to the components within those architectural layers, potentially mixing unit and integration tests depending on the context. Their precise organization might overlap with `unit/` and `integration/`.
- **`/mocks/`**: Contains predefined mock objects and potentially reusable mocking utilities used across different tests.
- **`/fixtures/`**: Contains pytest fixtures used for setting up test data, dependencies, and common test states.
- **`/helpers/`**: Contains utility functions designed to simplify test setup or repetitive validation logic.
- **`/standalone/`**, **`/enhanced/`**: The exact purpose of these directories needs further clarification but likely holds specific test suites or experiments.

**Note:** Dedicated directories for `performance/` and `compliance/` tests, as sometimes found in standard structures, do not currently exist at the top level. Performance and compliance aspects are likely tested within `e2e/`, `security/`, or integration tests where relevant.

### 2.1. Unit Tests (Example Structure)

**Location**: Primarily `/backend/app/tests/unit/`, potentially organized by layer (e.g., `/backend/app/tests/unit/domain/`)

**Key Areas**: Domain model validation, Application service logic, Utility function behavior.

**Example** (*Illustrative, actual tests may be more complex*):
```python
# /backend/app/tests/unit/domain/test_digital_twin.py
def test_digital_twin_creation():
    # Arrange
    patient_id = UUID("00000000-0000-0000-0000-000000000001")

    # Act
    digital_twin = DigitalTwin.create(patient_id)

    # Assert
    assert digital_twin.patient_id == patient_id
    # ... other assertions
```

### 2.2. Integration Tests (Example Structure)

**Location**: Primarily `/backend/app/tests/integration/`

**Key Areas**: Repository implementations with test databases, API endpoints integrated with services, External service adapters.

**Example** (*Illustrative, actual tests may be more complex*):
```python
# /backend/app/tests/integration/test_patient_repository.py
async def test_patient_repository_create_and_find(test_db_session): # Using a fixture
    # Arrange
    repo = PatientRepository(db=test_db_session) # Dependency injection
    patient_data = {"name": "Test Patient", "date_of_birth": "1980-01-01"}

    # Act
    patient = await repo.create(patient_data)
    retrieved_patient = await repo.find_by_id(patient.id)

    # Assert
    assert retrieved_patient is not None
    # ... other assertions
```

### 2.3. End-to-End (E2E) / Functional Tests

**Location**: Primarily `/backend/app/tests/e2e/`

**Key Areas**: End-to-end user workflows via API calls, Business process validation, Feature completeness verification.

### 2.4. Security Tests

**Location**: Primarily `/backend/app/tests/security/`

**Key Areas**: Authentication/Authorization, PHI handling, Input validation/Output sanitization, Encryption checks.

**Example** (*Illustrative, actual tests may be more complex*):
```python
# /backend/app/tests/security/test_phi_sanitization.py
async def test_phi_redaction_in_logs(mock_logger): # Using mock/fixture
    # Arrange
    patient_with_phi = {"name": "John Doe", "ssn": "123-45-6789"}

    # Act
    # Simulate action that logs patient data
    log_output = get_captured_logs(mock_logger)

    # Assert
    assert "John Doe" not in log_output
    assert "123-45-6789" not in log_output
    assert "[REDACTED]" in log_output
```

### 2.5. Performance Tests (Current Status)

**Location**: Currently no dedicated `/performance/` directory. Performance aspects might be evaluated manually or via benchmarks integrated elsewhere.

### 2.6. Compliance Tests (Current Status)

**Location**: Currently no dedicated `/compliance/` directory. Compliance checks (e.g., HIPAA rules) are primarily integrated into `/security/` tests and potentially within unit/integration tests verifying specific controls (like audit logging).

## 3. Testing Tools and Frameworks

The platform uses the following testing tools and frameworks:

### 3.1. Primary Testing Frameworks

- **pytest**: Primary testing framework for all Python tests
- **pytest-asyncio**: For testing asynchronous code
- **pytest-cov**: For measuring test coverage
- **pytest-xdist**: For parallel test execution

### 3.2. Mocking and Fixtures

- **unittest.mock**: For mocking dependencies
- **pytest fixtures**: For test setup and dependency injection
- **factory_boy**: For generating test data

### 3.3. Security Testing Tools

- **OWASP ZAP**: For dynamic application security testing
- **Bandit**: For static security analysis
- **Safety**: For dependency vulnerability scanning

### 3.4. Performance Testing Tools

- **Locust**: For load and performance testing
- **pytest-benchmark**: For code performance benchmarking

## 4. Test Environment

### 4.1. Local Testing Environment

For local development and testing:

```bash
# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Run tests
pytest
```

### 4.2. CI/CD Testing

Testing in CI/CD pipelines:

- **GitHub Actions**: Automated test execution on push and pull requests
- **Stage-specific Testing**: Different test suites for development, staging, and production
- **Coverage Reports**: Test coverage tracking and reporting

## 5. Test Data Management

### 5.1. Test Data Sources

- **Generated Data**: Using factory_boy and Faker for realistic but non-PHI test data
- **Anonymized Data**: Sanitized and anonymized from production for specific tests
- **Edge Case Data**: Manually created data for boundary testing

### 5.2. Database Management for Tests

- **Test Databases**: Isolated databases for testing
- **Database Migrations**: Automated migration testing
- **Cleanup**: Automatic cleanup after tests

## 6. Best Practices

### 6.1. General Testing Principles

- **Arrange-Act-Assert**: Structure tests with clear setup, action, and validation
- **Single Responsibility**: Each test verifies one specific behavior
- **Independence**: Tests should not depend on other tests
- **Readability**: Tests should be clear and well-documented

### 6.2. Domain Testing

- Test domain entities for invariant enforcement
- Verify value object immutability
- Test domain service business logic
- Validate domain event generation

### 6.3. Application Layer Testing

- Test use case implementation
- Verify proper repository interactions
- Test command/query handlers
- Validate DTO transformations

### 6.4. Infrastructure Testing

- Test repository implementations
- Verify external service adapters
- Test database interactions
- Validate caching mechanisms

### 6.5. API Testing

- Test input validation
- Verify response formats
- Test error handling
- Validate authentication and authorization

### 6.6. Security Testing

- Test PHI protection mechanisms
- Verify audit logging
- Test access control enforcement
- Validate encryption implementation

### 6.7. Current Testing Patterns & Observations

Beyond the general best practices, the current test suite exhibits several common patterns:

- **Heavy Mocking/Patching**: Many tests, particularly unit and some integration tests, rely heavily on `unittest.mock` (or equivalent pytest mechanisms) to patch out dependencies like database interactions, external API calls, or even components from adjacent layers. This is often necessary for isolation but can sometimes lead to tests that don't fully represent real-world interactions.
- **Complex Fixtures**: Pytest fixtures located in `conftest.py` and the `/fixtures/` directory are extensively used to manage complex setup, such as initializing application instances, setting up test databases, creating mock services, and generating common test data.
- **Helper Functions**: The `/helpers/` directory contains utility functions frequently used to avoid repetition in test setup (e.g., creating authenticated test clients) or validation logic.
- **Potential Layer Bypassing**: Some tests, particularly those focused on specific logic deep within a layer, might directly instantiate and test classes without going through the full application stack or API layer, potentially using mocks to satisfy dependencies from outer layers. While efficient for targeted testing, this requires careful consideration to ensure integration points are covered elsewhere.

Understanding these patterns is crucial for navigating and contributing to the existing test suite.

## 7. Test Coverage

### 7.1. Coverage Targets

- **Domain Layer**: 95%+ code coverage
- **Application Layer**: 90%+ code coverage
- **Infrastructure Layer**: 85%+ code coverage
- **API Layer**: 90%+ code coverage
- **Security Components**: 100% code coverage

### 7.2. Critical Test Paths

High-priority test scenarios that must always pass:

- Patient data creation and retrieval
- Digital Twin state management
- Authentication and authorization
- PHI protection and sanitization
- Audit logging for sensitive operations

## 8. Troubleshooting and Debug

### 8.1. Common Test Issues

- **Database Connection Issues**: Verify test database configuration
- **Async Test Failures**: Ensure proper async/await usage
- **Mocking Problems**: Check mock setup and verification
- **Flaky Tests**: Identify and fix timing-dependent tests

### 8.2. Debug Strategies

- Use pytest's verbose mode: `pytest -v`
- Enable step debugging: `pytest --pdb`
- Debug specific tests: `pytest path/to/test.py::test_name`
- Print test coverage: `pytest --cov=app`

## 9. Current Test Status

### 9.1. Test Suite Health

Current test metrics:

- **Total Tests**: [Update Count] (Organized across `unit`, `integration`, `e2e`, `security`, `api`, etc.)
- **Overall Coverage**: [Update Percentage]% (Requires running coverage tool)
- **Passing Rate**: [Update Percentage]% (Requires running test suite)
- **Known Failing Tests**: See section 9.2

### 9.2. Known Test Issues / Gaps

Areas with currently failing, incomplete, or missing tests:

1.  Digital Twin prediction accuracy validation tests (if applicable).
2.  Some session timeout security tests (verify current status).
3.  **Lack of dedicated Performance test suite**: Performance under load needs systematic testing.
4.  **Lack of dedicated Compliance test suite**: While compliance aspects are tested, a focused suite might be beneficial.
5.  Complete end-to-end workflow tests covering complex user journeys.
6.  [Add any other known failing test categories from recent runs]

## 10. Testing Roadmap

Planned improvements to the testing strategy:

1.  Increase overall test coverage towards documented targets (Sec 7.1).
2.  Implement property-based testing where appropriate (e.g., for domain models).
3.  Enhance security testing, potentially with automated DAST/SAST tools integrated into CI.
4.  **Develop dedicated Performance test suite** (e.g., using Locust).
5.  **Develop dedicated Compliance test suite** mapped explicitly to HIPAA/regulatory requirements.
6.  Refactor complex tests to reduce reliance on excessive mocking where possible, favoring integration tests for cross-component validation.

---

This testing guide is a living document and will be updated as testing practices evolve and improve. Always refer to the latest version for current testing standards and practices.

Last Updated: 2025-04-20
