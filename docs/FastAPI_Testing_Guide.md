# FastAPI Testing Guide

## Testing Architecture

The Clarity AI Backend implements a comprehensive testing strategy with multiple test types:

1. **Unit Tests** (`app/tests/unit/`): Test individual functions and classes in isolation
2. **Integration Tests** (`app/tests/integration/`): Test components working together
3. **API Tests** (`app/tests/api/`): Test API endpoints through HTTP requests
4. **End-to-End Tests** (`app/tests/e2e/`): Test complete workflows

## Test Configuration

### `conftest.py`

The main test configuration is in `app/tests/conftest.py`, which provides:

1. Pytest fixtures for test dependencies
2. In-memory SQLite database configuration
3. Test client setup
4. Authentication mocking
5. Mock service implementations

Key fixtures include:

```python
# Create a test application with in-memory database
@pytest.fixture
def app_instance(test_settings):
    app = create_application(
        settings_override=test_settings,
        include_test_routers=True,
        disable_audit_middleware=True
    )
    return app

# Create a test client with authentication
@pytest_asyncio.fixture
async def authenticated_client(app_instance, test_user):
    # Create a client with authentication token
    async with AsyncClient(app=app_instance, base_url="http://test") as client:
        # Add authentication token
        client.headers["Authorization"] = f"Bearer {test_user.token}"
        yield client
```

## Database Testing

### In-Memory Database

Tests use an in-memory SQLite database with auto-creating tables:

```python
# In conftest.py
@pytest.fixture(scope="session")
def test_settings():
    """Create test application settings."""
    return Settings(
        DATABASE_URL="sqlite+aiosqlite:///:memory:",
        # Other test settings...
    )
```

### Database Fixtures

Test data fixtures are provided in `app/tests/fixtures/`:

```python
@pytest_asyncio.fixture
async def test_patient(db_session):
    """Create a test patient in the database."""
    patient = PatientModel(
        id=uuid4(),
        # Patient attributes...
    )
    db_session.add(patient)
    await db_session.commit()
    return patient
```

## API Testing

### Test Client

API tests use HTTPX's `AsyncClient` to make HTTP requests:

```python
async def test_get_patient(authenticated_client, test_patient):
    response = await authenticated_client.get(f"/api/v1/patients/{test_patient.id}")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == str(test_patient.id)
```

### Testing Authenticated Endpoints

For testing authenticated endpoints:

1. Use the `authenticated_client` fixture which includes a JWT token
2. Override authentication dependencies for specific test cases
3. Mock permission checks for different scenarios

```python
# Override authentication for specific tests
app.dependency_overrides[get_current_user] = lambda: test_admin_user
```

## Mocking

### Service Mocking

Mock implementations are provided in `app/tests/mocks/`:

```python
class MockXGBoostService(XGBoostServiceInterface):
    async def predict_risk(self, patient_id, risk_type, features):
        # Return test prediction data
        return {
            "risk_score": 0.75,
            "risk_factors": {"factor1": 5, "factor2": 3}
        }
```

### Dependency Overrides

Override dependencies for testing:

```python
@pytest.fixture
def mock_services(app_instance):
    # Override service dependencies with mocks
    app_instance.dependency_overrides[get_xgboost_service] = lambda: MockXGBoostService()
    # Add more overrides as needed
    yield
    # Clean up overrides after test
    app_instance.dependency_overrides = {}
```

## Common Testing Patterns

### Testing Request Validation

Test invalid inputs to ensure validation:

```python
async def test_invalid_input(client):
    response = await client.post(
        "/api/v1/xgboost/risk-prediction",
        json={"invalid_data": "missing_required_fields"}
    )
    assert response.status_code == 422  # Unprocessable Entity
```

### Testing Error Responses

Test error handling for different scenarios:

```python
async def test_not_found_error(authenticated_client):
    response = await authenticated_client.get("/api/v1/patients/non-existent-id")
    assert response.status_code == 404
    data = response.json()
    assert "detail" in data
```

## Common Pitfalls and Solutions

### 1. Query Parameter Issues

**Problem**: Tests fail with 422 errors due to missing query parameters.

**Solution**: Include all required query parameters, even if they seem optional:

```python
# If the endpoint has a **kwargs parameter:
response = await client.post("/api/v1/endpoint?kwargs={}", json=data)
```

### 2. Data Type Validation Errors

**Problem**: Tests fail with validation errors due to incorrect data types.

**Solution**: Ensure mock data matches schema types exactly:

```python
# Incorrect - strings instead of numbers:
mock_data = {"score": "5", "factors": {"severity": "3"}}

# Correct - numbers as required by schema:
mock_data = {"score": 5, "factors": {"severity": 3}}
```

### 3. Middleware Interference

**Problem**: Middleware causes test failures (e.g., audit logging, rate limiting).

**Solution**: Disable problematic middleware during tests:

```python
# In test fixture
app = create_application(
    settings_override=test_settings,
    disable_audit_middleware=True,
    # Other flags to disable middleware
)
```

### 4. Session Management

**Problem**: Database session not closed properly, leading to resource warnings.

**Solution**: Use async context managers to ensure proper cleanup:

```python
@pytest_asyncio.fixture
async def db_session():
    """Provide a clean database session for each test."""
    async with AsyncSession(engine) as session:
        yield session
        # Session is automatically closed after the test
```

### 5. Async Test Debugging

**Problem**: Async tests are difficult to debug.

**Solution**: Use explicit awaits and better error messages:

```python
async def test_with_better_errors(client):
    response = await client.get("/api/v1/endpoint")
    
    # Better error messages with context
    assert response.status_code == 200, f"Expected 200 but got {response.status_code}. Response: {response.text}"
```

## Performance Testing

For performance testing:

1. Use `pytest-benchmark` to measure endpoint performance
2. Disable logging and audit middleware for accurate measurements
3. Test with realistic database load

```python
@pytest.mark.benchmark
async def test_endpoint_performance(benchmark, client):
    result = await benchmark(client.get, "/api/v1/health")
    assert result.status_code == 200
```

## Security Testing

For security testing:

1. Test authentication bypass scenarios
2. Verify input validation for security issues
3. Test authorization boundaries
4. Verify sensitive data handling

## Continuous Integration

Tests are configured to run in CI with:

1. GitHub Actions workflow
2. Containerized test environment
3. Parallel test execution
4. Test coverage reporting 