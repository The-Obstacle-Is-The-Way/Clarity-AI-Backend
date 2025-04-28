"""
Pytest configuration file for the application.

This module provides fixtures and configuration for testing the application.
"""

import logging
import sys
import os
import pytest
import asyncio
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Optional, AsyncGenerator, Generator, Callable
from unittest.mock import AsyncMock, MagicMock, patch
from httpx import AsyncClient, ASGITransport
from fastapi import Depends

# CRITICAL FIX: Prevent XGBoost namespace collision
# This ensures the test collection mechanism doesn't confuse our test directory
# with the actual XGBoost library
for key in list(sys.modules.keys()):
    if key.startswith('xgboost.') and ('conftest' in key or 'tests' in key):
        del sys.modules[key]

# Import test mocks first to ensure dependency issues are resolved
# This makes tests collectable even without all dependencies installed
from app.tests.unit.mocks import *

import json
import uuid
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import sessionmaker

# Updated import path to match codebase structure
from app.config.settings import Settings, get_settings
from pydantic import SecretStr, Field
from app.infrastructure.security.jwt.jwt_service import JWTService
from app.core.interfaces.services.jwt_service import IJwtService
from app.infrastructure.security.auth.authentication_service import AuthenticationService
from app.presentation.api.dependencies.auth import get_authentication_service
from app.infrastructure.database.models import Base

# --- Conditional Import for Pydantic Settings ---
_HAS_PYDANTIC_SETTINGS = False
try:
    from pydantic_settings import BaseSettings
    _HAS_PYDANTIC_SETTINGS = True
except ImportError:
    try:
        # Fallback for Pydantic v1 style
        from pydantic import BaseSettings as V1BaseSettings
    except ImportError:
        # If neither is found, create a dummy BaseSettings
        class V1BaseSettings: 
            pass 
# --- End Conditional Import --- 

# Set test environment variables early
os.environ["TESTING"] = "true"
os.environ["MOCK_DI_CONTAINERS"] = "true"
os.environ["NOVAMIND_SKIP_APP_INIT"] = "true"
os.environ["ENVIRONMENT"] = "test"

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create patchers for problematic modules early in test collection
# This prevents collection errors when importing app modules

@pytest.fixture(scope="session", autouse=True)
def mock_problematic_imports():
    """Mock problematic imports to prevent collection errors. Applied automatically.
    
    NOTE: Using autouse=True and session scope. Ensure this is appropriate.
    If mocks need to be function-scoped or applied differently, adjust scope/autouse.
    """
    # First, import the container module without actually using it
    # This ensures the module is loaded before we try to patch it
    import app.infrastructure.di.container
    
    # Now create patches for problematic modules
    patches = []
    
    # Directly patch the get_container function to return our mock
    mock_container = MagicMock()
    
    # Configure the mock container to return mock objects for any requested service
    def resolve_mock(*args, **kwargs):
        mock_service = MagicMock()
        # Make any async methods return AsyncMock
        mock_service.__call__ = AsyncMock(return_value=mock_service)
        return mock_service
    
    mock_container.resolve.side_effect = resolve_mock
    mock_container.get.side_effect = resolve_mock
    
    # Add a patch for the get_container function
    container_func_patch = patch("app.infrastructure.di.container.get_container", return_value=mock_container)
    container_func_patch.start()
    patches.append(container_func_patch)
    
    # Add a patch for the module-level container variable
    container_var_patch = patch("app.infrastructure.di.container.container", mock_container)
    container_var_patch.start()
    patches.append(container_var_patch)
    
    # Mock app.main to prevent it from initializing real services
    main_patch = patch("app.main.app")
    mock_app = main_patch.start()
    mock_app.dependency_overrides = {}
    patches.append(main_patch)
    
    # Import our mock DB module
    from app.tests.mocks.persistence_db_mock import AsyncSession, get_db_session as mock_get_db_session
    
    # Mock database session using our custom mock implementation
    db_session_patch = patch("app.infrastructure.persistence.sqlalchemy.config.database.get_db_session", mock_get_db_session)
    db_session_patch.start()
    patches.append(db_session_patch)
    
    # Mock persistence.db module import
    # Create a sys.modules entry for the missing module
    import sys
    if "app.infrastructure.persistence.db" not in sys.modules:
        import app.tests.mocks.persistence_db_mock as db_mock
        sys.modules["app.infrastructure.persistence.db"] = db_mock
    
    # Mock analytics service that's causing collection issues
    analytics_patch = patch("app.domain.services.analytics_service.AnalyticsService")
    analytics_patch.start()
    patches.append(analytics_patch)
    
    yield # Yield control to the test/fixture using this fixture
    
    # Clean up all patches
    for p in patches:
        p.stop()
    
    # Remove our mock module from sys.modules
    if "app.infrastructure.persistence.db" in sys.modules:
        if sys.modules["app.infrastructure.persistence.db"].__name__ == "app.tests.mocks.persistence_db_mock":
            del sys.modules["app.infrastructure.persistence.db"]

# Add a MockSettings class for tests that need to mock application settings
class MockSettings:
    """Mock Settings class for HIPAA compliance and security tests.
    
    This class provides a minimal implementation of the Settings class with sensible
    defaults for testing. It allows tests to override specific settings as needed.
    """
    
    def __init__(self, **overrides):
        # Base settings
        self.API_V1_STR = "/api/v1"
        self.TESTING = True
        self.DEBUG = True
        self.SECRET_KEY = SecretStr("test-secret-key-for-testing-only")
        self.ALGORITHM = "HS256"
        self.ACCESS_TOKEN_EXPIRE_MINUTES = 30
        self.ENCRYPTION_KEY = SecretStr("test-encryption-key-for-testing-only")
        self.ENCRYPTION_SALT = "test-salt-for-testing-only"
        self.DATABASE_URL = "sqlite+aiosqlite:///:memory:"
        self.DATABASE_ENCRYPTION_ENABLED = True
        self.ENABLE_PHI_AUDITING = True
        self.PHI_EXCLUDE_PATHS = ["/docs", "/openapi.json", "/health"]
        self.BACKEND_CORS_ORIGINS = ["http://localhost:3000", "http://localhost:8000"]
        
        # ML Settings namespace 
        self.ml = MagicMock()
        self.ml.mentallama = MagicMock()
        self.ml.pat = MagicMock()
        self.ml.xgboost = MagicMock()
        
        # Apply any overrides passed to the constructor
        for key, value in overrides.items():
            setattr(self, key, value)

    # Use the imported BaseSettings if available for potential type checking downstream
    # This part is less critical as MockSettings doesn't inherit, but good practice.
    if _HAS_PYDANTIC_SETTINGS:
        # If needed for type hinting or checks later
        _BaseSettingsRef = BaseSettings 
    else:
        _BaseSettingsRef = V1BaseSettings


@pytest_asyncio.fixture(scope="session")
async def async_client(event_loop) -> AsyncGenerator[AsyncClient, None]:
    """
    Provides an asynchronous test client for the FastAPI application.
    Configures test-specific settings and overrides dependencies like JWTService.
    """
    # --- Define Test Settings ---
    def get_test_settings() -> Settings:
         # Return a Settings instance configured for tests
         # Ensure necessary imports (Settings, SecretStr) are available
         return Settings(
            TESTING=True,
            DATABASE_URL=TEST_DATABASE_URL,
            JWT_SECRET_KEY=SecretStr(TEST_SECRET), # Use consistent secret
            SECRET_KEY=SecretStr(TEST_SECRET), # Also set fallback secret key
            JWT_ALGORITHM="HS256",
            ACCESS_TOKEN_EXPIRE_MINUTES=15,
            JWT_REFRESH_TOKEN_EXPIRE_DAYS=7,
            JWT_ISSUER="test-issuer",
            JWT_AUDIENCE="test-audience",
            BACKEND_CORS_ORIGINS=["http://localhost:3000", "http://testserver"],
            # Add other necessary test settings if required
        )

    # --- Define Test JWT Service ---
    def get_test_jwt_service(settings: Settings = Depends(get_test_settings)) -> IJwtService:
        # Initialize JWTService with the test settings
        # Pass None for user_repository as it's likely not needed for basic token ops in tests
        # If user repo IS needed by JWT service logic you intend to test via this mock,
        # provide a mock repository instead of None.
        return JWTService(settings=settings, user_repository=None) # Use None or a mock repo

    # --- Define Test Authentication Service Mock ---
    def get_mock_authentication_service() -> AuthenticationService:
        mock_auth_service = AsyncMock(spec=AuthenticationService)

        # Configure the mock validate_token method
        async def mock_validate_token(token: str) -> tuple[User, list[str]] | None:
            # Basic validation logic for tests:
            # If token is "valid-token", return a mock user and roles.
            # Otherwise, return None (or raise specific exceptions if needed).
            # You can customize this based on test needs.
            if token and token != "invalid-token": # Check for non-empty token
                 # Create a mock User object or use a simple dictionary/dataclass
                 mock_user = MagicMock(spec=User)
                 mock_user.id = "test-user-id"
                 mock_user.username = "testuser"
                 mock_user.email = "test@example.com"
                 # Add other essential User attributes as needed by your application logic
                 
                 # Define roles based on token or test context
                 # This might need adjustment based on how your actual validate_token works
                 roles = ["patient"] # Default role for testing
                 if token == "provider-token": # Example for different role
                     roles = ["provider", "clinician"]
                 return (mock_user, roles)
            return None # Token is invalid or missing

        mock_auth_service.validate_token = mock_validate_token
        # Mock other AuthenticationService methods if they are called during the request lifecycle
        # Example: mock_auth_service.get_user_by_id = AsyncMock(return_value=...)

        return mock_auth_service


    # --- Define Dependency Overrides ---
    dependency_overrides = {
        get_settings: get_test_settings,
        IJwtService: get_test_jwt_service,
        get_authentication_service: get_mock_authentication_service
    }
    
    from app.main import create_application
    
    app = create_application(dependency_overrides=dependency_overrides)

    # Correct initialization using ASGITransport
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        yield client

# Fixtures for generating tokens using the *correct* test secret
# Moved from integration/conftest.py for potential wider use, or keep it there if preferred.
_TEST_SECRET_KEY_FOR_FIXTURES = "testsecret" # Ensure this matches the override

@pytest.fixture(scope="session")
def test_settings_for_token_gen() -> Settings:
    """Provides Settings configured with the correct test secret key for token generation fixtures."""
    # Using MagicMock might be simpler if only JWT settings are needed by JWTService
    mock_settings = MagicMock()
    mock_settings.JWT_SECRET_KEY = SecretStr(_TEST_SECRET_KEY_FOR_FIXTURES)
    mock_settings.JWT_ALGORITHM = "HS256"
    mock_settings.ACCESS_TOKEN_EXPIRE_MINUTES = 60 # Longer expiry for tests
    mock_settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS = 1
    mock_settings.JWT_ISSUER = "test-issuer"
    mock_settings.JWT_AUDIENCE = "test-audience"
    # Add .get_secret_value() if JWTService expects the raw string
    # mock_settings.JWT_SECRET_KEY.get_secret_value.return_value = _TEST_SECRET_KEY_FOR_FIXTURES
    return mock_settings

@pytest.fixture(scope="session")
def test_jwt_service(test_settings_for_token_gen: Settings) -> JWTService:
    """Provides a JWTService instance configured for generating test tokens."""
    # Pass None for user_repository if it's not needed or mock it
    return JWTService(settings=test_settings_for_token_gen, user_repository=None)


# Fixture to generate a valid token dynamically
@pytest_asyncio.fixture(scope="function") # Function scope for fresh tokens
async def get_valid_auth_headers(test_jwt_service: JWTService) -> Dict[str, str]:
    """Generates valid authentication headers with a fresh token for integration tests."""
    user_data = {"sub": "test-integration-user", "roles": ["patient"]} # Example user
    token = await test_jwt_service.create_access_token(data=user_data)
    return {"Authorization": f"Bearer {token}"}

@pytest_asyncio.fixture(scope="function")
async def get_valid_provider_auth_headers(test_jwt_service: JWTService) -> Dict[str, str]:
    """Generates valid authentication headers for a provider role."""
    user_data = {"sub": "test-provider-user", "roles": ["provider", "clinician"]}
    token = await test_jwt_service.create_access_token(data=user_data)
    return {"Authorization": f"Bearer {token}"}

# Remove the old jwt_service fixture defined earlier if it conflicts or is redundant
# @pytest.fixture
# def jwt_service(): ...


# ... rest of conftest.py ...
# (Ensure provider_token_headers and patient_token_headers fixtures below are updated or removed
# if they conflict with the new get_valid_auth_headers fixtures)

@pytest.fixture
def provider_token_headers(get_valid_provider_auth_headers: Dict[str, str]): # Depend on the new fixture
    """Provides valid auth headers for a provider role."""
    # Optionally add more specific headers if needed
    return get_valid_provider_auth_headers

@pytest.fixture
def patient_token_headers(get_valid_auth_headers: Dict[str, str]): # Depend on the new fixture
    """Provides valid auth headers for a patient role."""
    # Optionally add more specific headers if needed
    return get_valid_auth_headers

@pytest.fixture
def test_patient():
    """Create a test patient object for testing.
    
    This fixture creates a properly structured Patient domain entity following
    the required structure with Name and ContactInfo value objects.
    
    Returns:
        Patient: A properly structured Patient domain entity
    """
    from app.domain.entities.patient import Patient
    from app.domain.value_objects.name import Name
    from app.domain.value_objects.contact_info import ContactInfo
    
    # Generate a unique patient ID
    patient_id = str(uuid.uuid4())
    
    # Create using proper value objects for Name and ContactInfo
    # Respecting the structure without direct attributes and avoiding extra_data
    patient = Patient(
        id=patient_id,
        name=Name(first_name="Test", last_name="Patient"),
        contact_info=ContactInfo(email="test@example.com", phone="555-123-4567"),
        date_of_birth="1980-01-01",  # Using String for date to avoid SQLite binding issues
        medical_record_number="MRN-TEST-12345",
        created_by=None  # Set to None to bypass foreign key constraint
    )
    
    return patient


@pytest.fixture
def mock_patient_payload():
    """Create a mock patient payload for API tests.
    
    This fixture provides a properly structured dictionary that can be used
    to create or update a Patient through the API.
    
    Returns:
        Dict[str, Any]: A structured patient payload
    """
    patient_id = str(uuid.uuid4())
    return {
        "id": patient_id,
        "name": {
            "first_name": "Test", 
            "last_name": "Patient"
        },
        "contact_info": {
            "email": "test@example.com", 
            "phone": "555-123-4567"
        },
        "date_of_birth": "1980-01-01",
        "medical_record_number": "MRN-TEST-12345"
    }


@pytest.fixture
def mock_get_patient_by_id():
    """Create a mock for the get_patient_by_id service function.
    
    This fixture provides a mock that can be used to override the
    patient repository's get_by_id method for testing.
    
    Returns:
        MagicMock: A pre-configured mock for get_patient_by_id
    """
    from unittest.mock import MagicMock
    from app.domain.exceptions.patient_exceptions import PatientNotFoundError
    
    mock = MagicMock()
    
    # Configure the mock to return a test patient when called with a valid ID
    async def side_effect(patient_id: str):
        if patient_id == "not-found-id":
            raise PatientNotFoundError(f"Patient with ID {patient_id} not found")
        return test_patient()
    
    mock.side_effect = side_effect
    return mock


@pytest.fixture
def generate_token(jwt_service):
    """Generate JWT tokens for testing.
    
    This fixture provides a function that can generate tokens with
    custom claims for testing various scenarios.
    
    Returns:
        Callable: A function that generates tokens
    """
    async def _generate_token(claims: Dict[str, Any]) -> str:
        subject = claims.get("sub", str(uuid.uuid4()))
        roles = claims.get("roles", ["patient"])
        token = await jwt_service.create_access_token(subject=subject, roles=roles)
        return token
    
    return _generate_token


@pytest.fixture
def sample_rule():
    """Create a sample biometric alert rule for testing.
    
    This fixture provides a properly structured AlertRule object for use
    in biometric alert endpoint tests.
    
    Returns:
        AlertRule: A sample alert rule
    """
    from app.domain.services.biometric_event_processor import AlertRule, AlertPriority
    from datetime import datetime, timezone
    
    # Create with proper structure following domain entity requirements
    rule = AlertRule(
        id=str(uuid.uuid4()),
        name="Test Heart Rate Alert",
        description="Alert when heart rate exceeds threshold",
        patient_id=str(uuid.uuid4()),
        provider_id=str(uuid.uuid4()),
        condition="heart_rate > 100",
        priority=AlertPriority.MEDIUM,
        is_active=True,
        notification_channels=["email", "sms"],
        created_at=datetime.now(timezone.utc).isoformat(),
        updated_at=datetime.now(timezone.utc).isoformat(),
        triggered_count=0,
        last_triggered=None,
        min_interval_minutes=15
    )
    
    return rule


@pytest.fixture
def mock_biometric_event_processor():
    """Create a mock BiometricEventProcessor for testing.
    
    This fixture provides a mock instance of the BiometricEventProcessor
    with pre-configured return values for common methods.
    
    Returns:
        MagicMock: A mock biometric event processor
    """
    from unittest.mock import MagicMock
    
    mock = MagicMock()
    mock.register_rule.return_value = True
    mock.unregister_rule.return_value = True
    mock.process_event.return_value = []
    
    return mock


@pytest.fixture
def mock_current_user():
    """Create a mock user object for testing.
    
    This fixture provides a mock user object that can be used for
    authentication and authorization in tests.
    
    Returns:
        MagicMock: A mock user object
    """
    from unittest.mock import MagicMock
    
    user = MagicMock()
    user.id = str(uuid.uuid4())
    user.role = "provider"
    user.username = "test_provider"
    user.is_active = True
    
    return user


@pytest.fixture
def mock_rule_repository():
    """Create a mock rule repository for biometric alert testing.
    
    This fixture provides a comprehensive mock of the alert rule repository
    with pre-configured return values for all required methods.
    
    Returns:
        MagicMock: A mock rule repository
    """
    from unittest.mock import MagicMock
    from app.domain.exceptions import EntityNotFoundError
    
    repo = MagicMock()
    
    # Define behavior for common methods
    async def get_rules_mock(*args, **kwargs):
        return [sample_rule()]
    
    async def get_rule_by_id_mock(rule_id):
        if rule_id == "not-found-id":
            raise EntityNotFoundError(f"Rule with ID {rule_id} not found")
        return sample_rule()
    
    async def create_rule_mock(rule_data):
        return sample_rule()
    
    async def update_rule_mock(rule_id, rule_data):
        if rule_id == "not-found-id":
            raise EntityNotFoundError(f"Rule with ID {rule_id} not found")
        return sample_rule()
    
    async def delete_rule_mock(rule_id):
        if rule_id == "not-found-id":
            raise EntityNotFoundError(f"Rule with ID {rule_id} not found")
        return True
    
    # Configure the mock's methods
    repo.get_rules.side_effect = get_rules_mock
    repo.get_rule_by_id.side_effect = get_rule_by_id_mock
    repo.create_rule.side_effect = create_rule_mock
    repo.update_rule.side_effect = update_rule_mock
    repo.delete_rule.side_effect = delete_rule_mock
    repo.get_active_rules_for_patient.return_value = [sample_rule()]
    
    return repo


@pytest.fixture
def mock_clinical_rule_engine():
    """Create a mock clinical rule engine for testing.
    
    This fixture provides a mock implementation of the clinical rule engine
    with predefined templates and evaluation logic for testing.
    
    Returns:
        MagicMock: A mock clinical rule engine
    """
    from unittest.mock import MagicMock
    
    engine = MagicMock()
    
    # Define rule templates
    templates = [
        {
            "id": "template-1",
            "name": "High Heart Rate",
            "description": "Alert when heart rate exceeds threshold",
            "condition_template": "heart_rate > {threshold}",
            "default_values": {"threshold": 100},
            "parameters": [
                {
                    "name": "threshold",
                    "type": "integer",
                    "min": 60,
                    "max": 200,
                    "description": "Heart rate threshold in bpm"
                }
            ],
            "default_priority": "MEDIUM",
            "data_type": "heart_rate"
        },
        {
            "id": "template-2",
            "name": "Low Blood Oxygen",
            "description": "Alert when blood oxygen falls below threshold",
            "condition_template": "blood_oxygen < {threshold}",
            "default_values": {"threshold": 95},
            "parameters": [
                {
                    "name": "threshold",
                    "type": "integer",
                    "min": 80,
                    "max": 100,
                    "description": "Blood oxygen threshold in percentage"
                }
            ],
            "default_priority": "HIGH",
            "data_type": "blood_oxygen"
        }
    ]
    
    # Configure behavior
    engine.get_rule_templates.return_value = templates
    engine.create_rule_from_template.return_value = sample_rule()
    engine.evaluate_condition.return_value = True
    
    return engine


@pytest.fixture
def mock_alert_repository():
    """Create a mock alert repository for testing.
    
    This fixture provides a mock implementation of the alert repository
    with predefined behavior for various methods.
    
    Returns:
        MagicMock: A mock alert repository
    """
    from unittest.mock import MagicMock
    from app.domain.exceptions import EntityNotFoundError
    
    repo = MagicMock()
    
    # Configure basic behavior
    async def get_alerts_mock(*args, **kwargs):
        # Handle filters if present
        patient_id = kwargs.get("patient_id")
        if patient_id == "no-alerts-patient":
            return []
        return [sample_alert(sample_rule(), sample_data_point())] 
    
    async def get_alert_by_id_mock(alert_id):
        if alert_id == "not-found-id":
            raise EntityNotFoundError(f"Alert with ID {alert_id} not found")
        return sample_alert(sample_rule(), sample_data_point())
    
    async def acknowledge_alert_mock(alert_id, user_id):
        if alert_id == "not-found-id":
            raise EntityNotFoundError(f"Alert with ID {alert_id} not found")
        alert = sample_alert(sample_rule(), sample_data_point())
        alert.acknowledged_by = user_id
        alert.acknowledged_at = datetime.now(timezone.utc).isoformat()
        return alert
    
    # Assign behaviors
    repo.get_alerts.side_effect = get_alerts_mock
    repo.get_alert_by_id.side_effect = get_alert_by_id_mock
    repo.acknowledge_alert.side_effect = acknowledge_alert_mock
    
    return repo


@pytest.fixture
def sample_data_point():
    """Create a sample biometric data point for testing.
    
    This fixture provides a properly structured BiometricDataPoint
    for testing alert processing logic.
    
    Returns:
        BiometricDataPoint: A sample data point
    """
    from app.domain.entities.biometric_twin import BiometricDataPoint
    from datetime import datetime, timezone
    
    # Create a data point with all common biometric measurements
    data_point = BiometricDataPoint(
        id=str(uuid.uuid4()),
        patient_id=str(uuid.uuid4()),
        device_id="test-device-123",
        timestamp=datetime.now(timezone.utc).isoformat(),
        heart_rate=110,
        blood_pressure={"systolic": 120, "diastolic": 80},
        blood_oxygen=98,
        temperature=37.0,
        respiratory_rate=16,
        step_count=1000,
        sleep_data={"duration": 480, "efficiency": 0.92},
        data_type="heart_rate",
        source="test"
    )
    
    return data_point


@pytest.fixture
def sample_alert(sample_rule, sample_data_point):
    """Create a sample biometric alert for testing.
    
    This fixture creates a properly structured BiometricAlert object
    using the provided rule and data point.
    
    Returns:
        BiometricAlert: A sample biometric alert
    """
    from app.domain.services.biometric_event_processor import BiometricAlert
    from datetime import datetime, timezone
    
    # Create an alert with proper structure
    alert = BiometricAlert(
        id=str(uuid.uuid4()),
        rule_id=sample_rule.id,
        patient_id=sample_rule.patient_id,
        provider_id=sample_rule.provider_id,
        data_point_id=sample_data_point.id,
        triggered_at=datetime.now(timezone.utc).isoformat(),
        priority=sample_rule.priority,
        message=f"Alert: {sample_rule.name} triggered",
        data_value=sample_data_point.heart_rate,
        data_type="heart_rate",
        acknowledged=False,
        acknowledged_by=None,
        acknowledged_at=None,
        notification_status={"email": "sent", "sms": "pending"}
    )
    
    return alert

@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for each test session."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    yield loop
    loop.close()


@pytest.fixture
def client(async_client):
    """Create a TestClient instance for API security tests.
    
    This fixture provides a standard client name expected by the security tests.
    It wraps the async_client fixture to maintain compatibility with test modules
    that use the 'client' fixture name.
    
    Returns:
        AsyncClient: An async client for testing
    """
    return async_client


@pytest.fixture
def mock_db_session():
    """Create a mock database session for security tests.
    
    This fixture creates a mock session that simulates database operations
    without actually connecting to a database.
    
    Returns:
        MagicMock: A mock database session
    """
    from unittest.mock import MagicMock
    from app.tests.security.utils.test_mocks import MockAsyncSession
    
    return MockAsyncSession()


@pytest.fixture
def mock_encryption_service():
    """Create a mock encryption service for security tests.
    
    This fixture provides a mock implementation of the encryption service
    used in security testing.
    
    Returns:
        MagicMock: A mock encryption service
    """
    from app.tests.security.utils.test_mocks import MockEncryptionService
    
    return MockEncryptionService()


@pytest.fixture
def mock_rbac():
    """Create a mock role-based access control service for security tests.
    
    This fixture provides a mock implementation of the RBAC service
    used to check permissions in security tests.
    
    Returns:
        RoleBasedAccessControl: A mock RBAC service
    """
    from app.tests.security.utils.test_mocks import RoleBasedAccessControl
    
    return RoleBasedAccessControl()


@pytest.fixture
def mock_entity_factory():
    """Create a mock entity factory for security tests.
    
    This fixture provides a mock implementation of the entity factory
    used to create test entities in security tests.
    
    Returns:
        MockEntityFactory: A mock entity factory
    """
    from app.tests.security.utils.test_mocks import MockEntityFactory
    
    return MockEntityFactory()


@pytest.fixture
def mock_phi_service():
    """Create a mock PHI service for HIPAA compliance tests.
    
    This fixture provides a mock implementation of the PHI detection and
    sanitization service used in HIPAA compliance tests.
    
    Returns:
        MagicMock: A mock PHI service
    """
    from unittest.mock import MagicMock
    from app.tests.security.utils.test_mocks import PHIRedactionService
    
    return PHIRedactionService()

@pytest_asyncio.fixture(scope="function")
async def setup_database():
    """
    Set up the test database with required tables and test users.
    
    This fixture ensures that the test database is properly initialized
    before each test function runs.
    """
    # Import our standardized test database initializer - this is now our single source of truth for test database setup
    from app.tests.integration.utils.test_db_initializer import (
        get_test_db_session, 
        TEST_USER_ID, 
        TEST_CLINICIAN_ID,
        TestUser,
        TestPatient
    )
    
    # Use our standardized test database initializer to set up the test database
    logger.info("[Fixture setup_database] Using standardized test_db_initializer")
    
    # Simply yield and continue with tests - no actual setup needed here
    # The test_db_session fixture in individual tests will handle table creation
    yield
    
    # No teardown needed here - each test manages its own session via test_db_session

@pytest_asyncio.fixture(scope="function")
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Create an isolated database session for each test function with test users.

    This fixture uses the standardized test database initializer to ensure:
    1. The database has the correct schema
    2. Test users exist for foreign key relationships
    3. Each test runs in its own transaction that is rolled back after the test

    Yields:
        AsyncSession: SQLAlchemy async session with test users created
    """
    # Import our standardized test database initializer
    from app.tests.integration.utils.test_db_initializer import get_test_db_session
    
    # Use the standardized initializer to get a session
    async for session in get_test_db_session():
        yield session
        # The get_test_db_session generator handles cleanup and rollback

@pytest.fixture
def mock_encryption_service():
    """
    Create a proper mock encryption service for testing.
    
    Returns:
        MockEncryptionService: An encryption service with real encryption functionality
    """
    from app.tests.security.utils.test_mocks import MockEncryptionService
    
    # Create a mock encryption service with a fixed test key for deterministic results
    service = MockEncryptionService(direct_key='YDK6UZeOqpHeiU33a3HVt_FWdVh9Z2LtQZZU-C1LD1E=')
    
    # For backward compatibility with older tests using the MagicMock approach
    service.encrypt_phi_field = service.encrypt_field
    service.decrypt_phi_field = service.decrypt_field
    service.encrypt_patient_data = service.encrypt_dict
    service.decrypt_patient_data = service.decrypt_dict
    service.is_hipaa_compliant = True
    
    return service
