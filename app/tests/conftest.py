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
from typing import Dict, Any, List, Optional, AsyncGenerator, Generator, Callable, Tuple
from unittest.mock import AsyncMock, MagicMock, patch
from httpx import AsyncClient, ASGITransport
from fastapi import Depends, FastAPI

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
from app.core.services.ml.xgboost.interface import XGBoostInterface, ModelType
from app.infrastructure.persistence.sqlalchemy.config.database import Database
from app.presentation.middleware.authentication_middleware import AuthenticationMiddleware
from app.infrastructure.security.rate_limiting.rate_limiter import get_rate_limiter
from app.main import create_application # Import create_application
from app.domain.services.analytics_service import AnalyticsService # Import AnalyticsService
from app.infrastructure.di.container import get_container # Import get_container
from app.domain.entities.user import User # Import User
from app.domain.enums.role import Role # Import Role
from app.domain.repositories.user_repository import UserRepository # Ensure imported

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
os.environ["NOVAMIND_SKIP_APP_INIT"] = "true"
os.environ["ENVIRONMENT"] = "test"

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create patchers for problematic modules early in test collection
# This prevents collection errors when importing app modules

@pytest.fixture(scope="session", autouse=True)
def mock_problematic_imports():
    """Mock problematic imports to prevent collection errors. Applied automatically."""
    patches = []
    # Mock database session getter for collection
    from app.tests.mocks.persistence_db_mock import AsyncSession, get_db_session as mock_get_db_session
    db_session_patch = patch(
        "app.infrastructure.persistence.sqlalchemy.config.database.get_db_session",
        mock_get_db_session
    )
    db_session_patch.start()
    patches.append(db_session_patch)
    # Ensure persistence.db module is mocked for collection
    import sys
    if "app.infrastructure.persistence.db" not in sys.modules:
        import app.tests.mocks.persistence_db_mock as db_mock
        sys.modules["app.infrastructure.persistence.db"] = db_mock
    yield
    # Clean up patches
    for p in patches:
        p.stop()
    # Remove mock module if present
    if "app.infrastructure.persistence.db" in sys.modules and \
       sys.modules["app.infrastructure.persistence.db"].__name__ == "app.tests.mocks.persistence_db_mock":
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

# --- Helper Functions / Mock Factories (Module Level) ---

# Factory for Mock User Repository (Moved to Module Level)
def get_mock_user_repository() -> UserRepository:
    mock_repo = AsyncMock(spec=UserRepository)
    async def mock_get_by_id(user_id: uuid.UUID) -> Optional[MagicMock]:
        # Return a mock user based on common test IDs used in token generation
        user_id_str = str(user_id)
        mock_user = MagicMock(spec=User) # Using User domain entity spec
        mock_user.id = user_id
        mock_user.is_active = True
        mock_user.hashed_password = "$2b$12$EixZaYVK1fsbw1ZfbX3RU.II9.eGCwJoF1732K/i54e9QaJIX3fOC" # Example hash for 'password'

        if user_id_str == "test-integration-user": # From get_valid_auth_headers token 'sub'
             mock_user.username = "testuser"
             mock_user.email = "test@example.com"
             mock_user.roles = [Role.PATIENT] # Use Role enum
             logger.debug(f"MockUserRepository: Found user {user_id_str}")
             return mock_user
        elif user_id_str == "test-provider-user": # From get_valid_provider_auth_headers token 'sub'
             mock_user.username = "testprovider"
             mock_user.email = "provider@example.com"
             mock_user.roles = [Role.PROVIDER, Role.CLINICIAN] # Use Role enum
             logger.debug(f"MockUserRepository: Found user {user_id_str}")
             return mock_user
        logger.warning(f"MockUserRepository: User ID {user_id_str} not found in mock setup.")
        return None # Simulate user not found for unexpected IDs

    mock_repo.get_by_id = mock_get_by_id

    async def mock_get_by_username(username: str) -> Optional[MagicMock]:
         if username == "testuser":
             mock_user = MagicMock(spec=User)
             mock_user.id = uuid.UUID("test-integration-user") # Use consistent ID
             mock_user.username = username
             mock_user.is_active = True
             mock_user.hashed_password = "$2b$12$EixZaYVK1fsbw1ZfbX3RU.II9.eGCwJoF1732K/i54e9QaJIX3fOC" # Example hash for 'password'
             mock_user.roles = [Role.PATIENT]
             logger.debug(f"MockUserRepository: Found user by username {username}")
             return mock_user
         elif username == "test_provider": # Match username used in test_auth_endpoints
             mock_user = MagicMock(spec=User)
             mock_user.id = uuid.UUID("test-provider-user") # Use consistent ID
             mock_user.username = username
             mock_user.is_active = True
             mock_user.hashed_password = "$2b$12$EixZaYVK1fsbw1ZfbX3RU.II9.eGCwJoF1732K/i54e9QaJIX3fOC" # Example hash for 'password'
             mock_user.roles = [Role.PROVIDER, Role.CLINICIAN]
             logger.debug(f"MockUserRepository: Found user by username {username}")
             return mock_user
         logger.warning(f"MockUserRepository: User username {username} not found in mock setup.")
         return None
    mock_repo.get_by_username = mock_get_by_username

    return mock_repo

# --- Fixtures --- 

@pytest.fixture(scope="session", autouse=True)
def mock_problematic_imports():
    """Mock problematic imports to prevent collection errors. Applied automatically."""
    patches = []
    # Patch get_db_session to use a mock session for collection
    from app.tests.mocks.persistence_db_mock import get_db_session as mock_get_db_session
    db_session_patch = patch(
        "app.infrastructure.persistence.sqlalchemy.config.database.get_db_session",
        mock_get_db_session
    )
    db_session_patch.start()
    patches.append(db_session_patch)
    # Ensure persistence.db module is mocked for collection
    import sys
    if "app.infrastructure.persistence.db" not in sys.modules:
        import app.tests.mocks.persistence_db_mock as db_mock
        sys.modules["app.infrastructure.persistence.db"] = db_mock
    yield
    # Clean up patches
    for p in patches:
        p.stop()
    # Remove mock module if present
    if "app.infrastructure.persistence.db" in sys.modules and \
       sys.modules["app.infrastructure.persistence.db"].__name__ == "app.tests.mocks.persistence_db_mock":
        del sys.modules["app.infrastructure.persistence.db"]


@pytest_asyncio.fixture(scope="session")
async def async_client(event_loop, mock_xgboost_service: AsyncMock, test_jwt_service: JWTService) -> AsyncGenerator[AsyncClient, None]:
    """
    Provides an asynchronous test client using the main application factory.
    Applies necessary overrides DIRECTLY TO THE GLOBAL CONTAINER before app creation.
    Applies necessary patches during app creation.
    """
    # --- Get Global Container ---
    container = get_container()

    # --- Define Mocks and Test Services ---
    mock_analytics_service = AsyncMock(spec=AnalyticsService)
    
    # Define test settings and services factories (as before)
    def get_test_settings() -> Settings:
        """Return test settings for DI injection."""
        return MockSettings()

    # Removed custom JWTService factory in favor of using the test_jwt_service fixture


    # --- Store Original Container Registrations for Cleanup ---
    original_registrations = container._registrations.copy()

    # --- Override Services in Global Container BEFORE App Creation ---
    try:
        logger.info("Applying container overrides for async_client fixture...")
        container.override(Settings, get_test_settings)
        logger.debug("Overridden Settings")
        # Override JWTService and its interface for authentication
        container.override(IJwtService, lambda: test_jwt_service)
        logger.debug("Overridden IJwtService interface mapping")
        container.override(JWTService, lambda: test_jwt_service)
        logger.debug("Overridden JWTService concrete mapping")
        container.override(UserRepository, get_mock_user_repository)
        logger.debug("Overridden UserRepository")
        container.override(XGBoostInterface, lambda: mock_xgboost_service)
        logger.debug("Overridden XGBoostInterface")
        container.override(AnalyticsService, lambda: mock_analytics_service)
        logger.debug("Overridden AnalyticsService")
        logger.info("Container overrides applied.")

        # --- Apply Patches and Create App ---
        mock_rate_limiter_instance = AsyncMock()
        mock_rate_limiter_instance.process_request.return_value = (False, {})
        mock_rate_limiter_instance.apply_rate_limit_headers.return_value = None

        with patch('app.presentation.middleware.rate_limiting_middleware.get_rate_limiter', return_value=mock_rate_limiter_instance), \
             patch.object(Database, 'dispose', new_callable=AsyncMock):

            # Create the app using the factory - it will now use the globally overridden container
            test_app_instance = create_application()

            # Create the AsyncClient 
            async with AsyncClient(transport=ASGITransport(app=test_app_instance), base_url="http://testserver") as client_instance:
                # Attach the FastAPI app instance to the client for fixture access
                setattr(client_instance, 'app', test_app_instance)
                yield client_instance
                
    finally:
        # --- Cleanup: Restore Original Container Registrations ---
        container._registrations = original_registrations

# Fixtures for generating tokens using the *correct* test secret
# Moved from integration/conftest.py for potential wider use, or keep it there if preferred.
_TEST_SECRET_KEY_FOR_FIXTURES = "test-secret-key-for-testing-only" # Ensure this matches the override

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
def sample_actigraphy_data() -> Dict[str, Any]:
    """Placeholder fixture for sample actigraphy data."""
    return {}


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
    """Provides a sample rule dictionary for testing."""
    rule_id = str(uuid.uuid4())
    patient_id = str(uuid.uuid4())  # Using a new UUID for patient_id
    timestamp = datetime.now(timezone.utc)

    return {
        "rule_id": rule_id,
        "name": "Test High Heart Rate Rule",
        "description": "Alert when heart rate exceeds 120 bpm for 5 mins",
        "patient_id": patient_id,
        "priority": "warning",  # Corrected: Use valid enum string value
        "conditions": [
            {
                "metric": "heart_rate",
                "operator": "GREATER_THAN", # Should match ComparatorOperatorEnum
                "threshold": 120.0,
                "duration_minutes": 5
            }
        ],
        "logical_operator": "AND", # Should match LogicalOperatorEnum
        "is_active": True,
        "created_by": "test_user_1",
        "updated_by": "test_user_1",
        "created_at": timestamp.isoformat(),
        "updated_at": timestamp.isoformat()
    }

@pytest.fixture
def sample_patient_id() -> uuid.UUID:
    """Provides a sample patient UUID for testing."""
    return uuid.uuid4()

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
    """Provides the httpx.AsyncClient configured globally."""
    # This now correctly returns the AsyncClient instance, not TestClient.
    return async_client
    
@pytest.fixture
def app(client):
    """Provide the FastAPI application instance used by the AsyncClient fixture."""
    # The AsyncClient fixture stores the FastAPI app reference
    return getattr(client, 'app', None)


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

# --- XGBoost Mock Service Fixture (Moved from integration test) ---
@pytest.fixture(scope="session") # Use session scope consistent with async_client
def mock_xgboost_service():
    """Fixture for a session-scoped AsyncMock XGBoost service interface."""
    mock_service = AsyncMock(spec=XGBoostInterface)
    # Configure mock return values
    mock_service.predict_risk.return_value = {"prediction_id": "risk-pred-123", "risk_score": 0.75, "confidence": 0.9, "risk_level": "high"}
    mock_service.predict_treatment_response.return_value = {"prediction_id": "treat-pred-456", "response_probability": 0.8, "confidence": 0.85}
    mock_service.predict_outcome.return_value = {"prediction_id": "outcome-pred-789", "outcome_prediction": "stable", "confidence": 0.92}
    mock_service.get_model_info.return_value = {"model_type": ModelType.RISK_RELAPSE.value, "version": "1.0", "description": "Mock Relapse Model", "features": ["feat1", "feat2"]}
    mock_service.get_feature_importance.return_value = {"prediction_id": "pred123", "feature_importance": {"feat1": 0.6, "feat2": 0.4}}
    mock_service.get_available_models.return_value = [{"model_type": ModelType.RISK_RELAPSE.value, "version": "1.0"}]
    mock_service.is_initialized = True
    return mock_service
