"""
Pytest configuration file for the application.

This module provides fixtures and configuration for testing the application.
"""

import asyncio
import logging
import os
import sys
import uuid
from collections.abc import AsyncGenerator, Callable
from datetime import datetime, timezone
from typing import Any, Generator
from unittest.mock import AsyncMock, MagicMock, patch, Mock

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

# CRITICAL FIX: Prevent XGBoost namespace collision
# This ensures the test collection mechanism doesn't confuse our test directory
# with the actual XGBoost library
for key in list(sys.modules.keys()):
    if key.startswith('xgboost.') and ('conftest' in key or 'tests' in key):
        del sys.modules[key]

# Import test mocks first to ensure dependency issues are resolved
# This makes tests collectable even without all dependencies installed
import pytest_asyncio
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool

# Import our repository test utilities 
from app.tests.utils.repository_factory import (
    create_repository,
    MockUnitOfWork,
    MockUserRepository,
    MockPatientRepository,
    MockBiometricRuleRepository,
    MockBiometricAlertRepository,
    MockBiometricTwinRepository
)

# Updated import path to match codebase structure
from app.config.settings import (
    Settings,
    get_settings,  # Corrected import path based on grep
)
from app.core.services.ml.pat.pat_service import PATService  # Import PATService
from app.core.services.ml.xgboost.interface import XGBoostInterface
from app.domain.entities.appointment import Appointment  # noqa F401
from app.domain.entities.biometric_alert import BiometricAlert  # noqa F401
from app.domain.entities.biometric_twin import BiometricDataPoint  # noqa F401
from app.domain.entities.user import User  # Import User
from app.core.interfaces.repositories.user_repository import IUserRepository # ADDED
from app.infrastructure.persistence.sqlalchemy.config.database import get_db_session
from app.infrastructure.persistence.sqlalchemy.repositories.user_repository import (
    SQLAlchemyUserRepository as UserRepository,
)
from app.infrastructure.security.jwt.jwt_service import JWTService
from app.presentation.api.v1.dependencies import (  # Import from v1 dependencies
    get_pat_service,  # Add this import
)
from app.api.dependencies.ml import get_xgboost_service # Corrected import path
from app.presentation.dependencies.auth import (
    get_user_repository,  # Keep the correct import for get_user_repository
    get_jwt_service,  # Import get_jwt_service
)
from app.tests.unit.mocks import *

# ADDED: Import the interface for mock spec
from app.core.interfaces.services.authentication_service import IAuthenticationService 

# ADDED: Import the infrastructure service getters to override
from app.infrastructure.security.auth_service import get_auth_service as get_auth_service_infra
from app.infrastructure.security.jwt_service import get_jwt_service as get_jwt_service_infra

# ADDED: Import middleware for patching - REMOVED as patch is removed
# from app.presentation.middleware.authentication_middleware import AuthenticationMiddleware
from app.presentation.middleware.authentication_middleware import AuthenticationMiddleware # Ensure middleware is imported
# REMOVED unused imports related to rate limiting example
# from app.presentation.middleware.rate_limiting_middleware import RateLimitingMiddleware
# from app.infrastructure.security.rate_limiting.limiter import create_rate_limiter 

# ADDED: Import the specific provider functions for route overrides
from app.presentation.api.dependencies.auth import get_jwt_service as get_jwt_service_provider
from app.presentation.api.dependencies.auth_service import get_auth_service_provider
from app.presentation.api.dependencies.user_repository import get_user_repository_provider
from app.main import create_application # Import the actual app factory

@pytest.fixture
def auth_headers():
    """Authentication headers for API requests.
    
    Provides standard headers with a mock token for patient authentication.
    This is used by multiple test modules for authenticated requests.
    """
    # Use the mock token recognized by the mocked JWT service in async_client
    return {
        "Authorization": "Bearer VALID_PATIENT_TOKEN",  # Use the correct mock token string
        "Content-Type": "application/json"
    }

@pytest.fixture
def provider_auth_headers():
    """Authentication headers for provider API requests.
    
    Similar to auth_headers but with provider-level access rights.
    """
    return {
        "Authorization": "Bearer VALID_PROVIDER_TOKEN",  # Provider token with elevated privileges
        "Content-Type": "application/json"
    }

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

# --- Fixtures --- 

# Add the missing primary test settings fixture
@pytest.fixture(scope="session")
def test_settings() -> Settings:
    """Provides application settings configured for the test environment."""
    logger.info("Loading test settings.")
    try:
        settings = Settings()
        # Log critical settings like the database URL
        db_url = getattr(settings, 'DATABASE_URL', 'DATABASE_URL not found')
        logger.info(f"Loaded test settings. DATABASE_URL: {db_url}")
        if not db_url or db_url == 'DATABASE_URL not found':
             raise ValueError("DATABASE_URL is missing in test settings.")
        # Add checks for other essential settings if needed
        return settings
    except Exception as e:
        logger.error(f"Failed to load test settings: {e}")
        raise

@pytest.fixture(scope="session")
def test_engine(test_settings: Settings) -> AsyncEngine:
    """Provides a SQLAlchemy AsyncEngine configured for the test database."""
    logger.info(f"Creating test database engine for URL: {test_settings.DATABASE_URL}")
    engine_options = {
        "echo": False,  # Set to True for SQL debugging
        "poolclass": StaticPool,  # Important for SQLite in-memory
    }
    # Ensure the URL uses aiosqlite for async
    db_url = test_settings.DATABASE_URL
    if db_url.startswith("sqlite://") and not db_url.startswith("sqlite+aiosqlite://"):
        db_url = db_url.replace("sqlite://", "sqlite+aiosqlite://")

    # For SQLite, connect_args might be needed
    if "sqlite" in db_url:
        engine_options["connect_args"] = {"check_same_thread": False}

    engine = create_async_engine(db_url, **engine_options)
    return engine

@pytest.fixture(scope="session")
def mock_db_session_override(test_engine: AsyncEngine) -> Callable[[], AsyncGenerator[AsyncSession, None]]:
    """Provides a dependency override for the database session using the test engine."""
    test_session_local = async_sessionmaker(
        autocommit=False, autoflush=False, bind=test_engine, class_=AsyncSession
    )

    async def override_get_db() -> AsyncGenerator[AsyncSession, None]:
        async with test_session_local() as session:
            yield session

    logger.info("Created mock DB session override.")
    return override_get_db

@pytest.fixture(scope="session")
def mock_user_repository_override() -> Callable[[], IUserRepository]: # Changed return type
    """Provides a factory for creating MagicMock UserRepository instances."""
    def get_mock_repo() -> IUserRepository: # Changed return type
        mock_repo = MagicMock(spec=IUserRepository) # Changed spec
        mock_repo.get_by_id = AsyncMock(return_value=None)
        mock_repo.get_by_email = AsyncMock(return_value=None)
        mock_repo.create = AsyncMock(return_value=User(id=uuid.uuid4(), username="testuser", email="test@example.com", hashed_password="hashed", role="patient")) # Changed return value
        mock_repo.update = AsyncMock(return_value=User(id=uuid.uuid4(), username="testuser", email="test@example.com", hashed_password="hashed", role="patient")) # Changed return value
        mock_repo.delete = AsyncMock(return_value=True)
        mock_repo.list_all = AsyncMock(return_value=[])
        logger.debug("Providing mock IUserRepository instance.") # Updated log message
        return mock_repo
    logger.info("Created mock IUserRepository override provider.") # Updated log message
    return get_mock_repo

@pytest.fixture(scope="session")
def mock_pat_service_override() -> Callable[[], PATService]:
    """Override PATService dependency for testing."""
    mock_service = Mock(spec=PATService)
    mock_service.initialize = AsyncMock()
    mock_service.get_available_models = Mock(return_value=["model1", "model2"])
    mock_service.predict = AsyncMock(return_value={"prediction": "some_value"})
    mock_service.explain = AsyncMock(return_value={"explanation": "some_explanation"})
    mock_service.integrate = AsyncMock(return_value=True)
    logger.debug("Providing mock PATService instance.")
    return mock_service

@pytest.fixture(scope="session")
def mock_xgboost_service_override() -> Callable[[], XGBoostInterface]:
    """Provides a dependency override for the XGBoost service returning a mock."""
    def get_mock_xgboost_service() -> XGBoostInterface:
        mock_service = MagicMock(spec=XGBoostInterface)
        logger.debug("Providing mock XGBoostService instance.")
        return mock_service
    logger.info("Created mock XGBoostService override provider.")
    return get_mock_xgboost_service

# --- Application Fixture with Overrides ---

@pytest.fixture(scope="function") # CHANGED scope to function
def mock_jwt_service() -> AsyncMock:
    """Provides an AsyncMock for the JWTService."""
    # REMOVED spec=JWTService to see if it interferes with method mocking
    mock = AsyncMock()
    mock.create_access_token = AsyncMock(return_value="mock_access_token")
    mock.create_refresh_token = AsyncMock(return_value="mock_refresh_token")
    mock.decode_token = AsyncMock(return_value={"sub": "mock_user_id"})
    mock.get_user_from_token = AsyncMock(return_value=None) # Default to None, override in specific tests if needed
    return mock

@pytest.fixture(scope="function") # CHANGED scope to function
def mock_auth_service(test_patient: User) -> AsyncMock: # Depend on test_patient fixture
    """Provides an AsyncMock for the AuthService."""
    mock = AsyncMock(spec=IAuthenticationService)
    mock.authenticate_user = AsyncMock(return_value=test_patient)
    mock.create_access_token = AsyncMock(return_value="mock_access_token")
    mock.create_refresh_token = AsyncMock(return_value="mock_refresh_token")
    mock.decode_token = AsyncMock(return_value={"sub": "mock_user_id"})
    mock.get_user_from_token = AsyncMock(return_value=test_patient)
    mock.get_user_by_id = AsyncMock(return_value=test_patient) # Ensure this method is async mock
    
    # ADDED: Define an async side_effect function
    async def _get_user_by_id_side_effect(user_id):
        # Basic logic for testing, can be expanded
        if str(user_id) == str(test_patient.id):
            return test_patient
        # Can add logic here to return different users or raise exceptions for tests
        # from app.domain.exceptions.auth_exceptions import UserNotFoundException
        # raise UserNotFoundException(\"Mock user not found\")
        return test_patient # Default return

    mock.get_user_by_id.side_effect = _get_user_by_id_side_effect # Assign the async side effect

    return mock

@pytest.fixture(scope="function") # Keep FUNCTION SCOPE
def initialized_app(
    test_settings: Settings, 
    mock_db_session_override: Callable[[], AsyncGenerator[AsyncSession, None]], 
    mock_user_repository: MockUserRepository, # Use the concrete mock repo fixture
    mock_pat_service_override: Callable[[], PATService], 
    mock_jwt_service: AsyncMock, # Use function-scoped mock
    mock_auth_service: AsyncMock, # Use function-scoped mock
    mocker # Inject mocker fixture
) -> Generator[FastAPI, None, None]:
    """
    Creates a FastAPI application instance for testing using the real factory,
    patches the INFRASTRUCTURE service getters used by AuthenticationMiddleware fallback,
    and overrides necessary route dependencies.
    Scope is function to ensure isolation.
    """
    logger.info(">>> Creating initialized_app fixture (scope=function) using INFRA GETTER PATCHING...")

    # --- Patch the INFRASTRUCTURE GETTERS used by Middleware Fallback --- 
    # Target the names as they are imported *within* the middleware module
    mocker.patch(
        'app.presentation.middleware.authentication_middleware.get_jwt_service',
        return_value=mock_jwt_service
    )
    mocker.patch(
        'app.presentation.middleware.authentication_middleware.get_auth_service',
        return_value=mock_auth_service
    )
    logger.info(">>> Patched infrastructure getters in middleware module scope.")

    # --- Create App using Real Factory --- 
    # Middleware will now use the patched getters if its internal _jwt_service/_auth_service are None
    test_app = create_application(settings=test_settings)
    logger.info(">>> Real application created.")

    # --- Apply Dependency Overrides for Database/PAT --- 
    # Still override these essential ones
    test_app.dependency_overrides[get_db] = mock_db_session_override
    test_app.dependency_overrides[get_async_db] = mock_db_session_override
    test_app.dependency_overrides[get_pat_service] = mock_pat_service_override
    
    # Keep user repo override for routes that might need it directly
    def _override_user_repo_provider():
        logger.info(f"*** ROUTE OVERRIDE: Providing mock_user_repository (ID: {id(mock_user_repository)}) ***")
        return mock_user_repository
    test_app.dependency_overrides[get_user_repository_provider] = _override_user_repo_provider

    logger.info(f">>> Applied DB/PAT/UserRepo dependency overrides.")

    yield test_app # Yield the fully configured app instance

    # Patcher context managers handle unpatching automatically
    logger.info("<<< Tearing down initialized_app fixture (infra getter patching)...")

# --- Async Client Fixture --- 

@pytest_asyncio.fixture(scope="function") # Changed to function scope
async def async_client(
    initialized_app: FastAPI, # Depend on the initialized app with overrides
) -> AsyncGenerator[AsyncClient, None]:
    """
    Create a new httpx AsyncClient instance for tests.
    Uses the `initialized_app` fixture which includes dependency overrides.
    """
    # Use ASGITransport to interact with the FastAPI app in-memory
    transport = ASGITransport(app=initialized_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Attach app reference for potential inspection in tests (optional)
        client.app = initialized_app 
        yield client


# Fixtures for generating tokens using the *correct* test secret
# Moved from integration/conftest.py for potential wider use, or keep it there if preferred.
_TEST_SECRET_KEY_FOR_FIXTURES = "test-secret-key-for-testing-only" # Ensure this matches the override

@pytest.fixture(scope="session") # <-- Added scope="session"
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

@pytest.fixture
def test_jwt_service(test_settings_for_token_gen: Settings) -> JWTService:
    """Provides a JWTService instance configured for generating test tokens."""
    # Pass None for user_repository if it's not needed or mock it
    return JWTService(settings=test_settings_for_token_gen, user_repository=None)


# Fixture to generate a valid token dynamically
@pytest_asyncio.fixture(scope="function") # Function scope for fresh tokens
async def get_valid_auth_headers(test_jwt_service: JWTService) -> dict[str, str]:
    """Generates valid authentication headers with a fresh token for integration tests."""
    # --- Use string representation of defined constant UUID --- 
    user_data = {"sub": str(TEST_INTEGRATION_USER_ID), "roles": ["patient"]}
    # ----------------------------------------------------------
    token = await test_jwt_service.create_access_token(data=user_data)
    return {"Authorization": f"Bearer {token}"}

@pytest_asyncio.fixture(scope="function")
async def get_valid_provider_auth_headers(test_jwt_service: JWTService) -> dict[str, str]:
    """Generates valid authentication headers for a provider role."""
    # --- Use string representation of defined constant UUID --- 
    user_data = {"sub": str(TEST_PROVIDER_USER_ID), "roles": ["provider", "clinician"]}
    # ----------------------------------------------------------
    token = await test_jwt_service.create_access_token(data=user_data)
    return {"Authorization": f"Bearer {token}"}

# Remove the old jwt_service fixture defined earlier if it conflicts or is redundant
# @pytest.fixture
# def jwt_service(): ...


# ... rest of conftest.py ...
# (Ensure provider_token_headers and patient_token_headers fixtures below are updated or removed
# if they conflict with the new get_valid_auth_headers fixtures)

@pytest.fixture
def provider_token_headers(get_valid_provider_auth_headers: dict[str, str]): # Depend on the new fixture
    """Provides valid auth headers for a provider role."""
    # Optionally add more specific headers if needed
    return get_valid_provider_auth_headers

@pytest.fixture
def patient_token_headers(get_valid_auth_headers: dict[str, str]): # Depend on the new fixture
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
    # Removed ContactInfo and Name imports as they are not directly needed for init
    # from app.domain.value_objects.contact_info import ContactInfo 
    # from app.domain.value_objects.name import Name
    
    # Generate a unique patient ID
    patient_id = uuid.uuid4() # Use UUID object directly
    
    # Initialize using direct fields expected by the dataclass __init__
    patient = Patient(
        id=patient_id,
        # Provide name components directly if preferred, or just 'name'
        # name=Name(first_name="Test", last_name="Patient"), # Keep if Name is still used internally 
        first_name="Test", # Or provide components
        last_name="Patient",
        # REMOVED: contact_info=ContactInfo(email="test@example.com", phone="555-123-4567"),
        # ADDED: Provide email and phone directly
        email="test@example.com", 
        phone="555-123-4567",
        date_of_birth="1980-01-01",  # Using String for date to avoid SQLite binding issues
        medical_record_number="MRN-TEST-12345",
        created_by=None  # Set to None to bypass foreign key constraint
    )
    
    return patient

@pytest.fixture
def sample_actigraphy_data() -> dict[str, Any]:
    """Placeholder fixture for sample actigraphy data."""
    return {}

# --- Sample Identifiers ---

@pytest.fixture(scope="session")
def sample_patient_id() -> uuid.UUID:
    """Provides a consistent, reusable UUID for a sample patient."""
    # return uuid.uuid4() # Generate random each run
    return uuid.UUID("123e4567-e89b-12d3-a456-426614174000") # Fixed UUID for consistency

@pytest.fixture(scope="session")
def sample_rule_id() -> uuid.UUID:
    """Provides a consistent, reusable UUID for a sample alert rule."""
    return uuid.UUID("789e0123-f45a-67b8-c90d-123456789abc") # Fixed UUID for consistency

@pytest.fixture(scope="session")
def sample_alert_id() -> uuid.UUID:
    """Provides a consistent, reusable UUID for a sample alert."""
    return uuid.UUID("abcdef01-2345-6789-abcd-ef0123456789") # Fixed UUID for consistency

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
    async def _generate_token(claims: dict[str, Any]) -> str:
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
    from datetime import datetime, timezone

    from app.domain.services.biometric_event_processor import BiometricAlert
    
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

# pytest.mark.usefixtures("mock_db_session") # Apply mock session if needed globally

# Override the default function-scoped event_loop fixture with session scope
@pytest_asyncio.fixture(scope="session")
def event_loop():
    """
    Create a session-scoped event loop for pytest-asyncio.
    
    This prevents ScopeMismatch errors when using session scoped fixtures
    that depend on event_loop fixtures. Using session scope ensures all
    async fixtures can share the same event loop regardless of their scope.
    """
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
    from app.tests.security.utils.test_mocks import MockAsyncSession
    
    return MockAsyncSession()


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
    """Provides a mock XGBoost service conforming to the interface."""
    # Create a MagicMock specifying the interface methods
    mock_service = AsyncMock(spec=XGBoostInterface)
    
    # Define comprehensive mock implementations for required methods
    mock_service.predict = AsyncMock(return_value={"prediction": "mock_result", "confidence": 0.95})
    mock_service.predict_risk = AsyncMock(return_value={"risk_level": "low", "score": 0.2, "patient_id": "test-patient-id"})
    mock_service.predict_treatment_response = AsyncMock(return_value={"response": "positive", "probability": 0.8})
    mock_service.predict_outcome = AsyncMock(return_value={"outcome": "remission", "probability": 0.75})
    
    # Service information and metadata methods
    mock_service.get_model_info = AsyncMock(return_value={
        "name": "mock_model", 
        "version": "1.0",
        "training_date": "2025-01-15",
        "metrics": {"accuracy": 0.92, "f1": 0.89},
        "record_id": "info"
    })
    
    # Feature importance and explainability methods
    mock_service.get_feature_importance = AsyncMock(return_value={
        "feature_importance": [
            {"feature": "age", "importance": 0.25},
            {"feature": "medication_history", "importance": 0.32},
            {"feature": "symptom_duration", "importance": 0.18}
        ]
    })
    
    # Integration methods
    mock_service.integrate_with_digital_twin = AsyncMock(return_value={
        "status": "success",
        "twin_id": "dt-12345",
        "integration_timestamp": "2025-04-15T12:30:00Z"
    })
    
    # Health and monitoring
    mock_service.healthcheck = AsyncMock(return_value={"status": "ok", "dependencies": "mocked"})
    
    logger.info("Created mock XGBoost service fixture.") # Add log
    return mock_service

@pytest.fixture
def mock_phi_service():
    """Create a mock PHI service for HIPAA compliance tests.
    
    This fixture provides a mock implementation of the PHI detection and
    sanitization service used in HIPAA compliance tests.
    
    Returns:
        MagicMock: A mock PHI service
    """
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
    
    # Use our standardized test database initializer to set up the test database
    logger.info("[Fixture setup_database] Using standardized test_db_initializer")
    
    # Simply yield and continue with tests - no actual setup needed here
    # The test_db_session fixture in individual tests will handle table creation
    yield
    
    # No teardown needed here - each test manages its own session via test_db_session

@pytest_asyncio.fixture(scope="function") # Reverted scope to function
async def test_db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Create an isolated database session for each test function with test users.
    
    This fixture uses the standardized test database initializer to ensure:
    1. The database has the correct schema
    2. Test users exist for foreign key relationships
    3. Each test runs in its own transaction that is rolled back after the test

    Yields:
        AsyncSession: SQLAlchemy async session with test users created
    """
    # Use in-memory SQLite for testing; connect_args needed for SQLite
    database_url = "sqlite+aiosqlite:///:memory:"
    engine = create_async_engine(
        database_url,
        echo=False,
        # CRITICAL: Use StaticPool for asyncio compatibility with SQLite in tests
        poolclass=StaticPool, 
        connect_args={"check_same_thread": False} # Required for SQLite
    )

    # Create tables
    async with engine.begin() as conn:
        # logger.info("Dropping all tables in test database...")
        # await conn.run_sync(Base.metadata.drop_all)
        logger.info("Creating all tables in test database...")
        await conn.run_sync(Base.metadata.create_all)

    # Create a session factory
    testing_session_local = async_sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=engine,
        expire_on_commit=False,
        class_=AsyncSession # Ensure we use AsyncSession
    )

    async with testing_session_local() as session:
        logger.info("Yielding test database session.")
        yield session # Yield the session for the test
        logger.info("Rolling back test database session transaction.")
        await session.rollback() # Rollback any changes after the test

    # Drop tables after session is closed (optional cleanup)
    # async with engine.begin() as conn:
    #     await conn.run_sync(Base.metadata.drop_all)

    await engine.dispose()

# Define consistent UUIDs for test users
TEST_INTEGRATION_USER_ID = uuid.UUID("a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11")
TEST_PROVIDER_USER_ID = uuid.UUID("00000000-0000-0000-0000-000000000001") # Example provider UUID
_TEST_SECRET_KEY_FOR_FIXTURES = "super-secret-key-for-testing-fixtures-only"

@pytest.fixture
def mock_session() -> AsyncSession:
    """Create a mock AsyncSession for testing."""
    mock = AsyncMock(spec=AsyncSession)
    # Add essential session methods
    mock.execute = AsyncMock()
    mock.commit = AsyncMock()
    mock.rollback = AsyncMock()
    mock.close = AsyncMock()
    mock.refresh = AsyncMock()
    return mock

@pytest.fixture
def mock_unit_of_work(mock_session: AsyncSession) -> MockUnitOfWork:
    """Create a MockUnitOfWork for dependency injection."""
    return MockUnitOfWork(mock_session)

@pytest.fixture
def user_repository(mock_session: AsyncSession) -> IUserRepository: # Changed return type
    """Create a test-compatible UserRepository instance."""
    return MockUserRepository(mock_session) # Assumes MockUserRepository implements IUserRepository

@pytest.fixture
def mock_current_active_user_override():
    """Create a mock for the current active user dependency."""
    from unittest.mock import MagicMock
    
    user = User(id=str(uuid.uuid4()), username="testuser", role="patient")
    mock = MagicMock(return_value=user)
    return mock

@pytest.fixture
def mock_jwt_handler():
    """Create a mock JWT handler for testing."""
    from unittest.mock import MagicMock

    from app.infrastructure.auth.jwt_handler import JWTHandler
    
    mock_handler = MagicMock(spec=JWTHandler)
    return mock_handler
