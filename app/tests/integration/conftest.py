"""
Integration Test Configuration and Fixtures

This file contains test fixtures specific to integration tests which may
require network connections, databases, and other external services.
"""

import logging
import uuid
from collections.abc import AsyncGenerator
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from asgi_lifespan import LifespanManager
from fastapi import FastAPI, Header
from fastapi.testclient import TestClient
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from app.core.config import Settings
from app.core.domain.entities.user import User, UserRole, UserStatus
from app.core.interfaces.aws_service_interface import (
    AWSServiceFactory,
    S3ServiceInterface,
)
from app.core.interfaces.services.encryption_service_interface import IEncryptionService

# Import JWT service interface
# Added imports for mock JWT service
from app.core.interfaces.services.jwt_service import IJwtService, JWTServiceInterface

# Import Redis service interface and mock implementation
from app.core.interfaces.services.redis_service_interface import IRedisService
from app.core.models.token_models import TokenPayload
from app.domain.exceptions.token_exceptions import InvalidTokenException
from app.infrastructure.aws.service_factory_provider import get_aws_service_factory

# End of added imports
# Import SQLAlchemy models and utils
from app.infrastructure.security.jwt.jwt_service import get_jwt_service as get_jwt_service_provider
from app.presentation.api.dependencies.repository import get_encryption_service

# Import the predefined test user UUIDs
# Import the FastAPI application
# Import test database initializer functions
from app.tests.integration.utils.test_db_initializer import (
    TEST_CLINICIAN_ID,
    TEST_USER_ID,
    create_test_users,
    get_test_db_session,
)
from app.tests.utils.mock_redis_service import create_mock_redis_service

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize models
# ensure_all_models_loaded()
# validate_models()


# Database fixtures
@pytest_asyncio.fixture
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Creates a properly initialized database session for testing with all models registered.
    Uses the test_db_initializer function to create an in-memory SQLite database with test data.

    This is the canonical database session fixture that should be used across all tests.
    It ensures proper model registration, transaction handling, and test data initialization.

    Yields:
        AsyncSession: SQLAlchemy AsyncSession for test database access
    """
    try:
        logger.info("Creating test database session with canonical SQLAlchemy models")
        # Use the test_db_initializer function to create an in-memory test database
        # This handles all model creation and test data setup
        async for session in get_test_db_session():
            # Ensure models are properly registered before yielding the session
            # ensure_all_models_loaded()

            # Create test users
            await create_test_users(session)

            # Yield the session for the test to use
            yield session

            # Session will be automatically closed and rolled back after test
    except Exception as e:
        logger.error(f"Error setting up test database: {e}")
        raise


@pytest.fixture
def mock_db_data() -> dict[str, list[dict[str, Any]]]:
    """
    Provides mock database data for tests.

    Returns:
        Dictionary of mock collections/tables with test data.
    """

    return {
        "patients": [
            {
                "id": "p-12345",
                "name": "Test Patient",
                "age": 30,
                "gender": "F",
                "medical_history": ["Anxiety", "Depression"],
                "created_at": "2025-01-15T10:30:00Z",
            },
            {
                "id": "p-67890",
                "name": "Another Patient",
                "age": 45,
                "gender": "M",
                "medical_history": ["Bipolar Disorder"],
                "created_at": "2025-02-20T14:15:00Z",
            },
        ],
        "providers": [
            {
                "id": "prov-54321",
                "name": "Dr. Test Provider",
                "specialization": "Psychiatry",
                "license_number": "LP12345",
            }
        ],
        "appointments": [
            {
                "id": "apt-11111",
                "patient_id": "p-12345",
                "provider_id": "prov-54321",
                "datetime": "2025-04-15T10:00:00Z",
                "status": "scheduled",
            }
        ],
        "digital_twins": [
            {
                "patient_id": "p-12345",
                "model_version": "v2.1.0",
                "neurotransmitter_levels": {
                    "serotonin": 0.75,
                    "dopamine": 0.65,
                    "norepinephrine": 0.70,
                },
                "last_updated": "2025-04-10T08:45:00Z",
            }
        ],
    }


# Authentication fixtures and JWT service for proper token generation
@pytest.fixture
def test_config() -> dict[str, Any]:
    """
    Provides a standard test configuration for JWT and other services.

    Returns:
        Dict with test configuration values
    """
    # Import the centralized test configuration to ensure consistency
    from app.tests.integration.utils.test_config import get_test_settings_override

    # Use the standardized test settings from the utility function
    return get_test_settings_override()


@pytest.fixture
def jwt_service(test_settings: Settings) -> IJwtService:
    """
    Provides a properly configured JWT service for test token generation.

    This ensures tokens are generated using the same secret key that the
    authentication middleware will use for validation.

    Returns:
        IJwtService: Configured JWT service instance
    """
    from app.infrastructure.security.jwt.jwt_service import JWTService

    # JWTService expects a Settings object
    return JWTService(settings=test_settings, user_repository=None)


@pytest.fixture
async def patient_auth_headers(jwt_service: IJwtService) -> dict[str, str]:
    """
    Creates authentication headers with a JWT token for patient test user.

    Returns:
        Dict with Authorization header containing Bearer token
    """
    # Comprehensive token data that matches the full JWT payload structure expected by the auth middleware
    token_data = {
        "sub": "00000000-0000-0000-0000-000000000001",  # TEST_USER_ID
        "username": "testuser",
        "email": "test.user@novamind.ai",
        "role": "PATIENT",
        "roles": ["PATIENT"],
        "verified": True,
        "active": True,
        "jti": str(uuid.uuid4()),
    }
    # create_access_token is now synchronous
    token = jwt_service.create_access_token(data=token_data)

    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


@pytest.fixture
async def provider_auth_headers(jwt_service: IJwtService) -> dict[str, str]:
    """
    Provides authentication headers for a test clinician user.

    Returns:
        Dict with Authorization header containing valid JWT for test clinician
    """
    # Comprehensive token data that matches the full JWT payload structure
    token_data = {
        "sub": "00000000-0000-0000-0000-000000000002",  # TEST_CLINICIAN_ID
        "username": "testclinician",
        "email": "test.clinician@novamind.ai",
        "role": "CLINICIAN",
        "roles": ["CLINICIAN", "PROVIDER"],
        "verified": True,
        "active": True,
        "jti": str(uuid.uuid4()),
    }

    # create_access_token is now synchronous
    token = jwt_service.create_access_token(data=token_data)

    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


# API Testing Fixtures
@pytest_asyncio.fixture
async def test_app(
    test_settings: Settings,
    mock_s3_service: MagicMock,
    mock_encryption_service: MagicMock,
    mock_jwt_service_with_placeholder_handling: JWTServiceInterface,
) -> FastAPI:
    logger.info(
        "Creating FastAPI app instance for integration tests via integration/conftest.py (test_app fixture)."
    )

    from app.app_factory import (  # Moved import here to be self-contained
        create_application,
    )

    app = create_application(settings_override=test_settings)

    mock_aws_factory = MagicMock(spec=AWSServiceFactory)
    mock_aws_factory.get_s3_service.return_value = mock_s3_service

    app.dependency_overrides[get_aws_service_factory] = lambda: mock_aws_factory
    app.dependency_overrides[get_encryption_service] = lambda: mock_encryption_service
    app.dependency_overrides[
        get_jwt_service_provider
    ] = lambda: mock_jwt_service_with_placeholder_handling

    # Removed: async with LifespanManager(app):
    yield app  # Just yield the configured app


@pytest_asyncio.fixture
async def test_client(test_app: FastAPI) -> AsyncGenerator[AsyncClient, None]:
    """Provides an AsyncClient instance configured for the test_app, managing its lifespan."""
    from asgi_lifespan import LifespanManager  # Moved import here

    logger.info(f"test_client fixture: Managing lifespan for test_app with id: {id(test_app)}")

    async with LifespanManager(test_app) as manager:
        logger.info(f"test_client fixture: LifespanManager active for app id: {id(manager.app)}")
        transport = ASGITransport(app=manager.app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            logger.info(
                f"test_client fixture: Yielding client for app id used by transport: {id(manager.app)}"
            )
            yield client


@pytest.fixture
def mock_s3_service() -> MagicMock:
    """
    Provides a mock S3 service for testing.

    Returns:
        MagicMock: A MagicMock instance configured to simulate S3ServiceInterface.
    """
    mock = MagicMock(spec=S3ServiceInterface)
    # Example of mocking a method if needed for specific tests:
    # mock.upload_file.return_value = {"status": "success", "file_id": "mock_s3_file_id"}
    # mock.get_file_url.return_value = "https://mock-s3-bucket.s3.amazonaws.com/mock_s3_file_id"
    return mock


@pytest.fixture
def mock_encryption_service() -> IEncryptionService:
    """
    Provides a mock implementation of the IEncryptionService for testing.

    This allows testing of encryption-related logic without actual encryption operations.
    The mock provides a simple encryption simulation where encrypt adds a prefix
    and decrypt removes it, ensuring proper testing of encryption/decryption flows.

    Returns:
        MagicMock: Mocked IEncryptionService instance with realistic behavior
    """
    mock_service = MagicMock(spec=IEncryptionService)

    # Define specific mock behaviors to simulate encryption/decryption
    def mock_encrypt(data):
        """Mock encrypt by prefixing data with 'ENCRYPTED_' marker."""
        if isinstance(data, str):
            data = data.encode("utf-8")
        elif not isinstance(data, bytes):
            data = str(data).encode("utf-8")
        return b"ENCRYPTED_" + data

    def mock_decrypt(data):
        """Mock decrypt by removing 'ENCRYPTED_' prefix."""
        if isinstance(data, str):
            data = data.encode("utf-8")

        if data.startswith(b"ENCRYPTED_"):
            return data[len(b"ENCRYPTED_") :]
        return data  # Return as-is if not properly encrypted

    mock_service.encrypt.side_effect = mock_encrypt
    mock_service.decrypt.side_effect = mock_decrypt

    return mock_service


@pytest.fixture
def mock_jwt_service_with_placeholder_handling() -> JWTServiceInterface:
    """
    Provides a mock JWT service that handles specific placeholder tokens.

    This allows tests to simulate different authentication states without
    needing to generate full JWTs.
    """
    mock_service = MagicMock(spec=JWTServiceInterface)

    # Define the side effect function for decode_token as an async function
    async def decode_token_side_effect(token: str, audience: str | None = None) -> TokenPayload:
        logger.info(f"INTEGRATION mock JWT decode_token CALLED with token: {token}")

        current_time = datetime.now(timezone.utc)
        default_exp_time = current_time + timedelta(minutes=15)
        default_iat_time = current_time

        # Handle predefined placeholder tokens
        if token == "VALID_PATIENT_TOKEN":
            return TokenPayload(
                sub=str(TEST_USER_ID),  # Ensure this is a string representation of UUID
                username="integration_test_patient",  # This is an extra field not in TokenPayload, will be ignored by Pydantic if not in model
                email="integration.patient@example.com",  # Extra field
                roles=[UserRole.PATIENT.value],  # Use .value for string representation of enum
                exp=int(default_exp_time.timestamp()),  # Convert to int timestamp
                iat=int(default_iat_time.timestamp()),  # Add iat
                jti=str(uuid.uuid4()),  # Unique token ID
                token_type="access",  # This is an extra field, 'scope' or 'scopes' is used by TokenPayload
                scope="access",  # Use 'scope' or 'scopes'
                # Add any other fields expected by TokenPayload or downstream consumers
                first_name="Integration Test",  # Extra field
                last_name="Patient",  # Extra field
                is_active=True,  # Extra field
                is_verified=True,  # Extra field
            )
        elif token == "VALID_PROVIDER_TOKEN":
            return TokenPayload(
                sub=str(TEST_CLINICIAN_ID),  # Ensure this is a string representation of UUID
                username="integration_test_provider",  # Extra
                email="integration.provider@example.com",  # Extra
                roles=[UserRole.CLINICIAN.value],  # Use .value for string representation of enum
                exp=int(default_exp_time.timestamp()),  # Convert to int timestamp
                iat=int(default_iat_time.timestamp()),  # Add iat
                jti=str(uuid.uuid4()),
                token_type="access",  # Extra, use scope
                scope="access",
                first_name="Integration Test",  # Extra
                last_name="Provider",  # Extra
                is_active=True,  # Extra
                is_verified=True,  # Extra
            )
        elif token == "VALID_ADMIN_TOKEN":
            return TokenPayload(
                sub=str(uuid.UUID("00000000-0000-0000-0000-000000000003")),  # Example Admin ID
                username="integration_test_admin",  # Extra
                email="integration.admin@example.com",  # Extra
                roles=[UserRole.ADMIN.value],  # Use .value for string representation of enum
                exp=int(default_exp_time.timestamp()),  # Convert to int timestamp
                iat=int(default_iat_time.timestamp()),  # Add iat
                jti=str(uuid.uuid4()),
                token_type="access",  # Extra, use scope
                scope="access",
                first_name="Integration Test",  # Extra
                last_name="Admin",  # Extra
                is_active=True,  # Extra
                is_verified=True,  # Extra
            )
        elif token == "EXPIRED_TOKEN":
            raise InvalidTokenException("Token has expired")  # Simulate expired token
        elif token == "INVALID_FORMAT_TOKEN":
            raise InvalidTokenException("Invalid token format")  # Simulate malformed token
        else:
            # Default case for unhandled tokens
            raise InvalidTokenException(
                f"Integration mock: Unhandled or invalid token format: {token}"
            )

    # Assign the async side_effect to an AsyncMock instance
    mock_service.decode_token = AsyncMock(side_effect=decode_token_side_effect)

    # Mock create_access_token and create_refresh_token to return placeholder strings if needed
    # or actual JWTs if this mock service is also used for token generation in some tests.
    # For now, assume they are not the primary focus for decoding tests.
    mock_service.create_access_token = MagicMock(return_value="MOCK_ACCESS_JWT_STRING")
    mock_service.create_refresh_token = MagicMock(return_value="MOCK_REFRESH_JWT_STRING")
    mock_service.create_token_pair = MagicMock(
        return_value=("MOCK_ACCESS_JWT_STRING", "MOCK_REFRESH_JWT_STRING")
    )

    return mock_service


@pytest.fixture
def mock_mentallama_api() -> Any:
    """
    Provides a mock for the MentaLLama API service.

    Returns:
        A mock MentaLLama API client.
    """

    class MockMentaLLamaAPI:
        async def predict(self, patient_id: str, data: dict[str, Any]) -> dict[str, Any]:
            return {
                "patient_id": patient_id,
                "prediction": {
                    "anxiety_level": 0.65,
                    "depression_level": 0.55,
                    "confidence": 0.80,
                    "recommended_interventions": [
                        "CBT therapy",
                        "Mindfulness practice",
                    ],
                },
                "model_version": "mentallama-v1.2.0",
            }

        async def get_model_info(self) -> dict[str, Any]:
            return {
                "name": "MentaLLama",
                "version": "1.2.0",
                "last_updated": "2025-03-15",
                "parameters": 7_000_000_000,
                "supported_features": [
                    "anxiety_prediction",
                    "depression_prediction",
                    "intervention_recommendation",
                ],
            }

    return MockMentaLLamaAPI()


@pytest.fixture
async def app_with_mocked_services() -> FastAPI:
    """
    Provides a mock for AWS services like S3, SageMaker, etc.

    Returns:
        A mock AWS service client.
    """

    class MockAWSService:
        def invoke_endpoint(self, endpoint_name: str, data: dict[str, Any]) -> dict[str, Any]:
            return {
                "result": {
                    "prediction": [0.65, 0.35, 0.80],
                    "processing_time_ms": 120,
                    "model_version": "xgboost-v2.1",
                },
                "success": True,
                "request_id": "aws-req-12345",
            }

        def upload_file(self, file_path: str, bucket: str, key: str) -> bool:
            return True

        def download_file(self, bucket: str, key: str, local_path: str) -> bool:
            # Simulate creating a file
            with open(local_path, "w") as f:
                f.write('{"mock": "data"}')
            return True

    return MockAWSService()


@pytest.fixture
def integration_fixture() -> str:
    """Basic fixture for integration tests."""

    return "integration_fixture"


@pytest.fixture
def actigraphy_file_name() -> str:
    """Provides a sample filename for actigraphy data uploads."""
    return "test_actigraphy_data.csv"


@pytest.fixture
def actigraphy_file_content() -> bytes:
    """Provides sample CSV content for actigraphy data uploads."""
    # Simple CSV: timestamp,x,y,z
    csv_content = (
        "timestamp,x,y,z\\n"
        "2023-01-01T00:00:00Z,0.1,0.2,0.9\\n"
        "2023-01-01T00:00:01Z,0.2,0.3,0.8\\n"
        "2023-01-01T00:00:02Z,0.3,0.4,0.7\\n"
    )
    return csv_content.encode("utf-8")


@pytest_asyncio.fixture
async def test_db_engine(test_settings: Settings):
    """
    Creates an async SQLAlchemy engine for integration tests.
    Uses the database URL from test_settings.

    Returns:
        AsyncEngine: SQLAlchemy AsyncEngine instance suitable for integration tests
    """

    # Get database URL from settings, with fallback
    database_url = getattr(test_settings, "DATABASE_URL", None) or "sqlite+aiosqlite:///:memory:"

    # Set async database URL attribute if it doesn't exist (prevents NoneType startswith error)
    if not hasattr(test_settings, "ASYNC_DATABASE_URL") or test_settings.ASYNC_DATABASE_URL is None:
        test_settings.ASYNC_DATABASE_URL = database_url

    logger.info(f"Creating async database engine for integration tests with URL: {database_url}")

    # Create engine with appropriate settings for testing (echo=False in tests to reduce noise)
    engine = create_async_engine(
        database_url,
        echo=False,
        future=True,
        connect_args={"check_same_thread": False} if database_url.startswith("sqlite") else {},
    )

    logger.info(f"AsyncEngine created successfully: {engine}")

    # Setup any engine-level configurations if needed
    async with engine.begin() as conn:
        # For SQLite: Enable foreign key constraints
        if database_url.startswith("sqlite"):
            await conn.execute(text("PRAGMA foreign_keys=ON"))

        # Create all tables in a single transaction
        from app.infrastructure.persistence.sqlalchemy.models.base import Base

        await conn.run_sync(Base.metadata.create_all)

    logger.info("All database tables created from metadata")

    yield engine

    # Cleanup: dispose of the engine to release connections
    logger.info("Disposing test database engine")
    await engine.dispose()


@pytest_asyncio.fixture
async def test_app_with_db_session(
    test_settings: Settings,
    mock_s3_service: MagicMock,
    mock_encryption_service: MagicMock,
    mock_jwt_service_with_placeholder_handling: JWTServiceInterface,
    test_db_engine,
) -> AsyncGenerator[FastAPI, None]:
    """
    Creates a FastAPI app with fully initialized database session factory in app.state
    for tests that require database access through FastAPI dependency injection.
    """
    logger.info("Creating FastAPI app instance with DB session factory for integration tests")

    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from app.app_factory import create_application

    # Create the app instance
    app = create_application(
        settings_override=test_settings,
        jwt_service_override=mock_jwt_service_with_placeholder_handling,
        skip_auth_middleware=True,
    )
    logger.info(
        f"DEBUG_INTEGRATION_CONTEST_APP_TYPE: Immediately after create_application (Auth MW SKIPPED), app type is {type(app)}, id is {id(app)}."
    )  # DEBUG LOGGING

    # Create a properly configured session factory
    db_session_factory = async_sessionmaker(
        bind=test_db_engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
    )

    # CRITICAL: Set the session factory directly in app.state
    # This is what the app will use for database access in API endpoints
    app.state.actual_session_factory = db_session_factory
    app.state.engine = test_db_engine
    app.state.db_schema_created = True

    logger.info(f"App instance created in test_app_with_db_session. App ID: {id(app)}")
    logger.info(
        f"app.state.engine ID: {id(app.state.engine if hasattr(app.state, 'engine') else None)}"
    )
    logger.info(
        f"app.state.actual_session_factory: {app.state.actual_session_factory if hasattr(app.state, 'actual_session_factory') else 'Not set'}"
    )

    # Use LifespanManager to correctly run startup/shutdown events
    try:
        async with LifespanManager(app) as manager:
            logger.info(
                "Application lifespan startup completed, actual_session_factory is properly set"
            )
            if hasattr(manager.app, "state") and hasattr(
                manager.app.state, "actual_session_factory"
            ):
                yield manager.app
            else:
                yield app
    except Exception as e:
        logger.error(f"Error in test_app_with_db_session fixture: {e}")
        raise


@pytest_asyncio.fixture
async def test_client_with_db_session(
    test_app_with_db_session: FastAPI,
) -> AsyncGenerator[AsyncClient, None]:
    """Provides an AsyncClient instance configured with DB session factory"""
    from httpx._transports.asgi import ASGITransport

    async with AsyncClient(
        transport=ASGITransport(app=test_app_with_db_session), base_url="http://test"
    ) as client:
        yield client


@pytest_asyncio.fixture
async def test_app_with_auth_override(
    test_app_with_db_session: FastAPI,
    mock_auth_dependency,
    # mock_jwt_service_with_placeholder_handling: JWTServiceInterface # Not directly used here, already in app from previous fixture if needed by create_application
):
    """Overrides authentication dependencies for a test application instance."""
    app_to_override = test_app_with_db_session
    logger.info(
        f"DEBUG_AUTH_OVERRIDE_FIXTURE: Received app type: {type(app_to_override)}, id: {id(app_to_override)}"
    )  # Unique logger message
    if not isinstance(app_to_override, FastAPI):
        logger.error(
            f"DEBUG_AUTH_OVERRIDE_FIXTURE: app_to_override IS NOT A FastAPI instance! Type: {type(app_to_override)}"
        )
        raise TypeError("test_app_with_db_session did not yield a FastAPI app for auth override.")

    # Store original overrides to restore them specifically, though clear() is usually enough
    app_to_override.dependency_overrides.copy()

    # Override authentication dependencies with appropriate role handlers
    test_app_with_db_session.dependency_overrides[get_current_user] = mock_auth_dependency(
        "PATIENT"
    )
    test_app_with_db_session.dependency_overrides[get_current_active_user] = mock_auth_dependency(
        "PATIENT"
    )
    test_app_with_db_session.dependency_overrides[require_admin_role] = mock_auth_dependency(
        "ADMIN"
    )
    test_app_with_db_session.dependency_overrides[require_clinician_role] = mock_auth_dependency(
        "CLINICIAN"
    )

    return test_app_with_db_session


@pytest_asyncio.fixture
async def authenticated_client(
    test_app_with_db_session: FastAPI, mock_auth_dependency
) -> AsyncGenerator[AsyncClient, None]:
    """
    Creates an authenticated test client with DB session factory properly initialized.

    This fixture provides a client that:
    1. Uses the app with DB session properly set
    2. Has authentication dependencies overridden
    3. Is ready to make authenticated API requests

    Returns:
        An authenticated AsyncClient for testing protected endpoints
    """
    # Override auth dependencies to bypass authentication in tests
    from httpx._transports.asgi import ASGITransport

    from app.presentation.api.dependencies.auth import (
        get_current_active_user,
        get_current_user,
    )

    # Set up the authentication overrides using the patient role by default
    test_app_with_db_session.dependency_overrides[get_current_user] = lambda: mock_auth_dependency(
        "PATIENT"
    )
    test_app_with_db_session.dependency_overrides[
        get_current_active_user
    ] = lambda: mock_auth_dependency("PATIENT")

    # Create the client with the authenticated app
    async with AsyncClient(
        transport=ASGITransport(app=test_app_with_db_session), base_url="http://test"
    ) as client:
        logger.info("Created authenticated AsyncClient for testing protected endpoints")
        yield client


@pytest.fixture
def mock_auth_dependency():
    """
    Creates a dependency override to bypass authentication checks in tests.

    This allows tests to run without requiring a valid JWT token,
    while still providing the expected user object to the endpoints.
    """
    # raise RuntimeError("DEBUG: app/tests/integration/conftest.py mock_auth_dependency was called!") # DEBUGGING LINE - REVERTED

    # Import here to avoid circular imports
    from app.core.domain.entities.user import (  # Added UserStatus
        User,
        UserRole,
        UserStatus,
    )

    # Create mock users for different roles
    # Ensure these match the User dataclass in app.core.domain.entities.user
    mock_patient = User(
        id=uuid.UUID(
            "00000000-0000-0000-0000-000000000001"
        ),  # TEST_USER_ID from utils.test_db_initializer
        username="integration_test_patient",
        email="integration.patient@example.com",
        full_name="Integration Test Patient",
        password_hash="$2b$12$EixZaYVK1fsbw1ZfbX3RU.II9.eGCwJoF1732K/i54e9QaJIX3fOC",  # Example hash
        roles={UserRole.PATIENT},
        account_status=UserStatus.ACTIVE,  # Corrected to account_status
    )

    mock_provider = User(
        id=uuid.UUID(
            "00000000-0000-0000-0000-000000000002"
        ),  # TEST_CLINICIAN_ID from utils.test_db_initializer
        username="integration_test_provider",
        email="integration.provider@example.com",
        full_name="Integration Test Provider",
        password_hash="$2b$12$EixZaYVK1fsbw1ZfbX3RU.II9.eGCwJoF1732K/i54e9QaJIX3fOC",  # Example hash
        roles={UserRole.CLINICIAN},
        account_status=UserStatus.ACTIVE,  # Corrected to account_status
    )

    mock_admin = User(
        id=uuid.UUID("00000000-0000-0000-0000-000000000003"),  # Example Admin ID
        username="integration_test_admin",
        email="integration.admin@example.com",
        full_name="Integration Test Admin",
        password_hash="$2b$12$EixZaYVK1fsbw1ZfbX3RU.II9.eGCwJoF1732K/i54e9QaJIX3fOC",  # Example hash
        roles={UserRole.ADMIN},
        account_status=UserStatus.ACTIVE,  # Corrected to account_status
    )

    # Store the mock users by role type
    mock_users = {
        "PATIENT": mock_patient,
        "CLINICIAN": mock_provider,
        "ADMIN": mock_admin,
        "DEFAULT": mock_provider,  # Default to provider for broader endpoint access
    }

    logger = logging.getLogger(__name__)  # Ensure logger is defined if used

    # Return a function that can be used to override dependencies
    def override_dependency(role: str = "DEFAULT"):
        # Create an async function to return the appropriate user
        async def get_mock_user():
            user_to_return = mock_users.get(role, mock_users["DEFAULT"])
            logger.info(
                f"INTEGRATION mock_auth_dependency providing user: {user_to_return.username} with roles {user_to_return.roles} and ID {user_to_return.id} and account_status {user_to_return.account_status}"
            )  # Added account_status logging
            return user_to_return

        return get_mock_user

    return override_dependency


# Test API endpoint for authentication verification
def create_auth_me_endpoint(app: FastAPI) -> None:
    """Add a test endpoint to verify authentication."""

    @app.get("/api/v1/auth/me")
    async def auth_me_endpoint(
        x_test_auth_bypass: str = Header(None),
    ):
        """Test endpoint that returns the authenticated user's information."""
        # This function will be automatically handled by the test authentication middleware
        # The middleware will add the user to the request scope based on the X-Test-Auth-Bypass header
        # or the token in the Authorization header
        return {
            "authenticated": True,
            "user_id": "00000000-0000-0000-0000-000000000002",
            "roles": ["clinician"],
        }


# Create a consistent JWT token for testing
def create_test_token(
    subject: str = "test.user@example.com",
    user_id: str = "00000000-0000-0000-0000-000000000002",
    roles: list[str] | None = None,
    expiration_minutes: int = 30,
) -> str:
    """Create a JWT token for testing."""
    roles = roles or ["clinician"]

    # Current time
    now = datetime.now(timezone.utc)

    # Token payload
    payload = {
        "sub": subject,
        "id": user_id,
        "user_id": user_id,
        "roles": roles,
        "exp": (now + timedelta(minutes=expiration_minutes)).timestamp(),
        "iat": now.timestamp(),
        "jti": str(uuid.uuid4()),
        "iss": "test-issuer",
        "aud": "test-audience",
        "type": "access",
    }

    # Sign token with a test key
    test_secret = "test_secret_key_for_testing_only"
    token = jwt.encode(payload, test_secret, algorithm="HS256")

    return token


@pytest.fixture
def test_app() -> FastAPI:
    """Create a test FastAPI application with appropriate configuration for testing."""
    # Create a new app with test settings
    from app.app_factory import (  # Import the create_application function
        create_application,
    )

    app = create_application()

    # Add auth verification endpoint for testing
    create_auth_me_endpoint(app)

    # Replace any existing authentication middleware with test-specific middleware
    # that accepts test tokens and test-specific headers
    public_paths = {
        "/health",
        "/docs",
        "/openapi.json",
        "/api/v1/auth/login",
        "/api/v1/auth/refresh",
    }

    # This is tricky - we need to remove any existing instances of AuthenticationMiddleware
    # and replace them with our test-specific middleware
    app.middleware_stack = None  # Clear the middleware stack
    app.add_middleware(TestAuthenticationMiddleware, public_paths=public_paths)

    return app


@pytest.fixture
def test_client(test_app: FastAPI) -> TestClient:
    """
    Create a TestClient instance with auth middleware configured.

    This fixture provides a properly configured TestClient for making requests
    to the API in tests. It ensures authentication middleware is properly set up
    to handle test tokens and auth bypass headers.

    Returns:
        TestClient: Configured TestClient for making authenticated requests
    """
    logger.info("test_client fixture: Initializing test client")

    # Create client with lifespan context
    client = TestClient(test_app)

    # Log client creation
    logger.info(
        f"test_client fixture: Yielding client for app id used by transport: {id(test_app)}"
    )

    # Add helper methods for authenticated requests
    def get_auth_headers(role: str = "clinician", user_id: str | None = None):
        """Get authentication headers for the given role."""
        if user_id is None:
            user_id = "00000000-0000-0000-0000-000000000002"  # Default test clinician ID
            if role.lower() == "admin":
                user_id = "00000000-0000-0000-0000-000000000001"  # Admin ID
            elif role.lower() == "patient":
                user_id = "00000000-0000-0000-0000-000000000003"  # Patient ID

        # Create a JWT token
        token = create_test_token(
            subject=f"test.{role.lower()}@example.com",
            user_id=user_id,
            roles=[role.lower()],
        )

        return {
            "Authorization": f"Bearer {token}",
            "X-Test-Auth-Bypass": f"{role}:{user_id}",
        }

    # Attach helper method to client
    client.get_auth_headers = get_auth_headers

    return client


@pytest.fixture
def auth_headers():
    """Provide authentication headers for different roles."""

    def _auth_headers(role: str = "clinician", user_id: str | None = None):
        """Get auth headers for a specific role."""
        if user_id is None:
            user_id = "00000000-0000-0000-0000-000000000002"  # Default test clinician ID
            if role.lower() == "admin":
                user_id = "00000000-0000-0000-0000-000000000001"  # Admin ID
            elif role.lower() == "patient":
                user_id = "00000000-0000-0000-0000-000000000003"  # Patient ID

        return {"X-Test-Auth-Bypass": f"{role}:{user_id}"}

    return _auth_headers


# Add Redis service mock fixture


@pytest.fixture
def mock_redis_service() -> IRedisService:
    """
    Provides a mock Redis service implementing IRedisService for testing.

    This mock allows tests requiring Redis to run without an actual Redis instance.
    It simulates Redis operations in memory for test isolation.

    Returns:
        IRedisService: A mock implementation of the Redis service interface
    """
    return create_mock_redis_service()


# Override Redis dependency in FastAPI app
@pytest.fixture
def override_redis_dependency(test_app: FastAPI, mock_redis_service: IRedisService) -> FastAPI:
    """
    Overrides the Redis service dependency in the FastAPI app for testing.

    This allows tests to use a mock Redis service instead of a real one.

    Args:
        test_app: The FastAPI application instance
        mock_redis_service: The mock Redis service to use

    Returns:
        FastAPI: The modified FastAPI app with Redis dependency overridden
    """
    # Import the dependency provider to override
    from app.presentation.api.dependencies.redis import get_redis_service

    # Store original dependency override to restore later if needed
    original_dependencies = test_app.dependency_overrides.copy()

    # Override the dependency
    test_app.dependency_overrides[get_redis_service] = lambda: mock_redis_service

    yield test_app

    # Restore original dependencies after test
    test_app.dependency_overrides = original_dependencies


# Add this fixture after db_session_mock fixture


@pytest_asyncio.fixture
async def db_session_mock() -> AsyncGenerator[MagicMock, None]:
    """
    Creates a mock database session that can be used for tests that need database access
    but don't want to use the real database.

    This mock session implements all AsyncSession methods and can be used to mock
    repository dependencies that require a database session.

    Returns:
        AsyncMock: An AsyncMock instance configured to behave like an AsyncSession
    """
    logger.info("Creating mock database session for tests")

    # Create a comprehensive AsyncMock that simulates AsyncSession
    mock_session = AsyncMock()

    # Mock execute method with a default behavior that returns a mock result
    mock_result = MagicMock()
    mock_result.scalars.return_value.first.return_value = None
    mock_result.scalar_one_or_none.return_value = None
    mock_result.scalar.return_value = None
    mock_result.scalar_one.side_effect = Exception("No row found")
    mock_result.one_or_none.return_value = None
    mock_result.one.side_effect = Exception("No row found")
    mock_result.all.return_value = []

    # Connect the mock_result to the session's execute method
    mock_session.execute.return_value = mock_result

    # Mock the other AsyncSession methods
    mock_session.commit.return_value = None
    mock_session.rollback.return_value = None
    mock_session.close.return_value = None
    mock_session.refresh.return_value = None

    # Properly simulate context manager behavior
    mock_session.__aenter__.return_value = mock_session
    mock_session.__aexit__.return_value = None

    # Provide a way to customize the return values of different query methods
    def configure_query_result(result_data, method="all") -> None:
        """Helper to configure the mock session to return specific results for queries.

        Args:
            result_data: The data to return from the query
            method: The query method to mock ('all', 'first', 'one', 'one_or_none', etc.)
        """
        if method == "all":
            mock_result.all.return_value = result_data
            mock_result.scalars.return_value.all.return_value = result_data
        elif method == "first":
            mock_result.first.return_value = result_data
            mock_result.scalars.return_value.first.return_value = result_data
        elif method == "one":
            mock_result.one.return_value = result_data
            mock_result.scalars.return_value.one.return_value = result_data
        elif method == "one_or_none":
            mock_result.one_or_none.return_value = result_data
            mock_result.scalars.return_value.one_or_none.return_value = result_data
        elif method == "scalar":
            mock_result.scalar.return_value = result_data
        elif method == "scalar_one":
            mock_result.scalar_one.return_value = result_data
        elif method == "scalar_one_or_none":
            mock_result.scalar_one_or_none.return_value = result_data

    # Attach the configuration helper to the mock session
    mock_session.configure_query_result = configure_query_result

    yield mock_session


# Add a repository mock factory fixture
@pytest.fixture
def repository_mock_factory():
    """
    Creates a factory function that builds mock repository instances for testing.

    This allows tests to easily create mock repositories with customizable behavior
    without having to implement all repository methods.

    Returns:
        Callable: A factory function that creates mock repositories
    """

    def create_mock_repository(repo_interface, **method_returns):
        """
        Create a mock repository that implements the specified interface

        Args:
            repo_interface: The repository interface class to mock
            **method_returns: Dict of method names and their return values

        Returns:
            MagicMock: A configured mock repository implementing the interface
        """
        mock_repo = MagicMock(spec=repo_interface)

        # Configure each method with a default AsyncMock
        # This makes all methods async and returns None by default
        for method_name in dir(repo_interface):
            # Skip dunder methods, properties, and non-callable attributes
            if (
                method_name.startswith("_")
                or isinstance(getattr(repo_interface, method_name, None), property)
                or not callable(getattr(repo_interface, method_name, None))
            ):
                continue

            # Create an AsyncMock for this method
            method_mock = AsyncMock()
            setattr(mock_repo, method_name, method_mock)

        # Update methods with specific return values if provided
        for method_name, return_value in method_returns.items():
            if hasattr(mock_repo, method_name):
                getattr(mock_repo, method_name).return_value = return_value

        return mock_repo

    return create_mock_repository


# Add this fixture after repository_mock_factory


@pytest.fixture
def override_repository_dependencies(repository_mock_factory):
    """
    Fixture to override repository dependencies in the app for tests.

    This fixture allows tests to easily override repository dependencies
    in the FastAPI app to use mock repositories instead of real ones.

    Args:
        repository_mock_factory: Factory function to create mock repositories

    Returns:
        Callable: A function that can be used to override repository dependencies
    """

    def _override_dependencies(app: FastAPI, repository_overrides: dict):
        """
        Override repository dependencies in the app with mock repositories.

        Args:
            app: The FastAPI app instance
            repository_overrides: Dict mapping dependency functions to repository interfaces and custom returns
                Example: {get_user_repository: (IUserRepository, {"get_by_id": mock_user})}

        Returns:
            dict: The original dependency_overrides before overriding
        """
        # Store original overrides to restore later if needed
        original_overrides = app.dependency_overrides.copy()

        # Create and apply mock repositories
        for dependency_func, (
            repo_interface,
            method_returns,
        ) in repository_overrides.items():
            mock_repo = repository_mock_factory(repo_interface, **method_returns)
            app.dependency_overrides[dependency_func] = lambda: mock_repo

        return original_overrides

    return _override_dependencies


@pytest.fixture
def app_with_mocked_repositories(
    app_instance: FastAPI, repository_mock_factory, override_repository_dependencies
):
    """
    Provides a FastAPI app instance with common repository dependencies mocked.

    This fixture creates an app instance with UserRepository, PatientRepository,
    and other commonly used repositories mocked out for testing.

    Returns:
        FastAPI: App instance with mocked repositories
    """
    from app.core.interfaces.repositories.patient_repository import IPatientRepository
    from app.core.interfaces.repositories.user_repository_interface import (
        IUserRepository,
    )
    from app.presentation.api.dependencies.auth import get_user_repository_dependency
    from app.presentation.api.dependencies.database import (
        get_patient_repository_dependency,
    )

    # Create a test user for auth tests
    test_user = User(
        id=uuid.UUID("00000000-0000-0000-0000-000000000001"),
        username="test_user",
        email="test.user@clarity.health",
        full_name="Test User",
        password_hash="$2b$12$TestPasswordHashForTestingOnly",
        roles={UserRole.PATIENT},
        account_status=UserStatus.ACTIVE,
    )

    # Create a test patient
    test_patient = MagicMock()
    test_patient.id = uuid.UUID("00000000-0000-0000-0000-000000000001")
    test_patient.first_name = "Test"
    test_patient.last_name = "Patient"
    test_patient.date_of_birth = datetime(1990, 1, 1)
    test_patient.email = "test.patient@clarity.health"

    # Override common repository dependencies
    override_repository_dependencies(
        app_instance,
        {
            get_user_repository_dependency: (
                IUserRepository,
                {
                    "get_by_id": test_user,
                    "get_by_email": test_user,
                    "get_by_username": test_user,
                },
            ),
            get_patient_repository_dependency: (
                IPatientRepository,
                {"get_by_id": test_patient},
            ),
        },
    )

    return app_instance
