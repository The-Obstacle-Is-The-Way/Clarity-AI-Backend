"""
Integration Test Configuration and Fixtures

This file contains test fixtures specific to integration tests which may
require network connections, databases, and other external services.
"""

import logging
import uuid
from collections.abc import AsyncGenerator
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from asgi_lifespan import LifespanManager

# Import JWT service interface
from app.core.interfaces.services.jwt_service import IJwtService
from app.core.interfaces.aws_service_interface import S3ServiceInterface, AWSServiceFactory
from app.core.interfaces.services.encryption_service_interface import IEncryptionService
from app.presentation.api.dependencies.repository import get_encryption_service
from app.infrastructure.aws.service_factory_provider import get_aws_service_factory
from app.core.config import Settings

# Added imports for mock JWT service
from app.core.interfaces.services.jwt_service_interface import JWTServiceInterface
from app.infrastructure.security.jwt_service import get_jwt_service as get_jwt_service_provider
from app.core.models.token_models import TokenPayload
from app.core.domain.entities.user import UserRole
from app.domain.exceptions.token_exceptions import InvalidTokenException
# Import the predefined test user UUIDs
from app.tests.integration.utils.test_db_initializer import TEST_USER_ID, TEST_CLINICIAN_ID
# End of added imports

# Import SQLAlchemy models and utils
from app.infrastructure.persistence.sqlalchemy.registry import metadata as main_metadata

# Import the FastAPI application
# Import test database initializer functions
from app.tests.integration.utils.test_db_initializer import create_test_users, get_test_db_session

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
    from app.infrastructure.security.jwt_service import JWTService
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
        "jti": str(uuid.uuid4())
    }
    # create_access_token is now synchronous
    token = jwt_service.create_access_token(data=token_data)
    
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

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
        "jti": str(uuid.uuid4())
    }
    
    # create_access_token is now synchronous
    token = jwt_service.create_access_token(data=token_data)
    
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

# API Testing Fixtures
@pytest_asyncio.fixture
async def test_app(
    test_settings: Settings,
    mock_s3_service: MagicMock, 
    mock_encryption_service: MagicMock, 
    mock_jwt_service_with_placeholder_handling: JWTServiceInterface
) -> FastAPI:
    logger.info("Creating FastAPI app instance for integration tests via integration/conftest.py (test_app fixture).")
    
    from app.app_factory import create_application # Moved import here to be self-contained
    app = create_application(settings_override=test_settings)

    mock_aws_factory = MagicMock(spec=AWSServiceFactory)
    mock_aws_factory.get_s3_service.return_value = mock_s3_service
    
    app.dependency_overrides[get_aws_service_factory] = lambda: mock_aws_factory
    app.dependency_overrides[get_encryption_service] = lambda: mock_encryption_service
    app.dependency_overrides[get_jwt_service_provider] = lambda: mock_jwt_service_with_placeholder_handling
    
    # Removed: async with LifespanManager(app):
    yield app # Just yield the configured app

@pytest_asyncio.fixture
async def test_client(test_app: FastAPI) -> AsyncGenerator[AsyncClient, None]:  
    """Provides an AsyncClient instance configured for the test_app, managing its lifespan."""
    from httpx import ASGITransport # Moved import here
    from asgi_lifespan import LifespanManager # Moved import here
    
    logger.info(f"test_client fixture: Managing lifespan for test_app with id: {id(test_app)}")
    
    async with LifespanManager(test_app) as manager:
        logger.info(f"test_client fixture: LifespanManager active for app id: {id(manager.app)}")
        transport = ASGITransport(app=manager.app) 
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            logger.info(f"test_client fixture: Yielding client for app id used by transport: {id(manager.app)}")
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
            data = data.encode('utf-8')
        elif not isinstance(data, bytes):
            data = str(data).encode('utf-8')
        return b'ENCRYPTED_' + data
    
    def mock_decrypt(data):
        """Mock decrypt by removing 'ENCRYPTED_' prefix."""
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        if data.startswith(b'ENCRYPTED_'):
            return data[len(b'ENCRYPTED_'):]
        return data  # Return as-is if not properly encrypted
    
    mock_service.encrypt.side_effect = mock_encrypt
    mock_service.decrypt.side_effect = mock_decrypt
    
    return mock_service


@pytest.fixture
def mock_jwt_service_with_placeholder_handling() -> JWTServiceInterface:
    """
    Provides a mock JWTService that handles placeholder token strings
    and returns corresponding TokenPayload objects.
    """
    # This mock JWT service fixture is designed to handle placeholder tokens
    # used in some integration tests, returning predefined TokenPayload objects.
    mock_service = MagicMock(spec=JWTServiceInterface)

    def decode_token_side_effect(token: str, audience: str | None = None) -> TokenPayload: # Added audience to match interface
        logger.info(f"Mock JWT Service: Decoding token '{token}'")
        if token == "VALID_PATIENT_TOKEN":
            # Return a TokenPayload for a mock patient
            # Ensure 'sub' is the predefined TEST_USER_ID
            return TokenPayload(
                sub=str(TEST_USER_ID), # Use predefined patient UUID
                username="mockpatient_placeholder", # Matches test_db_initializer
                email="test.user@novamind.ai",    # Matches test_db_initializer
                role=UserRole.PATIENT,
                roles=[UserRole.PATIENT],
                jti=str(uuid.uuid4()), # Placeholder JTI
                exp=9999999999,  # Far future expiration
                iat=0,  # Issued at epoch
            )
        elif token == "VALID_PROVIDER_TOKEN":
            # Return a TokenPayload for a mock provider/clinician
            # Ensure 'sub' is the predefined TEST_CLINICIAN_ID
            return TokenPayload(
                sub=str(TEST_CLINICIAN_ID), # Use predefined clinician UUID
                username="mockprovider_placeholder", # Username can be a placeholder
                email="test.clinician@novamind.ai", # Matches test_db_initializer
                role=UserRole.CLINICIAN,
                roles=[UserRole.CLINICIAN],
                jti=str(uuid.uuid4()), # Placeholder JTI
                exp=9999999999,  # Far future expiration
                iat=0,  # Issued at epoch
            )
        elif token == "VALID_ADMIN_TOKEN":
            return TokenPayload(
                sub="mock_admin_id_placeholder",
                username="mockadmin_placeholder",
                email="admin_placeholder@example.com",
                role=UserRole.ADMIN,
                roles=[UserRole.ADMIN],
                jti=str(uuid.uuid4()),
                exp=9999999999,
                iat=0,
                active=True,
                verified=True
            )
        elif token == "EXPIRED_TOKEN":
            raise InvalidTokenException("Token has expired")
        elif token == "INVALID_SIGNATURE_TOKEN":
            raise InvalidTokenException("Invalid token signature (mocked)")
        elif token == "MALFORMED_TOKEN":
            raise InvalidTokenException("Malformed token (mocked)")
        else:
            # Attempt to decode as a real JWT if not a placeholder,
            # or raise specific error for unhandled placeholders.
            # For now, let's assume any other string is an unhandled placeholder.
            raise InvalidTokenException(f"Token not recognized by mock_jwt_service_with_placeholder_handling: {token}")

    mock_service.decode_token.side_effect = decode_token_side_effect
    # Mock create_access_token if it's called by the application during tests, though less likely for override scenario
    # mock_service.create_access_token.return_value = "MOCK_JWT_TOKEN_FROM_CREATE"
    return mock_service


@pytest.fixture
def mock_mentallama_api() -> Any:
    """
    Provides a mock for the MentaLLama API service.

    Returns:
        A mock MentaLLama API client.
    """

    class MockMentaLLamaAPI:
        async def predict(
            self, patient_id: str, data: dict[str, Any]
        ) -> dict[str, Any]:
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
        def invoke_endpoint(
            self, endpoint_name: str, data: dict[str, Any]
        ) -> dict[str, Any]:
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

        def download_file(
            self,
            bucket: str,
            key: str,
            local_path: str
        ) -> bool:
            # Simulate creating a file
            with open(local_path, "w") as f:
                f.write('{"mock": "data"}')
            return True

    return MockAWSService()


@pytest.fixture
def integration_fixture():
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
    return csv_content.encode('utf-8')

@pytest_asyncio.fixture
async def test_app_with_db_session(
    test_settings: Settings,
    mock_s3_service: MagicMock, 
    mock_encryption_service: MagicMock, 
    mock_jwt_service_with_placeholder_handling: JWTServiceInterface,
    test_db_engine
) -> AsyncGenerator[FastAPI, None]:
    """
    Creates a FastAPI app with fully initialized database session factory in app.state
    for tests that require database access through FastAPI dependency injection.
    """
    logger.info("Creating FastAPI app instance with DB session factory for integration tests")
    
    from app.app_factory import create_application
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    # Create the app instance
    app = create_application(settings_override=test_settings)
    
    # Create a properly configured session factory
    db_session_factory = async_sessionmaker(
        bind=test_db_engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False
    )
    
    # CRITICAL: Set the session factory directly in app.state
    # This is what the app will use for database access in API endpoints
    app.state.db_session_factory = db_session_factory
    
    # Add mock service overrides
    mock_aws_factory = MagicMock(spec=AWSServiceFactory)
    mock_aws_factory.get_s3_service.return_value = mock_s3_service
    
    app.dependency_overrides[get_aws_service_factory] = lambda: mock_aws_factory
    app.dependency_overrides[get_encryption_service] = lambda: mock_encryption_service
    app.dependency_overrides[get_jwt_service_provider] = lambda: mock_jwt_service_with_placeholder_handling
    
    # Verify session factory was set correctly
    logger.info(f"Created db_session_factory in app.state: {app.state.db_session_factory}")
    
    # Initialize the application's lifespan context to ensure proper setup
    async with LifespanManager(app):
        try:
            # Verify session factory is available
            if not hasattr(app.state, 'db_session_factory') or app.state.db_session_factory is None:
                logger.error("db_session_factory not available in app.state after lifespan initialization!")
                raise RuntimeError("Failed to set db_session_factory in app.state")
                
            logger.info("Application lifespan startup completed, db_session_factory is properly set")
            yield app
        finally:
            # Clean up as needed
            logger.info("Cleaning up test_app_with_db_session fixture")
            if hasattr(app.state, 'db_session_factory'):
                app.state.db_session_factory = None

@pytest_asyncio.fixture
async def test_client_with_db_session(test_app_with_db_session: FastAPI) -> AsyncGenerator[AsyncClient, None]:  
    """Provides an AsyncClient instance configured with DB session factory"""
    async with AsyncClient(app=test_app_with_db_session, base_url="http://test") as client:
        yield client

@pytest_asyncio.fixture
async def test_app_with_auth_override(test_app_with_db_session: FastAPI, mock_auth_dependency) -> FastAPI:
    """
    Provides a test app with authentication dependencies overridden for testing different
    user roles without actual authentication.
    """
    from app.presentation.api.dependencies.auth import (
        get_current_user, 
        get_current_active_user,
        require_admin_role,
        require_clinician_role
    )
    
    # Override authentication dependencies with appropriate role handlers
    test_app_with_db_session.dependency_overrides[get_current_user] = mock_auth_dependency("PATIENT")
    test_app_with_db_session.dependency_overrides[get_current_active_user] = mock_auth_dependency("DEFAULT")
    test_app_with_db_session.dependency_overrides[require_admin_role] = mock_auth_dependency("ADMIN")
    test_app_with_db_session.dependency_overrides[require_clinician_role] = mock_auth_dependency("CLINICIAN")
    
    return test_app_with_db_session

@pytest_asyncio.fixture
async def authenticated_client(
    test_app_with_db_session: FastAPI,
    mock_auth_dependency
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
    from app.presentation.api.dependencies.auth import (
        get_current_user, 
        get_current_active_user,
        require_admin_role,
        require_clinician_role
    )
    
    # Set up the authentication overrides using the patient role by default
    test_app_with_db_session.dependency_overrides[get_current_user] = lambda: mock_auth_dependency("PATIENT")
    test_app_with_db_session.dependency_overrides[get_current_active_user] = lambda: mock_auth_dependency("PATIENT")
    
    # Create the client with the authenticated app
    async with AsyncClient(
        app=test_app_with_db_session,
        base_url="http://test"
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
    # Import here to avoid circular imports
    from app.presentation.api.dependencies.auth import (
        get_current_user, 
        get_current_active_user,
        require_admin_role,
        require_clinician_role
    )
    from app.core.domain.entities.user import User, UserRole, UserStatus
    
    # Create mock users for different roles
    mock_patient = User(
        id=uuid.UUID("00000000-0000-0000-0000-000000000001"),  # TEST_USER_ID
        username="test_patient",
        email="test.patient@example.com",
        full_name="Test Patient",
        password_hash="not_a_real_hash",
        roles={UserRole.PATIENT},
        status=UserStatus.ACTIVE
    )
    
    mock_provider = User(
        id=uuid.UUID("00000000-0000-0000-0000-000000000002"),  # TEST_CLINICIAN_ID 
        username="test_provider",
        email="test.provider@example.com",
        full_name="Test Provider",
        password_hash="not_a_real_hash",
        roles={UserRole.CLINICIAN},
        status=UserStatus.ACTIVE
    )
    
    mock_admin = User(
        id=uuid.UUID("00000000-0000-0000-0000-000000000003"),
        username="test_admin",
        email="test.admin@example.com",
        full_name="Test Admin",
        password_hash="not_a_real_hash",
        roles={UserRole.ADMIN},
        status=UserStatus.ACTIVE
    )
    
    # Store the mock users by role type
    mock_users = {
        "PATIENT": mock_patient,
        "CLINICIAN": mock_provider,
        "ADMIN": mock_admin,
        "DEFAULT": mock_provider,  # Default to provider since many endpoints require a clinician
    }
    
    # Create async dependency override functions
    async def mock_get_current_user():
        return mock_users["DEFAULT"]
        
    async def mock_get_current_active_user():
        return mock_users["DEFAULT"]
        
    async def mock_require_admin_role():
        return mock_users["ADMIN"]
        
    async def mock_require_clinician_role():
        return mock_users["CLINICIAN"]
    
    # Return a function that can be used to override dependencies
    def override_dependency(role: str = "DEFAULT"):
        if role == "ADMIN":
            return mock_require_admin_role
        elif role == "CLINICIAN":
            return mock_require_clinician_role
        elif role == "PATIENT":
            return mock_get_current_user
        else:
            return mock_get_current_active_user
    
    return override_dependency
