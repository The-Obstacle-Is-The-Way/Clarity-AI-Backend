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
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

# Import JWT service interface
from app.core.interfaces.services.jwt_service import IJwtService
from app.core.interfaces.aws_service_interface import S3ServiceInterface
from app.core.interfaces.services.encryption_service_interface import IEncryptionService
from app.core.config import Settings

# Import SQLAlchemy models and utils
from app.infrastructure.persistence.sqlalchemy.models.base import ensure_all_models_loaded
from app.infrastructure.persistence.sqlalchemy.registry import validate_models

# Import the FastAPI application
# Import test database initializer functions
from app.tests.integration.utils.test_db_initializer import create_test_users, get_test_db_session

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize models
ensure_all_models_loaded()
validate_models()


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
            ensure_all_models_loaded()
            
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
    # db_session: AsyncSession, # REMOVE THIS - Lifespan handles DB init for the app
    test_settings: Settings,
    mock_s3_service: MagicMock,
    mock_encryption_service: MagicMock
) -> FastAPI:
    logger.info("Creating FastAPI app instance for integration tests via integration/conftest.py.")
    
    # Use the application factory
    from app.main import create_application
    app = create_application(settings_override=test_settings)

    # Apply common overrides for integration tests
    app.dependency_overrides[get_s3_service] = lambda: mock_s3_service
    app.dependency_overrides[get_encryption_service] = lambda: mock_encryption_service
    
    logger.info(f"App '{app.title}' created. Lifespan will run when client starts. Settings env: {app.state.settings.ENVIRONMENT}")
    return app

@pytest_asyncio.fixture
async def test_client(test_app: FastAPI) -> AsyncGenerator[AsyncClient, None]:  
    """
    Creates a real test client for API integration testing with properly configured
    test application with all required dependencies injected.

    Yields:
        A FastAPI AsyncClient instance configured for testing.
    """
    async with AsyncClient(app=test_app, base_url="http://test") as client:
        yield client


# External Service Mocks
@pytest.fixture
def mock_encryption_service() -> IEncryptionService:
    """
    Provides a mock implementation of the encryption service interface.
    For integration tests, this often just needs to pass data through.
    """
    mock_service = MagicMock(spec=IEncryptionService)
    mock_service.encrypt.side_effect = lambda data: data.encode() if isinstance(data, str) else data
    mock_service.decrypt.side_effect = lambda data: data.decode() if isinstance(data, bytes) else data
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
