"""
MentaLLaMA API Integration Tests.

This module contains integration tests for the MentaLLaMA API routes, following
clean architecture principles with precise, mathematically elegant implementations.
"""

import logging
from collections.abc import AsyncGenerator
from unittest.mock import AsyncMock, MagicMock
from typing import Optional

import asyncio
import pytest
import pytest_asyncio
from app.tests.utils.asyncio_helpers import run_with_timeout
import asyncio
import pytest
from app.tests.utils.asyncio_helpers import run_with_timeout_asyncio
from httpx import AsyncClient, ASGITransport
from fastapi import FastAPI
from datetime import datetime, timezone, timedelta
import uuid
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from app.infrastructure.persistence.sqlalchemy.models.base import Base
from app.domain.entities.audit_log import AuditLog
from app.core.interfaces.services.audit_logger_interface import AuditEventType, IAuditLogger, AuditSeverity
from app.application.services.audit_log_service import AuditLogService
from app.core.security.rate_limiting.middleware import RateLimitingMiddleware

# Application imports (Sorted)
from app.app_factory import create_application
from app.core.config import Settings
from app.core.interfaces.services.authentication_service import IAuthenticationService
from app.core.interfaces.services.jwt_service import IJwtService
from app.core.services.ml.interface import MentaLLaMAInterface
from app.core.models.token_models import TokenPayload
from app.domain.entities.user import User
from app.domain.models.user import UserRole
from app.presentation.api.dependencies.auth import get_current_user, get_current_active_user
from app.presentation.api.v1.dependencies.digital_twin import get_mentallama_service
from app.presentation.api.dependencies.auth import get_jwt_service

logger = logging.getLogger(__name__)

# Setup logging
logging.basicConfig(level=logging.INFO)

# Define the base URL for the API version being tested
BASE_URL = "/api/v1/mentallama"

# Configuration & Constants
TEST_PROMPT = "This is a test prompt."
TEST_USER_ID = "00000000-0000-0000-0000-000000000001"
TEST_MODEL = "test_model"
MENTALLAMA_API_PREFIX = f"{Settings().API_V1_STR}/mentallama"

# Create a mock audit logger that doesn't use the database
class MockAuditLogService(IAuditLogger):
    """Mock implementation of IAuditLogger for testing that doesn't access the database."""
    
    async def log_event(self, event_type: AuditEventType, actor_id: str, 
                       resource_type: Optional[str] = None, resource_id: Optional[str] = None,
                       action: Optional[str] = None, metadata: Optional[dict] = None, 
                       ip_address: Optional[str] = None, details: Optional[str] = None) -> str:
        """Log an event without using the database."""
        return str(uuid.uuid4())
        
    async def log_phi_access(self, actor_id: str, resource_type: str, resource_id: str,
                           action: str, metadata: Optional[dict] = None,
                           ip_address: Optional[str] = None, details: Optional[str] = None) -> str:
        """Log PHI access without using the database."""
        return str(uuid.uuid4())
        
    async def log_security_event(self, event_type: AuditEventType, actor_id: str,
                               details: str, metadata: Optional[dict] = None,
                               ip_address: Optional[str] = None) -> str:
        """Log security event without using the database."""
        return str(uuid.uuid4())
        
    async def log_admin_action(self, actor_id: str, action: str, 
                              resource_type: Optional[str] = None, resource_id: Optional[str] = None,
                              metadata: Optional[dict] = None, details: Optional[str] = None) -> str:
        """Log admin action without using the database."""
        return str(uuid.uuid4())
        
    async def log_login(self, user_id: str, success: bool, ip_address: Optional[str] = None, 
                       details: Optional[str] = None) -> str:
        """Log login event without using the database."""
        return str(uuid.uuid4())
        
    async def log_logout(self, user_id: str, ip_address: Optional[str] = None) -> str:
        """Log logout event without using the database."""
        return str(uuid.uuid4())
        
    async def log_system_event(self, event_type: str, details: str, 
                             component: Optional[str] = None, 
                             metadata: Optional[dict] = None) -> str:
        """Log system event without using the database."""
        return str(uuid.uuid4())


@pytest.fixture
def auth_headers() -> dict[str, str]:
    """
    Create authentication headers for testing.
    
    Returns:
        Dictionary with authentication headers
    """
    # Token format must have at least 3 segments (header.payload.signature)
    mock_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0X3VzZXJfMTIzIiwicm9sZSI6IlBBVElFTlQiLCJyb2xlcyI6WyJQQVRJRU5UIl0sImV4cCI6OTk5OTk5OTk5OX0.thisisafakesignature"
    return {"Authorization": f"Bearer {mock_token}"}


@pytest_asyncio.fixture(scope="function")
async def mock_mentallama_service_instance() -> AsyncMock:
    """Provides a mock Mentallama service dependency override 
    with pre-configured return values.
    """
    # Create a mock instance respecting the MentaLLaMAInterface spec
    mock = AsyncMock(spec=MentaLLaMAInterface)
    
    # Mock is_healthy method to return True for health checks
    mock.is_healthy.return_value = True
    
    # Create async process method that returns a proper dictionary
    async def process_side_effect(*args, **kwargs):
        """Process method implementation that handles different parameter formats.
        Some endpoints pass text=..., others pass prompt=..., and the kwargs vary.
        """
        # Get the input text from either the 'text' or 'prompt' parameter
        input_text = kwargs.get('text', kwargs.get('prompt', ''))
        model_type = kwargs.get('model_type', kwargs.get('model', 'default'))
        
        # Return different responses based on the model_type
        if model_type == "analysis":
            return {
                "success": True,
                "analysis": {
                    "sentiment": "positive",
                    "topics": ["health", "wellness"],
                    "emotions": ["happy", "content"]
                }
            }
        elif model_type == "conditions":
            return {
                "success": True,
                "conditions": [
                    {"name": "anxiety", "confidence": 0.3},
                    {"name": "depression", "confidence": 0.1}
                ]
            }
        elif model_type == "therapeutic":
            return {
                "success": True,
                "response": "I understand you're feeling that way. Let's explore this further."
            }
        elif model_type == "risk":
            return {
                "success": True,
                "risk_level": "low",
                "assessment": "No immediate risk detected",
                "recommendations": ["Regular follow-up"]
            }
        elif model_type == "wellness":
            return {
                "success": True,
                "dimensions": {
                    "physical": 0.8,
                    "emotional": 0.7,
                    "social": 0.6,
                    "spiritual": 0.5
                },
                "assessment": "Overall positive wellness profile"
            }
        else:
            # Default response for any other model type
            return {
                "success": True,
                "generated_text": f"Response for {input_text} using {model_type}",
                "model_used": model_type,
                "processing_time": 0.1
            }
    
    # Mock the process method with our implementation
    mock.process.side_effect = process_side_effect
    
    return mock


@pytest.fixture(scope="function")
def mock_auth_service() -> MagicMock:
    """Provides a mock JWTService dependency override,
    simplifying token verification for tests.
    """
    mock = MagicMock(spec=IAuthenticationService)

    # Mock ASYNC methods using AsyncMock
    # Create a mock User object or dictionary as needed for return types
    mock_user = MagicMock()
    mock_user.id = TEST_USER_ID
    mock_user.username = "testuser"
    # Add other necessary User attributes if the code being tested uses them

    mock.authenticate_user = AsyncMock(return_value=mock_user)
    mock.get_user_by_id = AsyncMock(return_value=mock_user)

    # Mock SYNC methods using standard return_value
    mock.create_access_token.return_value = "mock_access_token"
    mock.create_refresh_token.return_value = "mock_refresh_token"
    mock.create_token_pair.return_value = {
        "access_token": "mock_access_token",
        "refresh_token": "mock_refresh_token",
    }
    mock.refresh_token.return_value = {
        "access_token": "new_mock_access_token",
        "refresh_token": "mock_refresh_token",
    }
    # Removed: mock.verify_token - Method doesn't exist on interface

    return mock


@pytest.fixture
def global_mock_jwt_service() -> MagicMock:
    """
    Provides a mock JWT service for tests.
    
    Returns:
        MagicMock: JWT service mock with test functionality
    """
    mock = MagicMock(spec=IJwtService)
    
    # Mock token creation function
    async def create_access_token_side_effect(data=None, expires_delta=None):
        return "test.jwt.token"
    
    mock.create_access_token = AsyncMock(side_effect=create_access_token_side_effect)
    
    # Mock token decoding function
    async def decode_token_side_effect(token, audience=None):
        # Return a valid payload regardless of the token input
        return TokenPayload(
            sub=TEST_USER_ID,
            exp=int((datetime.now(timezone.utc) + timedelta(minutes=30)).timestamp()),
            iat=int(datetime.now(timezone.utc).timestamp()),
            jti=str(uuid.uuid4()),
            role="PATIENT",
            roles=["PATIENT"],
            username="testuser", 
            verified=True,
            active=True
        )
    
    mock.decode_token = AsyncMock(side_effect=decode_token_side_effect)
    
    return mock


# --- New Fixture for MentaLLaMA Test Client --- #
@pytest_asyncio.fixture
async def mentallama_test_client(
    client_app_tuple_func_scoped: tuple[AsyncClient, FastAPI], 
    mock_mentallama_service_instance: AsyncMock,
    global_mock_jwt_service: MagicMock
) -> AsyncClient:
    """Provides a test client with MentaLLaMA service dependency overridden."""
    client, app = client_app_tuple_func_scoped
    
    # Log app type for debugging
    logging.info(f"MENTALLAMA_TEST_CLIENT: Received app_from_fixture of type: {type(app)}")
    
    if not isinstance(app, FastAPI):
        logging.warning(f"MENTALLAMA_TEST_CLIENT: app_from_fixture is not FastAPI: {type(app)}. Trying to get FastAPI app from it.")
        app = app.app  # Try to get the FastAPI app
    else:
        logging.info(f"MENTALLAMA_TEST_CLIENT: app_from_fixture is already FastAPI type: {type(app)}. Using it directly for overrides.")
    
    # Override MentaLLaMA service
    app.dependency_overrides[get_mentallama_service] = lambda: mock_mentallama_service_instance
    logging.info(f"MENTALLAMA_TEST_CLIENT: Overrode MentaLLaMAInterface on app {id(app)}")
    
    # Override JWT service
    app.dependency_overrides[get_jwt_service] = lambda: global_mock_jwt_service
    logging.info(f"MENTALLAMA_TEST_CLIENT: Overrode IJwtService on app {id(app)} with global_mock_jwt_service ID: {id(global_mock_jwt_service)}")
    
    # Override audit log service with our mock
    mock_audit_service = MockAuditLogService()
    app.dependency_overrides[get_audit_log_service] = lambda: mock_audit_service
    logging.info(f"MENTALLAMA_TEST_CLIENT: Overrode AuditLogService with MockAuditLogService")
    
    # Set the mock audit logger on app.state to use in middleware
    app.state.audit_logger = mock_audit_service
    
    # Override get_current_user dependency with a mock user
    async def mock_get_current_user():
        """Returns a mock user for testing."""
        return User(
            id=TEST_USER_ID,
            username="testuser",
            email="test@example.com",
            role=UserRole.PATIENT.value,
            is_active=True,
            is_verified=True,
            roles=[UserRole.PATIENT]
        )
    
    # Override get_current_active_user to avoid account_status check
    async def mock_get_current_active_user():
        """Returns a mock active user for testing without checking account_status."""
        return await mock_get_current_user()
    
    # Override both dependencies
    app.dependency_overrides[get_current_user] = mock_get_current_user
    app.dependency_overrides[get_current_active_user] = mock_get_current_active_user
    
    logging.info(f"MENTALLAMA_TEST_CLIENT: Overrode get_current_user and get_current_active_user dependencies on app {id(app)}")
    
    yield client
    
    # Clear dependency overrides after test
    app.dependency_overrides.clear()
    logging.info(f"MENTALLAMA_TEST_CLIENT: Cleared dependency_overrides on app {id(app)}")


# --- Test Functions (Updated to use mentallama_test_client) --- #

@pytest.mark.asyncio
async def test_health_check(mentallama_test_client: AsyncClient, auth_headers: dict[str, str]) -> None:
    """Tests the health check endpoint."""
    response = await mentallama_test_client.get(f"{MENTALLAMA_API_PREFIX}/health", headers=auth_headers)
    assert response.status_code == 200
    # Check if the mocked service's healthy status is reflected
    assert response.json() == {"status": "healthy", "service_status": True}

@pytest.mark.asyncio
async def test_process_endpoint(mentallama_test_client: AsyncClient, auth_headers: dict[str, str]) -> None:
    """Tests the process endpoint with valid input."""
    payload = {"prompt": TEST_PROMPT, "user_id": TEST_USER_ID, "model": TEST_MODEL}
    response = await mentallama_test_client.post(
        f"{MENTALLAMA_API_PREFIX}/process", json=payload, headers=auth_headers
    )
    assert response.status_code == 200
    # Check response matches our mock implementation
    response_json = response.json()
    assert response_json["success"] is True
    assert response_json["generated_text"] == f"Response for {TEST_PROMPT} using {TEST_MODEL}"
    assert response_json["model_used"] == TEST_MODEL
    assert "processing_time" in response_json

@pytest.mark.asyncio
async def test_analyze_text_endpoint(mentallama_test_client: AsyncClient, auth_headers: dict[str, str]) -> None:
    """Tests the analyze text endpoint."""
    payload = {"text": "Some text to analyze", "user_id": TEST_USER_ID}
    response = await mentallama_test_client.post(
        f"{MENTALLAMA_API_PREFIX}/analyze", json=payload, headers=auth_headers
    )
    assert response.status_code == 200
    # Check response matches our mock implementation for analysis model type
    response_json = response.json()
    assert response_json["success"] is True
    assert "analysis" in response_json
    assert "sentiment" in response_json["analysis"]
    assert "topics" in response_json["analysis"]
    assert "emotions" in response_json["analysis"]

@pytest.mark.asyncio
async def test_detect_conditions_endpoint(mentallama_test_client: AsyncClient, auth_headers: dict[str, str]) -> None:
    """Tests the detect conditions endpoint."""
    payload = {"text": "Feeling very down.", "user_id": TEST_USER_ID}
    response = await mentallama_test_client.post(
        f"{MENTALLAMA_API_PREFIX}/detect-conditions", json=payload, headers=auth_headers
    )
    assert response.status_code == 200
    # Check response matches our mock implementation for conditions model type
    response_json = response.json()
    assert response_json["success"] is True
    assert "conditions" in response_json
    assert isinstance(response_json["conditions"], list)

@pytest.mark.asyncio
async def test_therapeutic_response_endpoint(mentallama_test_client: AsyncClient, auth_headers: dict[str, str]) -> None:
    """Tests the therapeutic response endpoint."""
    payload = {
        "conversation_history": [{"role": "user", "content": "I feel sad."}],
        "user_id": TEST_USER_ID
    }
    response = await mentallama_test_client.post(
        f"{MENTALLAMA_API_PREFIX}/therapeutic-response", json=payload, headers=auth_headers
    )
    assert response.status_code == 200
    # Check response matches our mock implementation for therapeutic model type
    response_json = response.json()
    assert response_json["success"] is True
    assert "response" in response_json

@pytest.mark.asyncio
async def test_suicide_risk_endpoint(mentallama_test_client: AsyncClient, auth_headers: dict[str, str]) -> None:
    """Tests the suicide risk assessment endpoint."""
    payload = {"text": "I want to end it all.", "user_id": TEST_USER_ID}
    response = await mentallama_test_client.post(
        f"{MENTALLAMA_API_PREFIX}/assess-suicide-risk", json=payload, headers=auth_headers
    )
    assert response.status_code == 200
    # Check response matches our mock implementation for risk model type
    response_json = response.json()
    assert response_json["success"] is True
    assert "risk_level" in response_json
    assert "assessment" in response_json
    assert "recommendations" in response_json

@pytest.mark.asyncio
async def test_wellness_dimensions_endpoint(mentallama_test_client: AsyncClient, auth_headers: dict[str, str]) -> None:
    """Tests the wellness dimensions assessment endpoint."""
    payload = {"text": "Feeling balanced.", "user_id": TEST_USER_ID}
    response = await mentallama_test_client.post(
        f"{MENTALLAMA_API_PREFIX}/assess-wellness", json=payload, headers=auth_headers
    )
    assert response.status_code == 200
    # Check response matches our mock implementation for wellness model type
    response_json = response.json()
    assert response_json["success"] is True
    assert "dimensions" in response_json
    assert "assessment" in response_json

@pytest.mark.asyncio
async def test_service_unavailable(mentallama_test_client: AsyncClient, mock_mentallama_service_instance: AsyncMock, auth_headers: dict[str, str]) -> None:
    """Test behavior when MentaLLaMA service is not available."""
    # Override is_healthy to return False and make the API throw the expected HTTPException
    mock_mentallama_service_instance.is_healthy.return_value = False
    
    # Test with the process endpoint
    response = await mentallama_test_client.post(
        f"{MENTALLAMA_API_PREFIX}/process",
        json={
            "prompt": TEST_PROMPT,
            "user_id": TEST_USER_ID,
            "model": TEST_MODEL
        },
        headers=auth_headers
    )
    
    # Should return 503 Service Unavailable
    assert response.status_code == 503
    assert "MentaLLaMA service is not available" in response.text


@pytest_asyncio.fixture(scope="function")
async def client_app_tuple_func_scoped() -> AsyncGenerator[tuple[AsyncClient, FastAPI], None]:
    """
    Provides a tuple of (AsyncClient, FastAPI) for testing with proper database engine setup
    and middleware skipping.
    
    Returns:
        Tuple with AsyncClient and FastAPI app
    """
    # Create an in-memory SQLite database with proper async engine
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    
    # Create tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    # Create a real session factory with a real engine
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    
    # Create custom settings for test environment with rate limiting disabled
    custom_settings = Settings()
    custom_settings.RATE_LIMITING_ENABLED = False  # Critical: Disable rate limiting
    
    # Create the FastAPI application with test settings
    app = create_application(
        skip_auth_middleware=True,  # Skip authentication middleware for tests
        settings_override=custom_settings,  # Use our custom settings without rate limiting
        include_test_routers=False  # Don't include test routers
    )
    
    # Override app.state attributes with the properly configured session factory and engine
    app.state.db_engine = engine
    app.state.actual_session_factory = session_factory
    app.state.db_schema_created = True  # Indicate schema is already created
    
    # Create an AsyncClient for testing
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Content-Type": "application/json"}
    ) as client:
        # Yield the client and app as a tuple for use in tests
        yield client, app
    
    # Clean up the database after the tests
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()
