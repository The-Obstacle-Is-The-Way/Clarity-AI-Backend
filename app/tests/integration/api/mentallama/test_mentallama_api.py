"""
MentaLLaMA API Integration Tests.

This module contains integration tests for the MentaLLaMA API routes, following
clean architecture principles with precise, mathematically elegant implementations.
"""

import logging
from collections.abc import AsyncGenerator
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from httpx import AsyncClient

# Application imports (Sorted)
from app.app_factory import create_application
from app.core.config import Settings
from app.core.interfaces.services.authentication_service import IAuthenticationService
from app.core.interfaces.services.jwt_service import IJwtService
from app.core.services.ml.interface import MentaLLaMAInterface

logger = logging.getLogger(__name__)

# Setup logging
logging.basicConfig(level=logging.INFO)

# Define the base URL for the API version being tested
BASE_URL = "/api/v1/mentallama"

# Configuration & Constants
TEST_PROMPT = "This is a test prompt."
TEST_USER_ID = "test_user_123"
TEST_MODEL = "test_model"
MENTALLAMA_API_PREFIX = f"{Settings().API_V1_STR}/mentallama"


@pytest_asyncio.fixture(scope="function")
async def mock_mentallama_service_instance() -> AsyncMock:
    """Provides a mock Mentallama service dependency override 
    with pre-configured return values.
    """
    # Create a mock instance respecting the MentaLLaMAInterface spec
    mock_service = AsyncMock(spec=MentaLLaMAInterface)

    # Mock only methods defined in the interface
    # Set return_value directly on the method mock attribute
    mock_service.process.return_value = {
        "model": "mock_model",
        "prompt": TEST_PROMPT,
        "response": "mock process response",
        "provider": "mock_provider",
    }
    mock_service.detect_depression.return_value = {"depression_detected": True, "score": 0.9}

    # Mock base interface methods if needed by tests (is_healthy is used by /health)
    # Set return_value directly on the method mock attribute
    mock_service.is_healthy.return_value = True

    # Ensure the methods themselves are awaitable 
    # (AsyncMock handles this by default when spec is used)

    return mock_service


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


@pytest.fixture(scope="function")
def mock_jwt_service() -> MagicMock:
    """Provides a mock JWTService dependency override,
    simplifying token verification for tests.
    """
    mock = MagicMock(spec=IJwtService)

    # --- Mock ASYNC methods --- #
    # Ensure decode_token itself is an awaitable mock that returns the payload
    mock.decode_token = AsyncMock(return_value={
        "sub": TEST_USER_ID, # Use consistent user ID
        "role": "admin",
        # Add other claims if necessary for tests
    })
    mock.create_access_token = AsyncMock(return_value="mock_access_token")
    mock.create_refresh_token = AsyncMock(return_value="mock_refresh_token")
    # Return a mock user object if needed by downstream code, else None is fine
    mock_user_payload = MagicMock() 
    mock_user_payload.id = TEST_USER_ID
    mock_user_payload.username = "testuser"
    mock.get_user_from_token = AsyncMock(return_value=mock_user_payload) 
    # Mock payload
    mock.verify_refresh_token = AsyncMock(return_value={"sub": TEST_USER_ID})

    # --- Mock SYNC methods --- #
    # Mock the synchronous method
    mock.get_token_payload_subject.return_value = TEST_USER_ID 

    return mock


# --- New Fixture for MentaLLaMA Test Client --- #
@pytest_asyncio.fixture(scope="function")
async def mentallama_test_client(
    test_settings: Settings, 
    mock_mentallama_service_instance: AsyncMock, 
    mock_auth_service: MagicMock,
    mock_jwt_service: MagicMock,
) -> AsyncGenerator[AsyncClient, None]:
    """Creates a FastAPI test client specific to MentaLLaMA API tests.

    Uses test_settings and applies MentaLLaMA, Auth, and JWT mock overrides.
    Handles application lifespan.
    """
    logger.info("Setting up MentaLLaMA test client fixture.")
    app = create_application(settings=test_settings)

    # Apply dependency overrides
    app.dependency_overrides[MentaLLaMAInterface] = lambda: mock_mentallama_service_instance
    app.dependency_overrides[IAuthenticationService] = lambda: mock_auth_service
    app.dependency_overrides[IJwtService] = lambda: mock_jwt_service
    
    # Apply Redis mock override if necessary (though test_settings should handle this)
    # You might need to mock specific Redis functions or the Redis client dependency
    # Example: from app.core.dependencies.redis import get_redis_client
    # mock_redis = AsyncMock()
    # app.dependency_overrides[get_redis_client] = lambda: mock_redis

    async with AsyncClient(app=app, base_url="http://test") as client:
        logger.info("Yielding MentaLLaMA test client.")
        yield client
    logger.info("MentaLLaMA test client fixture teardown.")


# --- Test Functions (Updated to use mentallama_test_client) --- #

@pytest.mark.asyncio
async def test_health_check(mentallama_test_client: AsyncClient) -> None:
    """Tests the health check endpoint."""
    response = await mentallama_test_client.get(f"{MENTALLAMA_API_PREFIX}/health")
    assert response.status_code == 200
    # Check if the mocked service's healthy status is reflected
    assert response.json() == {"status": "healthy", "service_status": True} 

@pytest.mark.asyncio
async def test_process_endpoint(mentallama_test_client: AsyncClient) -> None:
    """Tests the process endpoint with valid input."""
    payload = {"prompt": TEST_PROMPT, "user_id": TEST_USER_ID, "model": TEST_MODEL}
    headers = {"Authorization": "Bearer mock_token"} # Assuming JWT auth
    response = await mentallama_test_client.post(
        f"{MENTALLAMA_API_PREFIX}/process", json=payload, headers=headers
    )
    assert response.status_code == 200
    # Check against the mocked service return value
    assert response.json() == {
        "model": "mock_model",
        "prompt": TEST_PROMPT,
        "response": "mock process response",
        "provider": "mock_provider",
    }

@pytest.mark.asyncio
async def test_analyze_text_endpoint(mentallama_test_client: AsyncClient) -> None:
    """Tests the analyze text endpoint."""
    payload = {"text": "Some text to analyze", "user_id": TEST_USER_ID}
    headers = {"Authorization": "Bearer mock_token"}
    response = await mentallama_test_client.post(
        f"{MENTALLAMA_API_PREFIX}/analyze", json=payload, headers=headers
    )
    assert response.status_code == 200
    # Assuming analyze uses the same mock process method for now
    assert "response" in response.json() 

@pytest.mark.asyncio
async def test_detect_conditions_endpoint(mentallama_test_client: AsyncClient) -> None:
    """Tests the detect conditions endpoint."""
    payload = {"text": "Feeling very down.", "user_id": TEST_USER_ID}
    headers = {"Authorization": "Bearer mock_token"}
    response = await mentallama_test_client.post(
        f"{MENTALLAMA_API_PREFIX}/detect-conditions", json=payload, headers=headers
    )
    assert response.status_code == 200
    # Check against the mocked detect_depression return value
    assert response.json() == {"depression_detected": True, "score": 0.9}

@pytest.mark.asyncio
async def test_therapeutic_response_endpoint(mentallama_test_client: AsyncClient) -> None:
    """Tests the therapeutic response endpoint."""
    payload = {
        "conversation_history": [{"role": "user", "content": "I feel sad."}],
        "user_id": TEST_USER_ID
    }
    headers = {"Authorization": "Bearer mock_token"}
    response = await mentallama_test_client.post(
        f"{MENTALLAMA_API_PREFIX}/therapeutic-response", json=payload, headers=headers
    )
    assert response.status_code == 200
    # Assuming it uses the mock process method for now
    assert "response" in response.json()

@pytest.mark.asyncio
async def test_suicide_risk_endpoint(mentallama_test_client: AsyncClient) -> None:
    """Tests the suicide risk assessment endpoint."""
    payload = {"text": "I want to end it all.", "user_id": TEST_USER_ID}
    headers = {"Authorization": "Bearer mock_token"}
    response = await mentallama_test_client.post(
        f"{MENTALLAMA_API_PREFIX}/assess-suicide-risk", json=payload, headers=headers
    )
    assert response.status_code == 200
    # Add assertion based on expected mocked behavior
    assert "risk_level" in response.json() # Example assertion

@pytest.mark.asyncio
async def test_wellness_dimensions_endpoint(mentallama_test_client: AsyncClient) -> None:
    """Tests the wellness dimensions assessment endpoint."""
    payload = {"text": "Feeling balanced.", "user_id": TEST_USER_ID}
    headers = {"Authorization": "Bearer mock_token"}
    response = await mentallama_test_client.post(
        f"{MENTALLAMA_API_PREFIX}/assess-wellness", json=payload, headers=headers
    )
    assert response.status_code == 200
    # Add assertion based on expected mocked behavior
    assert "dimensions" in response.json() # Example assertion

@pytest.mark.asyncio
async def test_service_unavailable(
    # Renamed parameter to match the new fixture
    mentallama_test_client: AsyncClient, 
    mock_mentallama_service_instance: AsyncMock # Need the mock instance to modify it
) -> None:
    """Tests error handling when the MentaLLaMA service is unavailable."""
    # Configure the mock to raise an exception for this specific test
    mock_mentallama_service_instance.process.side_effect = Exception("Service Down")
    mock_mentallama_service_instance.detect_depression.side_effect = Exception("Service Down")
    # Add side effects for other methods called by endpoints if necessary

    payload = {"prompt": TEST_PROMPT, "user_id": TEST_USER_ID, "model": TEST_MODEL}
    headers = {"Authorization": "Bearer mock_token"}
    response = await mentallama_test_client.post(
        f"{MENTALLAMA_API_PREFIX}/process", json=payload, headers=headers
    )

    # Expecting an internal server error or specific service unavailable error
    assert response.status_code == 503 # Or 500 depending on error handling
    assert "detail" in response.json()
    # Check specific detail message if applicable
    # assert "MentaLLaMA service is currently unavailable" in response.json()["detail"]

    # Reset side effect if the mock instance is used across tests (though it's function scoped here)
    mock_mentallama_service_instance.process.side_effect = None
    mock_mentallama_service_instance.detect_depression.side_effect = None
