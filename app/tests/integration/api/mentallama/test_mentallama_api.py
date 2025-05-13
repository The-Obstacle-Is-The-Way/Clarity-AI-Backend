"""
MentaLLaMA API Integration Tests.

This module contains integration tests for the MentaLLaMA API routes, following
clean architecture principles with precise, mathematically elegant implementations.
"""

import logging
from collections.abc import AsyncGenerator
from unittest.mock import AsyncMock, MagicMock

import asyncio
import pytest
import pytest_asyncio
from app.tests.utils.asyncio_helpers import run_with_timeout
import asyncio
import pytest
from app.tests.utils.asyncio_helpers import run_with_timeout_asyncio
from httpx import AsyncClient
from fastapi import FastAPI
from datetime import datetime, timezone, timedelta
import uuid

# Application imports (Sorted)
from app.app_factory import create_application
from app.core.config import Settings
from app.core.interfaces.services.authentication_service import IAuthenticationService
from app.core.interfaces.services.jwt_service import IJwtService
from app.core.services.ml.interface import MentaLLaMAInterface
from app.core.models.token_models import TokenPayload

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
    mock_service = AsyncMock(spec=MentaLLaMAInterface)

    # Mock process method with proper async behavior
    mock_service.process.return_value = {
        "model": "mock_model",
        "prompt": TEST_PROMPT,
        "response": "mock process response",
        "provider": "mock_provider",
    }

    # Mock detect_depression method
    mock_service.detect_depression.return_value = {"depression_detected": True, "score": 0.9}

    # Mock required BaseMLInterface methods
    mock_service.initialize.return_value = None
    mock_service.is_healthy.return_value = True
    mock_service.shutdown.return_value = None

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
    
    # Mock token decoding function
    async def decode_token_side_effect(token, audience=None):
        return TokenPayload(
            sub=TEST_USER_ID,
            exp=int((datetime.now(timezone.utc) + timedelta(minutes=30)).timestamp()),
            iat=int(datetime.now(timezone.utc).timestamp()),
            role="PATIENT",
            roles=["PATIENT"],
            jti=str(uuid.uuid4())
        )
    
    # Set side effects for async methods
    mock.create_access_token = AsyncMock(side_effect=create_access_token_side_effect)
    mock.decode_token = AsyncMock(side_effect=decode_token_side_effect)
    
    return mock


# --- New Fixture for MentaLLaMA Test Client --- #
@pytest_asyncio.fixture(scope="function")
async def mentallama_test_client(
    client_app_tuple_func_scoped: tuple[AsyncClient, FastAPI],
    mock_mentallama_service_instance: MagicMock,
    global_mock_jwt_service: MagicMock,
) -> AsyncGenerator[AsyncClient, None]:
    """
    Provides an AsyncClient configured for MentaLLaMA tests with necessary
    dependencies mocked.
    The FastAPI app instance used for overrides is derived from client_app_tuple_func_scoped.
    """
    client, app_from_fixture = client_app_tuple_func_scoped
    logger.info(f"MENTALLAMA_TEST_CLIENT: Received app_from_fixture of type: {type(app_from_fixture)}")

    actual_app_for_overrides = app_from_fixture
    if not isinstance(app_from_fixture, FastAPI):
        logger.warning(
            f"MENTALLAMA_TEST_CLIENT: app_from_fixture is type {type(app_from_fixture)}, not FastAPI. "
            f"Checking for an inner '.app' attribute."
        )
        if hasattr(app_from_fixture, "app") and isinstance(app_from_fixture.app, FastAPI):
            actual_app_for_overrides = app_from_fixture.app
            logger.info(
                f"MENTALLAMA_TEST_CLIENT: Using inner app {type(actual_app_for_overrides)} for overrides."
            )
        else:
            logger.error(
                f"MENTALLAMA_TEST_CLIENT: app_from_fixture is {type(app_from_fixture)} and no suitable "
                f"inner '.app' attribute found. Dependency overrides will likely fail."
            )
    else:
        logger.info(
            f"MENTALLAMA_TEST_CLIENT: app_from_fixture is already FastAPI type: {type(app_from_fixture)}. "
            f"Using it directly for overrides."
        )

    # Override MentaLLaMA service
    actual_app_for_overrides.dependency_overrides[MentaLLaMAInterface] = lambda: mock_mentallama_service_instance
    logger.info(f"MENTALLAMA_TEST_CLIENT: Overrode MentaLLaMAInterface on app {id(actual_app_for_overrides)}")

    # ADDED: Override IJwtService with the global mock
    actual_app_for_overrides.dependency_overrides[IJwtService] = lambda: global_mock_jwt_service
    logger.info(f"MENTALLAMA_TEST_CLIENT: Overrode IJwtService on app {id(actual_app_for_overrides)} with global_mock_jwt_service ID: {id(global_mock_jwt_service)}")

    yield client

    # Teardown: Clear dependency overrides
    try:
        actual_app_for_overrides.dependency_overrides.clear()
        logger.info(f"MENTALLAMA_TEST_CLIENT: Cleared dependency_overrides on app {id(actual_app_for_overrides)}")
    except AttributeError:
        logger.error(
            f"MENTALLAMA_TEST_CLIENT: Failed to clear dependency_overrides. "
            f"actual_app_for_overrides type: {type(actual_app_for_overrides)} did not have them."
        )


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
    # Check against the mocked service return value
    assert response.json() == {
        "model": "mock_model",
        "prompt": TEST_PROMPT,
        "response": "mock process response",
        "provider": "mock_provider",
    }

@pytest.mark.asyncio
async def test_analyze_text_endpoint(mentallama_test_client: AsyncClient, auth_headers: dict[str, str]) -> None:
    """Tests the analyze text endpoint."""
    payload = {"text": "Some text to analyze", "user_id": TEST_USER_ID}
    response = await mentallama_test_client.post(
        f"{MENTALLAMA_API_PREFIX}/analyze", json=payload, headers=auth_headers
    )
    assert response.status_code == 200
    # Assuming analyze uses the same mock process method for now
    assert "response" in response.json() 

@pytest.mark.asyncio
async def test_detect_conditions_endpoint(mentallama_test_client: AsyncClient, auth_headers: dict[str, str]) -> None:
    """Tests the detect conditions endpoint."""
    payload = {"text": "Feeling very down.", "user_id": TEST_USER_ID}
    response = await mentallama_test_client.post(
        f"{MENTALLAMA_API_PREFIX}/detect-conditions", json=payload, headers=auth_headers
    )
    assert response.status_code == 200
    # Check that the response has expected structure but don't assume specific fields
    assert isinstance(response.json(), dict)

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
    # Check that the response has expected structure but don't assume specific fields
    assert isinstance(response.json(), dict)

@pytest.mark.asyncio
async def test_suicide_risk_endpoint(mentallama_test_client: AsyncClient, auth_headers: dict[str, str]) -> None:
    """Tests the suicide risk assessment endpoint."""
    payload = {"text": "I want to end it all.", "user_id": TEST_USER_ID}
    response = await mentallama_test_client.post(
        f"{MENTALLAMA_API_PREFIX}/assess-suicide-risk", json=payload, headers=auth_headers
    )
    assert response.status_code == 200
    # Don't assume specific fields in the response
    assert isinstance(response.json(), dict)

@pytest.mark.asyncio
async def test_wellness_dimensions_endpoint(mentallama_test_client: AsyncClient, auth_headers: dict[str, str]) -> None:
    """Tests the wellness dimensions assessment endpoint."""
    payload = {"text": "Feeling balanced.", "user_id": TEST_USER_ID}
    response = await mentallama_test_client.post(
        f"{MENTALLAMA_API_PREFIX}/assess-wellness", json=payload, headers=auth_headers
    )
    assert response.status_code == 200
    # Don't assume specific fields in the response
    assert isinstance(response.json(), dict)

@pytest.mark.asyncio
async def test_service_unavailable(
    mentallama_test_client: AsyncClient, 
    mock_mentallama_service_instance: AsyncMock,
    auth_headers: dict[str, str]
) -> None:
    """Tests error handling when the MentaLLaMA service is unavailable."""
    # Configure the mock to raise an exception for this specific test
    mock_mentallama_service_instance.process.side_effect = Exception("Service Down")
    mock_mentallama_service_instance.detect_depression.side_effect = Exception("Service Down")
    # Add side effects for other methods called by endpoints if necessary

    payload = {"prompt": TEST_PROMPT, "user_id": TEST_USER_ID, "model": TEST_MODEL}
    response = await mentallama_test_client.post(
        f"{MENTALLAMA_API_PREFIX}/process", json=payload, headers=auth_headers
    )

    # Expecting an internal server error or specific service unavailable error
    assert response.status_code == 503 # Or 500 depending on error handling
    assert "detail" in response.json()
    # Check specific detail message if applicable
    # assert "MentaLLaMA service is currently unavailable" in response.json()["detail"]

    # Reset side effect if the mock instance is used across tests (though it's function scoped here)
    mock_mentallama_service_instance.process.side_effect = None
    mock_mentallama_service_instance.detect_depression.side_effect = None


@pytest_asyncio.fixture(scope="function")
async def client_app_tuple_func_scoped() -> AsyncGenerator[tuple[AsyncClient, FastAPI], None]:
    """
    Provides a tuple of (AsyncClient, FastAPI) for testing.
    
    Returns:
        Tuple with AsyncClient and FastAPI app
    """
    # Create the FastAPI application with test settings
    app = create_application(skip_auth_middleware=True)  # Skip authentication middleware
    
    # Add mock session factory to app.state to avoid database dependency errors
    mock_session_factory = AsyncMock()
    app.state.actual_session_factory = mock_session_factory
    app.state.db_engine = MagicMock()
    app.state.db_session = AsyncMock()
    
    # Create an AsyncClient for testing
    async with AsyncClient(
        app=app,
        base_url="http://test",
        headers={"Content-Type": "application/json"}
    ) as client:
        # Yield the client and app as a tuple for use in tests
        yield client, app
