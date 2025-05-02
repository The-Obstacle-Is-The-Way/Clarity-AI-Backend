"""
MentaLLaMA API Integration Tests.

This module contains integration tests for the MentaLLaMA API routes, following
clean architecture principles with precise, mathematically elegant implementations.
"""

import logging
from collections.abc import Callable
from unittest.mock import AsyncMock, MagicMock, patch
from typing import AsyncGenerator, Generator, Any, Dict
from collections.abc import Callable, Awaitable

import pytest
import pytest_asyncio
from fastapi import FastAPI, Request, Response, status
from httpx import AsyncClient

from app.api.routes.ml import verify_api_key
from app.app_factory import create_application
from app.core.config.settings import get_settings
from app.core.exceptions import ModelNotFoundError, ServiceUnavailableError
from app.core.interfaces.services.authentication_service import IAuthenticationService
from app.core.interfaces.services.jwt_service import IJwtService
from app.core.services.ml.interface import MentaLLaMAInterface

settings = get_settings()

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Define the base URL for the API version being tested
BASE_URL = "/api/v1/mentallama"

# Configuration & Constants
TEST_PROMPT = "This is a test prompt."
TEST_USER_ID = "test_user_123"
TEST_MODEL = "test_model"
MENTALLAMA_API_PREFIX = f"{settings.API_V1_STR}/mentallama"


@pytest_asyncio.fixture(scope="function")
async def mock_mentallama_service_instance() -> AsyncMock:
    """Provides a mocked instance of the MentaLLaMA service based on its interface."""
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

    # Ensure the methods themselves are awaitable (AsyncMock handles this by default when spec is used)

    return mock_service


@pytest.fixture(scope="function")
def mock_mentallama_service_override(
    mock_mentallama_service_instance: AsyncMock
) -> AsyncMock:
    """Returns the mocked service instance for overriding the dependency."""
    return mock_mentallama_service_instance


@pytest.fixture(scope="function")
def mock_auth_service() -> MagicMock:
    """Provides a mocked instance of the IAuthenticationService."""
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
    """Provides a mocked instance of the IJwtService."""
    mock = MagicMock(spec=IJwtService)

    # Mock async methods correctly
    # Ensure decode_token itself is an awaitable mock that returns the payload
    mock.decode_token = AsyncMock(return_value={"sub": TEST_USER_ID, "scopes": ["mentallama"]})
    # Add mocks for other IJwtService async methods if they are called, even if just returning None or default
    mock.create_access_token = AsyncMock(return_value="mock_access_token")
    mock.create_refresh_token = AsyncMock(return_value="mock_refresh_token")
    mock.get_user_from_token = AsyncMock(return_value=None) # Adjust if a User object is needed
    mock.verify_refresh_token = AsyncMock(return_value={"sub": TEST_USER_ID}) # Mock payload

    # Mock synchronous methods (if any were defined and needed)
    # mock.get_token_payload_subject.return_value = TEST_USER_ID # Example if needed

    return mock


# Helper function for mocking the auth middleware call
async def mock_auth_middleware_call(request: Request, call_next: Callable[[Request], Response]) -> Response:
    # Simulate setting user context, bypassing actual auth logic
    request.state.user = {"id": TEST_USER_ID, "username": "testuser"}
    response = await call_next(request)
    return response


@pytest_asyncio.fixture(scope="session")
async def test_app(
    settings,
    mock_mentallama_service_override,
    mock_auth_service,
    mock_jwt_service,
) -> AsyncGenerator[FastAPI, None]:
    """Creates a FastAPI application instance for testing with mocked dependencies."""
    logger.info("Creating test FastAPI application instance...")
    app = create_application(settings=settings)

    # --- Mock Middleware Setup ---
    # Find and REPLACE AuthenticationMiddleware with a MagicMock
    auth_middleware_index = -1
    original_middleware = None
    for i, middleware in enumerate(app.user_middleware):
        if isinstance(middleware.cls, type) and issubclass(middleware.cls, AuthenticationMiddleware):
        # Check if middleware.cls is a class type before using issubclass
        # if inspect.isclass(middleware.cls) and issubclass(middleware.cls, AuthenticationMiddleware):
            auth_middleware_index = i
            original_middleware = middleware # Keep reference if needed
            logger.info(f"Found AuthenticationMiddleware at index {i}")
            break

    if auth_middleware_index != -1:
        # 1. Create the mock middleware instance
        mock_middleware_instance = MagicMock(spec=AuthenticationMiddleware)

        # 2. Inject mock services directly into the mock attributes
        #    These names must match the attributes accessed within the *real* middleware's
        #    _ensure_services_initialized or dispatch methods if they were called.
        mock_middleware_instance._auth_service = mock_auth_service
        mock_middleware_instance._jwt_service = mock_jwt_service
        logger.info("Mock Auth and JWT services assigned to MagicMock attributes.")

        # 3. Define a simple async dispatch function for the mock
        async def mock_dispatch(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
            # This mock bypasses all real auth logic and just proceeds
            logger.debug("Mock AuthenticationMiddleware dispatch called, proceeding to next.")
            # Ensure user state exists, mimicking part of the real middleware setup
            if not hasattr(request.state, 'user'):
                 request.state.user = UnauthenticatedUser()
            if not hasattr(request.state, 'auth'):
                 request.state.auth = None
            return await call_next(request)

        # 4. Assign the mock dispatch method to the mock instance
        mock_middleware_instance.dispatch = mock_dispatch

        # 5. Replace the original middleware entry with our mock
        #    We need to wrap the mock instance in a Middleware object like the original
        app.user_middleware[auth_middleware_index] = Middleware(lambda app: mock_middleware_instance)
        logger.info("Replaced original AuthenticationMiddleware with MagicMock wrapper.")

        # 6. Rebuild the middleware stack to apply the replacement
        app.middleware_stack = app.build_middleware_stack()
        logger.info("Rebuilt FastAPI middleware stack.")

    else:
        logger.warning("AuthenticationMiddleware not found in user_middleware. Cannot replace with mock.")

    # --- Dependency Overrides for Route Dependencies ---
    # Define a mock async function for verify_api_key dependency
    async def mock_verify_api_key():
        return None

    # Add dependency overrides AFTER app creation and middleware manipulation
    dependency_overrides = {
        MentaLLaMAInterface: lambda: mock_mentallama_service_override,
        IAuthenticationService: lambda: mock_auth_service, # Still needed for route dependencies
        IJwtService: lambda: mock_jwt_service,          # Still needed for route dependencies
        verify_api_key: mock_verify_api_key,
    }
    app.dependency_overrides = dependency_overrides
    logger.info("Applied dependency overrides for routes.")

    logger.info("Test application setup complete.")
    yield app
    logger.info("Test application teardown.")


# === Test Client Fixture ===
@pytest_asyncio.fixture(scope="function")
async def client(test_app: FastAPI) -> AsyncClient:
    """Provides an asynchronous test client for the application."""
    base_url = "http://testserver"
    async with AsyncClient(app=test_app, base_url=base_url) as client:
        yield client


# --- Test Cases ---


async def test_health_check(client: AsyncClient) -> None:
    """Tests the health check endpoint."""
    response = await client.get("/health")
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"status": "healthy"}


async def test_process_endpoint(client: AsyncClient) -> None:
    """Tests the process endpoint with valid input."""
    response = await client.post(
        f"{MENTALLAMA_API_PREFIX}/process",
        json={"prompt": TEST_PROMPT, "model": TEST_MODEL},
    )
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["model"] == "mock_model"
    assert data["prompt"] == TEST_PROMPT
    assert "response" in data


async def test_process_invalid_model(client: AsyncClient, mock_mentallama_service_override: AsyncMock) -> None:
    """Tests the process endpoint with an invalid model name."""
    mock_mentallama_service_override.process.side_effect = ModelNotFoundError("Invalid model")
    response = await client.post(
        f"{MENTALLAMA_API_PREFIX}/process",
        json={"prompt": TEST_PROMPT, "model": "invalid_model"},
    )
    assert response.status_code == status.HTTP_404_NOT_FOUND


async def test_process_empty_prompt(client: AsyncClient) -> None:
    """Tests the process endpoint with an empty prompt (should fail validation)."""
    response = await client.post(
        f"{MENTALLAMA_API_PREFIX}/process", json={"prompt": "", "model": TEST_MODEL}
    )
    # Expecting FastAPI's validation error (422)
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


async def test_analyze_text_endpoint(client: AsyncClient) -> None:
    """Tests the analyze text endpoint."""
    response = await client.post(
        f"{MENTALLAMA_API_PREFIX}/analyze", json={"text": TEST_PROMPT}
    )
    assert response.status_code == status.HTTP_200_OK
    assert "analysis" in response.json()


async def test_detect_conditions_endpoint(client: AsyncClient) -> None:
    """Tests the detect conditions endpoint."""
    response = await client.post(
        f"{MENTALLAMA_API_PREFIX}/detect-conditions", json={"text": TEST_PROMPT}
    )
    assert response.status_code == status.HTTP_200_OK
    assert "conditions" in response.json()


async def test_therapeutic_response_endpoint(client: AsyncClient) -> None:
    """Tests the therapeutic response endpoint."""
    payload = {
        "context": {"history": ["utterance1"]},
        "prompt": TEST_PROMPT
    }
    url = f"{BASE_URL}/therapeutic-response"
    response = await client.post(
        url,
        json=payload
    )
    assert response.status_code == status.HTTP_200_OK
    assert "response" in response.json()


async def test_suicide_risk_endpoint(client: AsyncClient) -> None:
    """Tests the suicide risk assessment endpoint."""
    response = await client.post(
        f"{MENTALLAMA_API_PREFIX}/suicide-risk", json={"text": TEST_PROMPT}
    )
    assert response.status_code == status.HTTP_200_OK
    assert "risk_level" in response.json()


async def test_wellness_dimensions_endpoint(client: AsyncClient) -> None:
    """Tests the wellness dimensions assessment endpoint."""
    response = await client.post(
        f"{MENTALLAMA_API_PREFIX}/wellness-dimensions", json={"text": TEST_PROMPT}
    )
    assert response.status_code == status.HTTP_200_OK
    assert "dimensions" in response.json()


async def test_service_unavailable(client: AsyncClient, mock_mentallama_service_override: AsyncMock) -> None:
    """Tests error handling when the MentaLLaMA service is unavailable."""
    # Configure the mock service to raise ServiceUnavailableError
    mock_mentallama_service_override.process.side_effect = ServiceUnavailableError(
        "MentaLLaMA service is down"
    )

    # Make a request to an endpoint that uses the service
    response = await client.post(
        f"{MENTALLAMA_API_PREFIX}/process",
        json={"prompt": TEST_PROMPT, "model": TEST_MODEL},
    )

    # Assert that the API returns a 503 Service Unavailable status
    assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
    assert "detail" in response.json()
    assert response.json()["detail"] == "MentaLLaMA service is down"
