"""
MentaLLaMA API Integration Tests.

This module contains integration tests for the MentaLLaMA API routes, following
clean architecture principles with precise, mathematically elegant implementations.
"""

import logging
from collections.abc import Callable, AsyncGenerator
from unittest.mock import AsyncMock, MagicMock, patch
import pytest
import pytest_asyncio
from fastapi import FastAPI, Depends, HTTPException
from fastapi.testclient import TestClient
from httpx import AsyncClient
from starlette.requests import Request
from starlette.responses import Response

from app.app_factory import create_application
from app.config.settings import Settings
from app.core.interfaces.services.authentication_service import IAuthenticationService
from app.core.interfaces.services.jwt_service import IJwtService
from app.core.services.ml.interface import MentaLLaMAInterface
from app.core.domain.entities.user import User
from app.api.routes.ml import verify_api_key
from app.presentation.middleware.authentication_middleware import AuthenticationMiddleware

settings = Settings()

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
    mock.decode_token.return_value = {"sub": "testuser", "role": "admin"}
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
async def mock_verify_api_key() -> AsyncMock:
    """Provides a mock for the verify_api_key dependency."""
    return AsyncMock() # Simple mock as the real function is empty


@pytest_asyncio.fixture(scope="session")
async def test_app_with_lifespan(
    settings: Settings,
    mock_mentallama_service_override: AsyncMock,
    mock_auth_service: MagicMock,
    mock_jwt_service: MagicMock,
    mock_verify_api_key: AsyncMock,
) -> AsyncGenerator[FastAPI, None]:
    """Creates a FastAPI application instance for testing with mocked dependencies.
    
    Patches add_middleware to prevent real AuthenticationMiddleware addition.
    """
    logger.info("Setting up test application fixture.")

    # --- Patch add_middleware --- #
    original_add_middleware = FastAPI.add_middleware
    
    def mock_add_middleware(self, middleware_class, **options):
        # Prevent adding the real AuthenticationMiddleware during test setup
        if middleware_class == AuthenticationMiddleware:
            logger.info("Skipping add_middleware for AuthenticationMiddleware during test setup.")
            return
        # Call the original for other middleware
        original_add_middleware(self, middleware_class, **options)

    with patch.object(FastAPI, 'add_middleware', mock_add_middleware):
        logger.info("Creating FastAPI app instance via create_application (with patched add_middleware)...")
        # Now create the app. The real AuthMiddleware won't be added.
        # NOTE: This assumes create_application doesn't have critical side effects
        # that depend on the real AuthMiddleware being present during its execution.
        app = create_application(settings) 
        logger.info("FastAPI app instance created.")

    # --- Apply Dependency Overrides AFTER app creation --- #
    # Routes depending on these services will now get the mocks
    logger.info("Applying dependency overrides...")
    dependency_overrides = {
        # Core Service Mocks
        MentaLLaMAInterface: lambda: mock_mentallama_service_override,
        IAuthenticationService: lambda: mock_auth_service, # Use the existing sync mock fixture
        IJwtService: lambda: mock_jwt_service,          # Use the existing sync mock fixture
        # API Key Dependency Mock (ensure it's overridden)
        verify_api_key: lambda: mock_verify_api_key, # Use the async mock fixture
    }
    app.dependency_overrides.update(dependency_overrides)
    logger.info("Dependency overrides applied.")

    # --- Manually Manage Lifespan --- #
    logger.info("Entering lifespan context manager...")
    async with app.router.lifespan_context(app):
        logger.info("Lifespan startup complete. Yielding app.")
        yield app
        logger.info("Lifespan shutdown initiated within fixture.")
    logger.info("Lifespan context manager exited.")
    logger.info("Tearing down test application fixture.")


# --- Fixture for Test Client (Depends on Lifespan-Managed App) --- #
@pytest_asyncio.fixture(scope="session")
async def client(test_app_with_lifespan: FastAPI) -> AsyncGenerator[AsyncClient, None]:
    """Provides an asynchronous test client for the application."""
    logger.info("Creating test client using lifespan-managed app...")
    async with AsyncClient(app=test_app_with_lifespan, base_url="http://test") as ac:
        yield ac
    logger.info("Test client teardown.")


# --- Test Functions --- #
@pytest.mark.asyncio
async def test_health_check(client: AsyncClient) -> None:
    """Tests the health check endpoint."""
    response = await client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}


@pytest.mark.asyncio
async def test_process_endpoint(client: AsyncClient) -> None:
    """Tests the process endpoint with valid input."""
    response = await client.post(
        f"{MENTALLAMA_API_PREFIX}/process",
        json={"prompt": TEST_PROMPT, "model": TEST_MODEL},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["model"] == "mock_model"
    assert data["prompt"] == TEST_PROMPT
    assert "response" in data


@pytest.mark.asyncio
async def test_process_invalid_model(client: AsyncClient, mock_mentallama_service_override: AsyncMock) -> None:
    """Tests the process endpoint with an invalid model name."""
    mock_mentallama_service_override.process.side_effect = Exception("Invalid model")
    response = await client.post(
        f"{MENTALLAMA_API_PREFIX}/process",
        json={"prompt": TEST_PROMPT, "model": "invalid_model"},
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_process_empty_prompt(client: AsyncClient) -> None:
    """Tests the process endpoint with an empty prompt (should fail validation)."""
    response = await client.post(
        f"{MENTALLAMA_API_PREFIX}/process", json={"prompt": "", "model": TEST_MODEL}
    )
    # Expecting FastAPI's validation error (422)
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_analyze_text_endpoint(client: AsyncClient) -> None:
    """Tests the analyze text endpoint."""
    response = await client.post(
        f"{MENTALLAMA_API_PREFIX}/analyze", json={"text": TEST_PROMPT}
    )
    assert response.status_code == 200
    assert "analysis" in response.json()


@pytest.mark.asyncio
async def test_detect_conditions_endpoint(client: AsyncClient) -> None:
    """Tests the detect conditions endpoint."""
    response = await client.post(
        f"{MENTALLAMA_API_PREFIX}/detect-conditions", json={"text": TEST_PROMPT}
    )
    assert response.status_code == 200
    assert "conditions" in response.json()


@pytest.mark.asyncio
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
    assert response.status_code == 200
    assert "response" in response.json()


@pytest.mark.asyncio
async def test_suicide_risk_endpoint(client: AsyncClient) -> None:
    """Tests the suicide risk assessment endpoint."""
    response = await client.post(
        f"{MENTALLAMA_API_PREFIX}/suicide-risk", json={"text": TEST_PROMPT}
    )
    assert response.status_code == 200
    assert "risk_level" in response.json()


@pytest.mark.asyncio
async def test_wellness_dimensions_endpoint(client: AsyncClient) -> None:
    """Tests the wellness dimensions assessment endpoint."""
    response = await client.post(
        f"{MENTALLAMA_API_PREFIX}/wellness-dimensions", json={"text": TEST_PROMPT}
    )
    assert response.status_code == 200
    assert "dimensions" in response.json()


@pytest.mark.asyncio
async def test_service_unavailable(client: AsyncClient, mock_mentallama_service_override: AsyncMock) -> None:
    """Tests error handling when the MentaLLaMA service is unavailable."""
    # Configure the mock service to raise Exception
    mock_mentallama_service_override.process.side_effect = Exception(
        "MentaLLaMA service is down"
    )

    # Make a request to an endpoint that uses the service
    response = await client.post(
        f"{MENTALLAMA_API_PREFIX}/process",
        json={"prompt": TEST_PROMPT, "model": TEST_MODEL},
    )

    # Assert that the API returns a 503 Service Unavailable status
    assert response.status_code == 503
    assert "detail" in response.json()
    assert response.json()["detail"] == "MentaLLaMA service is down"
