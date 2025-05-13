"""Test fixtures for security API tests."""

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI
from httpx import AsyncClient, ASGITransport

from app.core.config.settings import Settings as AppSettings
from app.core.domain.entities.user import User, UserRole, UserStatus
from app.core.interfaces.services.jwt_service_interface import JWTServiceInterface
from app.app_factory import create_application


@pytest.fixture(scope="function")
def app_instance(global_mock_jwt_service) -> FastAPI:
    """Create a function-scoped FastAPI app instance for testing."""
    test_settings = AppSettings(
        ENV="test",
        TEST_MODE=True,
        DATABASE_URL="sqlite+aiosqlite:///:memory:",
        JWT_SECRET_KEY="test_secret_key_for_jwt_tokens",
        JWT_ALGORITHM="HS256",
        PHI_ENCRYPTION_KEY="test_key_for_encryption_of_phi_data_12345",
    )
    app = create_application(
        settings_override=test_settings,
        jwt_service_override=global_mock_jwt_service,
        include_test_routers=True
    )
    return app


@pytest.fixture(scope="function")
async def client_app_tuple_func_scoped(app_instance: FastAPI) -> tuple[AsyncClient, FastAPI]:
    """Create a function-scoped test client connected to a test app instance."""
    async with AsyncClient(
        transport=ASGITransport(app=app_instance),
        base_url="http://test",
        follow_redirects=True,
    ) as client:
        yield client, app_instance


@pytest.fixture(scope="module")
def global_mock_jwt_service() -> MagicMock:
    """Create a module-scoped mock JWT service that can be used across tests."""
    mock_service = MagicMock(spec=JWTServiceInterface)
    
    # Mock tokens storage to simulate token validation
    token_store = {}
    token_exp_store = {}
    
    # Set up async methods
    mock_create_token = AsyncMock()
    async def mock_create_access_token(data: dict, expires_delta: timedelta = None):
        expires = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=15))
        token = f"mock_token_{uuid.uuid4()}"
        token_store[token] = data
        token_exp_store[token] = expires
        return token
    
    mock_create_token.side_effect = mock_create_access_token
    mock_service.create_access_token = mock_create_token
    
    mock_decode = AsyncMock()
    async def mock_decode_token(token: str):
        if token not in token_store:
            raise ValueError(f"Simplified mock: Token {token} not in store")
        if datetime.now(timezone.utc) > token_exp_store.get(token, datetime.max.replace(tzinfo=timezone.utc)):
            raise ValueError("Mock token has expired")
        return token_store[token]
    
    mock_decode.side_effect = mock_decode_token
    mock_service.decode_token = mock_decode
    
    mock_verify = AsyncMock()
    async def mock_verify_token(token: str):
        if token not in token_store:
            return False
        if datetime.now(timezone.utc) > token_exp_store.get(token, datetime.max.replace(tzinfo=timezone.utc)):
            return False
        return True
    
    mock_verify.side_effect = mock_verify_token
    mock_service.verify_token = mock_verify
    
    yield mock_service


@pytest.fixture
def authenticated_user() -> User:
    """Create a test user with authentication credentials."""
    return User(
        id=uuid.UUID("a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"),
        username="test_doctor",
        email="test.doctor@example.com", 
        full_name="Test Doctor",
        roles={UserRole.CLINICIAN},
        account_status=UserStatus.ACTIVE,
        password_hash="hashed_password_not_real",
        created_at=datetime.now(timezone.utc),
    )


@pytest.fixture
async def get_valid_auth_headers(global_mock_jwt_service, authenticated_user) -> dict[str, str]:
    """Get valid authentication headers for the authenticated user."""
    token_data = {
        "sub": str(authenticated_user.id),
        "username": authenticated_user.username,
        "email": authenticated_user.email,
        "roles": [role.value for role in authenticated_user.roles],
    }
    token = await global_mock_jwt_service.create_access_token(data=token_data)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
async def get_valid_provider_auth_headers(global_mock_jwt_service) -> dict[str, str]:
    """Get valid authentication headers for a provider user."""
    provider_id = uuid.uuid4()
    token_data = {
        "sub": str(provider_id),
        "username": "test_provider",
        "email": "provider@example.com",
        "roles": [UserRole.CLINICIAN.value],
    }
    token = await global_mock_jwt_service.create_access_token(data=token_data)
    return {"Authorization": f"Bearer {token}"} 