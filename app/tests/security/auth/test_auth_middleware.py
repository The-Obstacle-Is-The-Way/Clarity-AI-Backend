import time
from collections.abc import AsyncGenerator
from typing import Any
from unittest.mock import AsyncMock, MagicMock
import uuid

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import AsyncClient

from app.domain.exceptions.auth_exceptions import InvalidTokenException, TokenExpiredException, UserNotFoundException
from app.infrastructure.security.auth.authentication_service import AuthenticationService
from app.infrastructure.security.jwt_service import JWTService, TokenPayload, get_jwt_service as actual_get_jwt_service
from app.core.security.middleware import AuthenticationMiddleware
from app.infrastructure.security.auth_service import get_auth_service as actual_get_auth_service


@pytest.fixture
def mock_auth_service() -> AsyncMock:
    """Provides a mock AuthenticationService."""
    mock = AsyncMock(spec=AuthenticationService)
    async def mock_get_user_by_id(user_id: str) -> tuple[Any | None, list[str]]:
        if user_id == "expired_user":
            raise TokenExpiredException("User session associated with token expired")
        if user_id == "invalid_user":
            raise InvalidTokenException("User ID from token is invalid")
        
        if user_id in ["patient123", "provider123", "admin123", "user123"]:
            user = MagicMock()
            user.id = user_id
            user.is_active = True
            if user_id.startswith("patient"):
                user.roles = ["patient"]
            elif user_id.startswith("provider"):
                user.roles = ["provider"]
            elif user_id.startswith("admin"):
                user.roles = ["admin"]
            elif user_id == "user123":
                user.roles = ["user"]
            else:
                user.roles = []
            return user
        if user_id == "unknown_user_from_valid_token":
            raise UserNotFoundException(f"User with ID {user_id} not found.")

        logger.warning(f"mock_get_user_by_id called with unhandled user_id: {user_id}")
        return None 
    mock.get_user_by_id.side_effect = mock_get_user_by_id
    return mock

@pytest.fixture
def mock_jwt_service() -> AsyncMock:
    """Provides a mock JWTService."""
    mock = AsyncMock(spec=JWTService)
    async def mock_decode_token(token: str) -> TokenPayload | None:
        logger.debug(f"mock_decode_token called with token: {token}")
        if token == "patient123":
            return TokenPayload(sub="patient123", roles=["patient"], exp=int(time.time()) + 3600, iat=int(time.time()), jti=str(uuid.uuid4()), type="access")
        elif token == "expired":
            logger.debug(f"mock_decode_token raising TokenExpiredException for token: {token}")
            raise TokenExpiredException("Token has expired")
        elif token == "invalid":
            logger.debug(f"mock_decode_token raising InvalidTokenException for token: {token}")
            raise InvalidTokenException("Invalid token")
        
        if token not in ["patient123", "expired", "invalid"]:
             logger.warning(f"mock_decode_token received unhandled token: {token}, raising InvalidTokenException")
             raise InvalidTokenException(f"Unhandled token in mock_decode_token: {token}")
        return None
    mock.decode_token.side_effect = mock_decode_token
    return mock

@pytest.fixture
def app(
    mock_auth_service: AsyncMock,
    mock_jwt_service: AsyncMock
) -> FastAPI:
    """Creates a FastAPI app instance with middleware for testing."""
    fastapi_app = FastAPI()

    # Override dependencies at the app level
    # This ensures that if the middleware somehow falls back to DI, it gets the mocks.
    fastapi_app.dependency_overrides[actual_get_auth_service] = lambda: mock_auth_service
    fastapi_app.dependency_overrides[actual_get_jwt_service] = lambda: mock_jwt_service
    
    fastapi_app.add_middleware(
        AuthenticationMiddleware,
        auth_service=mock_auth_service,
        jwt_service=mock_jwt_service,
        public_paths=["/public"]
    )
    
    @fastapi_app.get("/public")
    async def public_route() -> dict[str, str]:
        return {"message": "public access"}
        
    @fastapi_app.get("/protected")
    async def protected_route() -> dict[str, str]:
        return {"message": "protected access"}
    
    return fastapi_app

@pytest_asyncio.fixture(scope="function")
async def async_client(app: FastAPI) -> AsyncGenerator[AsyncClient, None]:
    """Create an async test client for the app."""
    async with AsyncClient(app=app, base_url="http://testserver") as client:
        yield client

@pytest.mark.asyncio
async def test_public_route_access(async_client: AsyncClient) -> None:
    """Test that public routes are accessible without authentication."""
    response = await async_client.get("/public")
    assert response.status_code == 200
    assert response.json() == {"message": "public access"}

@pytest.mark.asyncio
async def test_protected_route_no_token(async_client: AsyncClient) -> None:
    """Test that protected routes require authentication (401 without token)."""
    response = await async_client.get("/protected")
    assert response.status_code == 401
    assert response.json() == {"detail": "Authentication required. No token provided."}

@pytest.mark.asyncio
async def test_protected_route_with_valid_token(async_client: AsyncClient) -> None:
    """Test that protected routes are accessible with a valid token."""
    response = await async_client.get(
        "/protected", headers={"Authorization": "Bearer patient123"}
    )
    assert response.status_code == 200
    assert response.json() == {"message": "protected access"}

@pytest.mark.asyncio
async def test_protected_route_with_invalid_token(async_client: AsyncClient) -> None:
    """Test that protected routes return 401 with an invalid token."""
    response = await async_client.get(
        "/protected", headers={"Authorization": "Bearer invalid"}
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid or malformed authentication token."}

@pytest.mark.asyncio
async def test_protected_route_with_expired_token(async_client: AsyncClient) -> None:
    """Test that protected routes return 401 with an expired token."""
    response = await async_client.get(
        "/protected", headers={"Authorization": "Bearer expired"}
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "Authentication token has expired."}
