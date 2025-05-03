import time
from unittest.mock import AsyncMock, MagicMock
from typing import Any, List, Tuple, Optional, Dict

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import AsyncClient

from app.domain.exceptions.token_exceptions import InvalidTokenException, TokenExpiredException
from app.infrastructure.security.auth.authentication_service import AuthenticationService
from app.infrastructure.security.jwt.jwt_service import JWTService, TokenPayload
from app.presentation.middleware.authentication_middleware import AuthenticationMiddleware


@pytest.fixture
def mock_auth_service() -> AsyncMock:
    """Provides a mock AuthenticationService."""
    mock = AsyncMock(spec=AuthenticationService)
    async def mock_validate_token(token: str) -> Tuple[Optional[Any], List[str]]:
        if token == "expired":
            raise TokenExpiredException("Token expired")
        if token == "invalid":
            raise InvalidTokenException("Invalid token")
        if token in ["patient123", "provider123", "admin123"]:
            user = MagicMock()
            user.id = token
            if token.startswith("patient"):
                user.roles = ["patient"]
            elif token.startswith("provider"):
                user.roles = ["provider"]
            elif token.startswith("admin"):
                user.roles = ["admin"]
            else:
                user.roles = []
            return user, ["read:all"]
        return None, []
    mock.validate_token.side_effect = mock_validate_token
    return mock

@pytest.fixture
def mock_jwt_service() -> AsyncMock:
    """Provides a mock JWTService."""
    mock = AsyncMock(spec=JWTService)
    async def mock_decode_token(token: str) -> Optional[TokenPayload]:
        if token == "valid-token":
            return TokenPayload(sub="user123", roles=["user"], exp=int(time.time()) + 3600)
        elif token == "expired-token":
            raise TokenExpiredException("Token has expired")
        elif token == "invalid-token":
            raise InvalidTokenException("Invalid token")
        else:
            return None
    mock.decode_token.side_effect = mock_decode_token
    return mock

@pytest.fixture
def app(
    mock_auth_service: AsyncMock,
    mock_jwt_service: AsyncMock
) -> FastAPI:
    """Creates a FastAPI app instance with middleware for testing."""
    app = FastAPI()
    app.add_middleware(
        AuthenticationMiddleware,
        public_paths=["/public"]
    )
    
    @app.get("/public")
    async def public_route() -> Dict[str, str]:
        return {"message": "public access"}
        
    @app.get("/protected")
    async def protected_route() -> Dict[str, str]:
        return {"message": "protected access"}
    
    return app

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
    assert "Authentication required" in response.text

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
    assert "Authentication failed" in response.text

@pytest.mark.asyncio
async def test_protected_route_with_expired_token(async_client: AsyncClient) -> None:
    """Test that protected routes return 401 with an expired token."""
    response = await async_client.get(
        "/protected", headers={"Authorization": "Bearer expired"}
    )
    assert response.status_code == 401
    assert "Authentication failed" in response.text
