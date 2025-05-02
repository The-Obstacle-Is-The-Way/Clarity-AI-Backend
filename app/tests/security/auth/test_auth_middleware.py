import time
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.domain.exceptions.token_exceptions import InvalidTokenException, TokenExpiredException
from app.infrastructure.security.auth.authentication_service import AuthenticationService
from app.infrastructure.security.jwt.jwt_service import JWTService, TokenPayload
from app.presentation.middleware.authentication_middleware import AuthenticationMiddleware


@pytest.fixture
def mock_auth_service():
    mock = AsyncMock(spec=AuthenticationService)
    async def mock_validate_token(token: str):
        if token == "expired":
            raise Exception("TokenExpiredError")
        if token == "invalid":
            raise Exception("InvalidTokenError")
        if token in ["patient123", "provider123", "admin123"]:
            user = MagicMock()
            user.id = token
            if token.startswith("patient"):
                user.roles = ["patient"]
            elif token.startswith("provider"):
                user.roles = ["provider"]
            elif token.startswith("admin"):
                user.roles = ["admin"]
            return user, ["read:all"]
        return None, []
    mock.validate_token.side_effect = mock_validate_token
    return mock

@pytest.fixture
def mock_jwt_service():
    mock = AsyncMock(spec=JWTService)
    async def mock_decode_token(token: str):
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
def app(mock_auth_service, mock_jwt_service):
    app = FastAPI()
    app.add_middleware(
        AuthenticationMiddleware,
        public_paths=["/public"]
    )
    
    @app.get("/public")
    async def public_route():
        return {"message": "public access"}
        
    @app.get("/protected")
    async def protected_route():
        return {"message": "protected access"}
    
    return app

@pytest.fixture
def test_client(app):
    return TestClient(app)

def test_public_route_access(test_client):
    response = test_client.get("/public")
    assert response.status_code == 200
    assert response.json() == {"message": "public access"}

def test_protected_route_no_token(test_client):
    response = test_client.get("/protected")
    assert response.status_code == 401
    assert "Authentication required" in response.text

def test_protected_route_with_valid_token(test_client):
    response = test_client.get("/protected", headers={"Authorization": "Bearer patient123"})
    assert response.status_code == 200
    assert response.json() == {"message": "protected access"}

def test_protected_route_with_invalid_token(test_client):
    response = test_client.get("/protected", headers={"Authorization": "Bearer invalid"})
    assert response.status_code == 401
    assert "Authentication failed" in response.text

def test_protected_route_with_expired_token(test_client):
    response = test_client.get("/protected", headers={"Authorization": "Bearer expired"})
    assert response.status_code == 401
    assert "Authentication failed" in response.text
