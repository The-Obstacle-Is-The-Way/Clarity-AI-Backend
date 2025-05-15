"""Test fixtures for the endpoints tests."""

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI
from httpx import AsyncClient, ASGITransport

from app.core.config.settings import Settings as AppSettings
from app.core.domain.entities.user import User, UserRole, UserStatus
from app.core.interfaces.services.jwt_service_interface import JWTServiceInterface


@pytest.fixture(scope="module")
def global_mock_jwt_service() -> MagicMock:
    """Create a module-scoped mock JWT service that can be used across tests."""
    mock_service = MagicMock(spec=JWTServiceInterface)
    
    # Import the TokenPayload model for proper type conformance
    from app.infrastructure.security.jwt.jwt_service import TokenPayload, TokenType
    
    # Set up async methods
    mock_service.create_access_token = AsyncMock()
    mock_service.create_access_token.return_value = "mocked.access.token"
    
    # Configure decode_token to return a proper TokenPayload model
    mock_service.decode_token = AsyncMock()
    def mock_decode_token(token, **kwargs):
        # Return a properly constructed TokenPayload
        return TokenPayload(
            sub="a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11",
            exp=int(datetime.now(timezone.utc).timestamp()) + 3600,  # 1 hour in the future
            iat=int(datetime.now(timezone.utc).timestamp()),
            jti=str(uuid.uuid4()),
            type=TokenType.ACCESS,
            roles=["clinician"],
            iss="test-issuer",
            aud="test-audience"
        )
    
    mock_service.decode_token.side_effect = mock_decode_token
    
    mock_service.verify_token = AsyncMock(return_value=True)
    
    # Customize create_access_token to use provided data
    async def custom_create_token(data=None, expires_delta=None, **kwargs):
        # Generate a fake token with some identifiable structure
        if not data:
            return "mocked.access.token.no.data"
        
        # Create a token with a format that includes some of the token data
        # to make it identifiable in tests
        prefix = "test" if "test" in data.get("sub", "") else "user"
        roles_str = ".".join(data.get("roles", []))[:20]  # Limit length
        return f"mocked.{prefix}.token.{roles_str}"
    
    mock_service.create_access_token.side_effect = custom_create_token
    
    # Add verify_access_token and verify_refresh_token methods
    mock_service.verify_access_token = AsyncMock()
    def mock_verify_access_token(token, **kwargs):
        return TokenPayload(
            sub="a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11",
            exp=int(datetime.now(timezone.utc).timestamp()) + 3600,  # 1 hour in the future
            iat=int(datetime.now(timezone.utc).timestamp()),
            jti=str(uuid.uuid4()),
            type=TokenType.ACCESS,
            roles=["clinician"],
            iss="test-issuer",
            aud="test-audience"
        )
    
    mock_service.verify_access_token.side_effect = mock_verify_access_token
    
    mock_service.verify_refresh_token = AsyncMock()
    def mock_verify_refresh_token(token, **kwargs):
        return TokenPayload(
            sub="a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11",
            exp=int(datetime.now(timezone.utc).timestamp()) + 3600 * 24,  # 24 hours in the future
            iat=int(datetime.now(timezone.utc).timestamp()),
            jti=str(uuid.uuid4()),
            type=TokenType.REFRESH,
            roles=["clinician"],
            iss="test-issuer",
            aud="test-audience"
        )
    
    mock_service.verify_refresh_token.side_effect = mock_verify_refresh_token
    
    return mock_service


@pytest.fixture
def authenticated_user() -> User:
    """Create a test user with authentication credentials."""
    return User(
        id=str(uuid.UUID("a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11")),  # Convert UUID to string
        username="test_doctor",
        email="test.doctor@example.com", 
        full_name="Test Doctor",
        first_name="Test",  # Add required field
        last_name="Doctor",  # Add required field
        roles={UserRole.CLINICIAN},
        status=UserStatus.ACTIVE,  # Using 'status' instead of 'account_status'
        hashed_password="hashed_password_not_real",
        created_at=datetime.now(timezone.utc),
    ) 


@pytest.fixture
async def auth_headers(global_mock_jwt_service: MagicMock, authenticated_user: User) -> dict[str, str]:
    """Provides headers with a test JWT token for authenticated requests."""
    # Create a token using the global mock JWT service
    # Handle roles correctly - convert to string values if they're enum objects
    roles = []
    for role in authenticated_user.roles:
        role_value = role.value if hasattr(role, 'value') else str(role)
        roles.append(role_value)
    
    token_data = {
        "sub": str(authenticated_user.id),
        "roles": roles,
        "username": authenticated_user.username,
        "email": authenticated_user.email,
        "type": "access"
    }
    access_token = await global_mock_jwt_service.create_access_token(data=token_data)
    return {"Authorization": f"Bearer {access_token}"} 