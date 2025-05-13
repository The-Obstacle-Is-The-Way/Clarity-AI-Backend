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
    
    # Set up async methods
    mock_service.create_access_token = AsyncMock()
    mock_service.create_access_token.return_value = "mocked.access.token"
    
    mock_service.decode_token = AsyncMock()
    mock_service.decode_token.return_value = MagicMock(
        sub="a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11",
        roles=["read:patients", "write:clinical_notes"],
        exp=9999999999
    )
    
    mock_service.verify_token = AsyncMock(return_value=True)
    
    # Customize create_access_token to use provided data
    async def custom_create_token(data=None, expires_delta=None):
        # Generate a fake token with some identifiable structure
        if not data:
            return "mocked.access.token.no.data"
        
        # Create a token with a format that includes some of the token data
        # to make it identifiable in tests
        prefix = "test" if "test" in data.get("sub", "") else "user"
        roles_str = ".".join(data.get("roles", []))[:20]  # Limit length
        return f"mocked.{prefix}.token.{roles_str}"
    
    mock_service.create_access_token.side_effect = custom_create_token
    
    return mock_service


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