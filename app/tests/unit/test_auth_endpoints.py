"""
Unit tests for the auth endpoints.

These tests mock the dependencies to test the endpoints functionality
in isolation from the full application.
"""

import pytest
import asyncio
import uuid
from fastapi import FastAPI, status
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, MagicMock, patch

# Import SQLAlchemy components for table creation
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

# Import the base model to create tables
from app.infrastructure.persistence.sqlalchemy.models.base import Base
from app.infrastructure.persistence.sqlalchemy.models.user import User as UserModel

# Import the endpoints module directly
from app.presentation.api.v1.endpoints.auth import (
    router, 
    login, 
    refresh_token as refresh_token_endpoint,
    logout,
    get_current_user_profile,
    get_session_info
)
from app.domain.entities.user import User
from app.domain.enums.role import Role
from app.infrastructure.security.auth.authentication_service import AuthenticationService
from app.infrastructure.repositories.user_repository import SqlAlchemyUserRepository


# Create fixed test user IDs for consistent reference
TEST_USER_ID = "00000000-0000-0000-0000-000000000001"
TEST_INACTIVE_USER_ID = "00000000-0000-0000-0000-000000000002"


@pytest.fixture(scope="session", autouse=True)
async def setup_database():
    """Create database tables before running tests."""
    # Create in-memory database for testing
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=True)
    
    # Create all tables from SQLAlchemy models
    async with engine.begin() as conn:
        # Enable foreign keys in SQLite
        await conn.execute(text("PRAGMA foreign_keys=ON"))
        
        # Create all tables defined in Base.metadata
        await conn.run_sync(Base.metadata.create_all)
    
    yield
    
    # Clean up after tests (optional for in-memory DB)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest.fixture
def app():
    """Create a FastAPI app with just the auth router."""
    app = FastAPI()
    app.include_router(router, prefix="/api/v1/auth")
    return app


@pytest.fixture
def client(app):
    """Create a test client using the test app."""
    return TestClient(app)


@pytest.fixture
def mock_auth_service():
    """Create a mock authentication service."""
    mock = AsyncMock()
    
    # Add mock settings directly to the mock service object
    # This mimics the structure if the service holds a settings attribute
    mock.settings = MagicMock()
    mock.settings.JWT_SECRET_KEY = "test-secret"
    mock.settings.JWT_ALGORITHM = "HS256"
    mock.settings.ACCESS_TOKEN_EXPIRE_MINUTES = 15
    mock.settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS = 7 # Corrected attribute name
    mock.settings.JWT_ISSUER = "test-issuer"
    mock.settings.JWT_AUDIENCE = "test-audience"

    # Configure the authenticate_user method to use our fixed test user IDs
    async def mock_authenticate(username, password):
        if username == "testuser" and password == "testpassword":
            return User(
                id=TEST_USER_ID,
                username="testuser",
                email="test@example.com",
                roles=[Role.PROVIDER],
                is_active=True
            )
        elif username == "inactive" and password == "testpassword":
            return User(
                id=TEST_INACTIVE_USER_ID,
                username="inactive",
                email="inactive@example.com",
                roles=[Role.PROVIDER],
                is_active=False
            )
        return None
    
    mock.authenticate_user.side_effect = mock_authenticate
    
    # Configure the create_token_pair method
    async def mock_create_token_pair(user):
        return {
            "access_token": f"test_access_token_{user.id}",
            "refresh_token": f"test_refresh_token_{user.id}"
        }
    
    mock.create_token_pair.side_effect = mock_create_token_pair
    
    # Configure the refresh_token method
    async def mock_refresh(token):
        if token.startswith("test_refresh_token_"):
            return {
                "access_token": "new_access_token",
                "refresh_token": "new_refresh_token"
            }
        raise ValueError("Invalid refresh token")
    
    mock.refresh_token.side_effect = mock_refresh
    
    # Configure the logout method
    async def mock_logout(tokens):
        return True
    
    mock.logout.side_effect = mock_logout
    
    return mock


@pytest.fixture
def mock_user_repository():
    """Create a mock user repository."""
    # Create the mock without spec to avoid attribute errors
    mock = AsyncMock()
    
    # Configure the get_by_id method
    async def mock_get_by_id(user_id):
        if user_id == TEST_USER_ID:
            return User(
                id=TEST_USER_ID,
                username="testuser",
                email="test@example.com",
                roles=[Role.PROVIDER],
                is_active=True
            )
        elif user_id == TEST_INACTIVE_USER_ID:
            return User(
                id=TEST_INACTIVE_USER_ID,
                username="inactive",
                email="inactive@example.com",
                roles=[Role.PROVIDER],
                is_active=False
            )
        return None
    
    mock.get_by_id.side_effect = mock_get_by_id
    
    # Configure the get_by_username method
    async def mock_get_by_username(username):
        if username == "testuser":
            return User(
                id=TEST_USER_ID,
                username="testuser",
                email="test@example.com",
                roles=[Role.PROVIDER],
                is_active=True,
                hashed_password="hashed_password"
            )
        elif username == "inactive":
            return User(
                id=TEST_INACTIVE_USER_ID,
                username="inactive",
                email="inactive@example.com",
                roles=[Role.PROVIDER],
                is_active=False,
                hashed_password="hashed_password"
            )
        return None
    
    mock.get_by_username.side_effect = mock_get_by_username
    
    return mock


@pytest.fixture
def mock_dependencies(app, mock_auth_service, mock_user_repository):
    """Override the endpoint dependencies."""
    # Override the endpoint dependencies
    app.dependency_overrides = {
        # Use mocks for both auth service and user repository
        "app.presentation.api.v1.endpoints.auth.get_auth_service_provider": lambda: mock_auth_service,
        "app.presentation.api.v1.endpoints.auth.get_user_repository_provider": lambda: mock_user_repository,
        "app.presentation.api.v1.endpoints.auth.get_current_user": lambda: {
            "sub": TEST_USER_ID,
            "roles": ["provider"],
            "permissions": ["read:patients"]
        },
        "app.presentation.api.v1.endpoints.auth.get_optional_user": lambda: {
            "sub": TEST_USER_ID,
            "roles": ["provider"],
            "permissions": ["read:patients"],
            "exp": 1619900000
        }
    }
    
    yield app.dependency_overrides


# Tests for login endpoint
def test_login_success(client, mock_auth_service, mock_dependencies):
    """Test successful login."""
    # Arrange
    login_data = {
        "username": "testuser",
        "password": "testpassword",
        "remember_me": False
    }
    
    # Act
    response = client.post("/api/v1/auth/login", json=login_data)
    
    # Assert
    assert response.status_code == status.HTTP_200_OK
    assert "access_token" in response.json()
    assert "refresh_token" in response.json()
    assert response.json()["token_type"] == "bearer"


def test_login_invalid_credentials(client, mock_auth_service, mock_dependencies):
    """Test login with invalid credentials."""
    # Arrange
    login_data = {
        "username": "invalid",
        "password": "invalid",
        "remember_me": False
    }
    
    # Act
    response = client.post("/api/v1/auth/login", json=login_data)
    
    # Assert
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "detail" in response.json()
    assert response.json()["detail"] == "Invalid credentials"


def test_login_inactive_account(client, mock_auth_service, mock_dependencies):
    """Test login with an inactive account."""
    # Arrange
    login_data = {
        "username": "inactive",
        "password": "testpassword",
        "remember_me": False
    }
    
    # Act
    response = client.post("/api/v1/auth/login", json=login_data)
    
    # Assert
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "detail" in response.json()
    assert response.json()["detail"] == "Account is inactive"


# Tests for refresh token endpoint
def test_refresh_token_success(client, mock_auth_service, mock_dependencies):
    """Test successful token refresh."""
    # Arrange
    refresh_data = {
        "refresh_token": f"test_refresh_token_{TEST_USER_ID}"
    }
    
    # Act
    response = client.post("/api/v1/auth/refresh", json=refresh_data)
    
    # Assert
    assert response.status_code == status.HTTP_200_OK
    assert "access_token" in response.json()
    assert "refresh_token" in response.json()
    assert response.json()["token_type"] == "bearer"


def test_refresh_token_invalid(client, mock_auth_service, mock_dependencies):
    """Test refresh with invalid token."""
    # Arrange
    refresh_data = {
        "refresh_token": "invalid_token"
    }
    
    # Act
    response = client.post("/api/v1/auth/refresh", json=refresh_data)
    
    # Assert
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


# Test for session info endpoint
def test_session_info(client, mock_dependencies):
    """Test session info endpoint."""
    # Act
    response = client.get("/api/v1/auth/session-info")
    
    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["authenticated"] is True
    assert data["user_id"] == TEST_USER_ID
    assert data["roles"] == ["provider"]


# It's better to mock the settings object passed to the service
# Let's assume the service gets settings via dependency injection or direct instantiation
# Modify the JWTService fixture in conftest.py or mock settings where JWTService is created

# If JWTService is created directly in tests (less ideal), ensure settings are mocked correctly:
# Example assuming direct creation or modification within a test:
# mock_settings = MagicMock()
# mock_settings.JWT_SECRET_KEY = "test_secret"
# mock_settings.JWT_ALGORITHM = "HS256"
# mock_settings.ACCESS_TOKEN_EXPIRE_MINUTES = 15
# mock_settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS = 7 # Corrected attribute name
# jwt_service_instance = JWTService(settings=mock_settings)

# The previous attempt added a test_mock_settings function which is not the correct place.
# Let's modify the conftest.py fixture instead if that's where the JWTService for tests is created.
# If not, we need to find where the JWTService used by the mocked AuthenticationService gets its settings.

# For now, let's ensure the conftest.py fixture uses the correct name.
# I will edit conftest.py next. 