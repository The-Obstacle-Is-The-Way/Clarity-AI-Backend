"""
Unit tests for the auth endpoints.

These tests mock the dependencies to test the endpoints functionality
in isolation from the full application.
"""

import asyncio
import warnings
from datetime import datetime
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI, status
from fastapi.testclient import TestClient

# Import SQLAlchemy components
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from app.core.config import settings

# Import domain entities and enums
from app.domain.entities.user import User
from app.domain.enums.role import Role
from app.domain.exceptions.token_exceptions import InvalidTokenError

# Import the base model
from app.infrastructure.persistence.sqlalchemy.models.base import Base

# Import services and repositories
from app.infrastructure.security.auth.authentication_service import (
    AuthenticationService,
)
from app.presentation.api.dependencies.auth import get_current_user, get_optional_user

# Import dependencies providers
from app.presentation.api.dependencies.auth_service import get_auth_service
from app.presentation.api.dependencies.repositories import get_user_repository

# Import the router
from app.presentation.api.v1.endpoints.auth import router as auth_router

# Suppress datetime binary incompatibility warning
warnings.filterwarnings(
    "ignore", message=".*datetime.datetime size changed.*", category=RuntimeWarning
)


# Create fixed test user IDs for consistent reference
TEST_USER_ID = "00000000-0000-0000-0000-000000000001"
TEST_INACTIVE_USER_ID = "00000000-0000-0000-0000-000000000002"


# Changed from session to function scope to fix ScopeMismatch error
@pytest.fixture(scope="function")
async def setup_database():
    """Create database tables before running tests."""
    # Create in-memory database for testing
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")

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
def app() -> FastAPI:
    """Create a FastAPI app with just the auth router."""
    app_instance = FastAPI()
    app_instance.include_router(auth_router, prefix="/api/v1/auth")
    return app_instance


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    """Create a test client using the test app."""
    return TestClient(app)


@pytest.fixture
def test_user() -> User:
    """Create a consistent test user object."""
    return User(
        id=TEST_USER_ID,
        username="testuser",
        email="test@example.com",
        first_name="Test",
        last_name="User",
        roles=[Role.PROVIDER],
        is_active=True,
        created_at=datetime.now(),
    )


@pytest.fixture
def mock_auth_service(test_user: User) -> AsyncMock:
    """Create a mock authentication service."""
    mock = AsyncMock(spec=AuthenticationService)

    # Configure the authenticate_user method
    async def mock_authenticate(username: str, password: str) -> User | None:
        if username == "testuser" and password == "testpassword":
            return test_user
        elif username == "inactive" and password == "testpassword":
            return User(
                id=TEST_INACTIVE_USER_ID,
                username="inactive",
                email="inactive@example.com",
                first_name="Inactive",
                last_name="User",
                roles=[Role.PROVIDER],
                is_active=False,
                created_at=datetime.now(),
            )
        return None

    mock.authenticate_user.side_effect = mock_authenticate

    # Configure create_token_pair method
    mock.create_token_pair.return_value = {
        "access_token": f"test_access_token_{TEST_USER_ID}",
        "refresh_token": f"test_refresh_token_{TEST_USER_ID}",
    }

    # Configure refresh_token method
    mock.refresh_token.return_value = {
        "access_token": f"new_access_token_{TEST_USER_ID}",
        "refresh_token": f"new_refresh_token_{TEST_USER_ID}",
    }

    # Add refresh_access_token method that the endpoint actually uses
    mock.refresh_access_token.return_value = {
        "access_token": f"new_access_token_{TEST_USER_ID}",
        "refresh_token": f"new_refresh_token_{TEST_USER_ID}",
    }

    # Configure the logout method
    async def mock_logout(tokens: list[str]) -> bool:
        return True

    mock.logout.side_effect = mock_logout

    return mock


@pytest.fixture
def mock_user_repository(test_user: User) -> AsyncMock:
    """Create a mock user repository."""
    mock = AsyncMock()

    # Configure the get_by_id method
    async def mock_get_by_id(user_id: str) -> User | None:
        if user_id == TEST_USER_ID:
            return test_user
        elif user_id == TEST_INACTIVE_USER_ID:
            return User(
                id=TEST_INACTIVE_USER_ID,
                username="inactive",
                email="inactive@example.com",
                first_name="Inactive",
                last_name="User",
                roles=[Role.PROVIDER],
                is_active=False,
                created_at=datetime.now(),
            )
        return None

    mock.get_by_id.side_effect = mock_get_by_id

    # Configure the get_by_username method
    async def mock_get_by_username(username: str) -> User | None:
        if username == "testuser":
            return User(
                id=TEST_USER_ID,
                username="testuser",
                email="test@example.com",
                first_name="Test",
                last_name="User",
                roles=[Role.PROVIDER],
                is_active=True,
                hashed_password="hashed_password",
                created_at=datetime.now(),
            )
        elif username == "inactive":
            return User(
                id=TEST_INACTIVE_USER_ID,
                username="inactive",
                email="inactive@example.com",
                first_name="Inactive",
                last_name="User",
                roles=[Role.PROVIDER],
                is_active=False,
                hashed_password="hashed_password",
                created_at=datetime.now(),
            )
        return None

    mock.get_by_username.side_effect = mock_get_by_username

    return mock


@pytest.fixture
def mock_optional_user(test_user: User) -> dict:
    """Mock the optional user dependency to return user data."""
    return {
        "sub": str(test_user.id),
        "email": test_user.email,
        "roles": test_user.roles,
        "exp": int(datetime.now().timestamp()) + 3600,
        "permissions": ["read:patient", "write:patient"],
    }


@pytest.fixture
def mock_dependencies(
    app: FastAPI,
    mock_auth_service: AsyncMock,
    mock_user_repository: AsyncMock,
    test_user: User,
    mock_optional_user: dict,
) -> None:
    """Override dependencies for the test app."""
    app.dependency_overrides[get_auth_service] = lambda: mock_auth_service
    app.dependency_overrides[get_user_repository] = lambda: mock_user_repository
    app.dependency_overrides[get_current_user] = lambda: test_user
    app.dependency_overrides[get_optional_user] = lambda: mock_optional_user


@pytest.fixture
def event_loop():
    """Create an instance of the default event loop for each test case."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


# Tests for login endpoint
@pytest.mark.asyncio
async def test_login_success(
    client: TestClient,
    mock_auth_service: AsyncMock,
    mock_dependencies: None,
    setup_database,
    test_user: User,
) -> None:
    """Test successful login."""
    # Arrange
    login_data = {
        "username": "testuser",
        "password": "testpassword",
        "remember_me": False,
    }

    # Act
    response = client.post("/api/v1/auth/login", json=login_data)

    # Assert
    assert response.status_code == status.HTTP_200_OK
    mock_auth_service.authenticate_user.assert_called_once_with("testuser", "testpassword")

    # Check token creation was called - don't compare User objects directly due to datetime differences
    mock_auth_service.create_token_pair.assert_called_once()

    # Check response structure
    response_data = response.json()
    expected_response = {
        "access_token": f"test_access_token_{TEST_USER_ID}",
        "refresh_token": f"test_refresh_token_{TEST_USER_ID}",
        "token_type": "bearer",
    }

    # Check fields individually to handle different expires_in values
    assert response_data["access_token"] == expected_response["access_token"]
    assert response_data["refresh_token"] == expected_response["refresh_token"]
    assert response_data["token_type"] == expected_response["token_type"]

    # The expires_in field will be different in test mode (3600 seconds = 1 hour)
    # vs regular mode (settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60)
    assert "expires_in" in response_data
    assert response_data["expires_in"] in [
        3600,  # 1 hour for test environment
        settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,  # Default from settings
    ]


@pytest.mark.asyncio
async def test_login_invalid_credentials(
    client: TestClient,
    mock_auth_service: AsyncMock,
    mock_dependencies: None,
    setup_database,
) -> None:
    """Test login with invalid credentials."""
    # Arrange
    login_data = {
        "username": "wronguser",
        "password": "wrongpass",
        "remember_me": False,
    }

    # Configure mock to return None for invalid credentials
    mock_auth_service.authenticate_user.return_value = None

    # Act
    response = client.post("/api/v1/auth/login", json=login_data)

    # Assert
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    mock_auth_service.authenticate_user.assert_called_once_with("wronguser", "wrongpass")
    assert "detail" in response.json()
    assert response.json()["detail"] == "Invalid credentials"


@pytest.mark.asyncio
async def test_login_inactive_account(
    client: TestClient,
    mock_auth_service: AsyncMock,
    mock_dependencies: None,
    setup_database,
) -> None:
    """Test login with an inactive account."""
    # Arrange
    login_data = {
        "username": "inactive",
        "password": "testpassword",
        "remember_me": False,
    }

    # Act
    response = client.post("/api/v1/auth/login", json=login_data)

    # Assert
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    mock_auth_service.authenticate_user.assert_called_once_with("inactive", "testpassword")
    assert "detail" in response.json()
    assert response.json()["detail"] == "Account is inactive"


@pytest.mark.asyncio
async def test_refresh_token_success(
    client: TestClient,
    mock_auth_service: AsyncMock,
    mock_dependencies: None,
    setup_database,
) -> None:
    """Test successful token refresh."""
    # Arrange
    refresh_data = {"refresh_token": f"test_refresh_token_{TEST_USER_ID}"}

    # Act
    response = client.post("/api/v1/auth/refresh", json=refresh_data)

    # Assert
    assert response.status_code == status.HTTP_200_OK
    mock_auth_service.refresh_access_token.assert_called_once_with(
        refresh_token_str=f"test_refresh_token_{TEST_USER_ID}"
    )

    # Check response structure
    response_data = response.json()
    assert response_data["access_token"] == f"new_access_token_{TEST_USER_ID}"
    assert response_data["refresh_token"] == f"new_refresh_token_{TEST_USER_ID}"
    assert response_data["token_type"] == "bearer"

    # The expires_in field will be different in test mode (3600 seconds = 1 hour)
    # vs regular mode (settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60)
    assert "expires_in" in response_data
    assert response_data["expires_in"] in [
        3600,  # 1 hour for test environment
        settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,  # Default from settings
    ]


@pytest.mark.asyncio
async def test_refresh_token_invalid(
    client: TestClient,
    mock_auth_service: AsyncMock,
    mock_dependencies: None,
    setup_database,
) -> None:
    """Test refreshing with an invalid token."""
    # Arrange
    refresh_data = {"refresh_token": "invalid_refresh_token"}

    # Configure the refresh_access_token method to raise an exception
    mock_auth_service.refresh_access_token.side_effect = InvalidTokenError("Invalid refresh token")

    # Act
    response = client.post("/api/v1/auth/refresh", json=refresh_data)

    # Assert
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    mock_auth_service.refresh_access_token.assert_called_once_with(
        refresh_token_str="invalid_refresh_token"
    )
    assert "detail" in response.json()
    assert "Invalid refresh token" in response.json()["detail"]


@pytest.mark.asyncio
async def test_session_info(client: TestClient, mock_dependencies: None, setup_database) -> None:
    """Test getting session info for an authenticated user."""
    # Act
    response = client.get("/api/v1/auth/session-info")

    # Assert
    assert response.status_code == status.HTTP_200_OK

    # Check response content matches the expected structure
    session_data = response.json()
    assert session_data["authenticated"] is True
    assert session_data["session_active"] is True
    assert session_data["user_id"] == TEST_USER_ID
    assert session_data["roles"] == [Role.PROVIDER]
