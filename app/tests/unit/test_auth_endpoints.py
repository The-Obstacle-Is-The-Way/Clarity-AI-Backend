"""
Unit tests for the auth endpoints.

These tests mock the dependencies to test the endpoints functionality
in isolation from the full application.
"""

import pytest
import warnings
from fastapi import FastAPI, status
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock
from collections.abc import Callable

# Import SQLAlchemy components
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

# Import the base model
from app.infrastructure.persistence.sqlalchemy.models.base import Base

# Import the router
from app.presentation.api.v1.endpoints.auth import router

# Import domain entities and enums
from app.domain.entities.user import User
from app.domain.enums.role import Role
from app.domain.exceptions import InvalidTokenError

# Import services and repositories
from app.infrastructure.security.auth.authentication_service import AuthenticationService

# Import dependencies providers
from app.presentation.api.dependencies.auth_service import get_auth_service_provider
from app.presentation.api.dependencies.user_repository import get_user_repository_provider
from app.presentation.api.dependencies.auth import get_current_user, get_optional_user


# Suppress datetime binary incompatibility warning
warnings.filterwarnings(
    "ignore", 
    message=".*datetime.datetime size changed.*", 
    category=RuntimeWarning
)


# Create fixed test user IDs for consistent reference
TEST_USER_ID = "00000000-0000-0000-0000-000000000001"
TEST_INACTIVE_USER_ID = "00000000-0000-0000-0000-000000000002"


@pytest.fixture(scope="session", autouse=True)
async def setup_database() -> None:
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
    app_instance.include_router(router, prefix="/api/v1/auth")
    return app_instance


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    """Create a test client using the test app."""
    return TestClient(app)


@pytest.fixture
def mock_auth_service() -> AsyncMock:
    """Create a mock authentication service."""
    mock = AsyncMock(spec=AuthenticationService) # Use spec for better mocking
    
    # Configure the authenticate_user method
    async def mock_authenticate(username: str, password: str) -> User | None:
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
    
    # Configure create_access_token method
    async def mock_create_access_token(user: User) -> str:
        return f"test_access_token_{user.id}"
    mock.create_access_token.side_effect = mock_create_access_token

    # Configure create_refresh_token method
    async def mock_create_refresh_token(user: User) -> str:
        return f"test_refresh_token_{user.id}"
    mock.create_refresh_token.side_effect = mock_create_refresh_token
    
    # Configure the logout method (keep if needed for logout tests)
    async def mock_logout(tokens: dict[str, str]) -> bool:
        return True
    
    mock.logout.side_effect = mock_logout
    
    return mock


@pytest.fixture
def mock_user_repository() -> AsyncMock:
    """Create a mock user repository."""
    # Create the mock without spec to avoid attribute errors
    mock = AsyncMock()
    
    # Configure the get_by_id method
    async def mock_get_by_id(user_id: str) -> User | None:
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
    async def mock_get_by_username(username: str) -> User | None:
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
def mock_dependencies(
    app: FastAPI, 
    mock_auth_service: AsyncMock, 
    mock_user_repository: AsyncMock
) -> None:
    """Override dependencies for the test app."""
    app.dependency_overrides[get_auth_service_provider] = lambda: mock_auth_service
    app.dependency_overrides[get_user_repository_provider] = lambda: mock_user_repository
    
    # Mock auth dependencies if needed for specific tests like get_current_user
    test_user = User(
        id=TEST_USER_ID, 
        username="testuser", 
        email="test@example.com", 
        roles=[Role.PROVIDER], 
        is_active=True
    )
    app.dependency_overrides[get_current_user] = lambda: test_user
    app.dependency_overrides[get_optional_user] = lambda: test_user 


# Tests for login endpoint
async def test_login_success(
    client: TestClient, 
    mock_auth_service: AsyncMock, 
    mock_dependencies: Callable
) -> None:
    """Test successful login."""
    # Arrange
    login_data = {"username": "testuser", "password": "testpassword"}
    
    # Act
    response = client.post("/api/v1/auth/login", json=login_data)
    
    # Assert
    assert response.status_code == status.HTTP_200_OK
    mock_auth_service.authenticate_user.assert_called_once_with(
        "testuser", "testpassword"
    )
    # Assert that token creation methods were called for the authenticated user
    authenticated_user = await mock_auth_service.authenticate_user("testuser", "testpassword")
    mock_auth_service.create_access_token.assert_called_once_with(authenticated_user)
    mock_auth_service.create_refresh_token.assert_called_once_with(authenticated_user)

    # Check response body (adjust based on actual endpoint response structure)
    # Assuming the endpoint returns tokens directly
    access_token = await mock_auth_service.create_access_token(authenticated_user)
    refresh_token = await mock_auth_service.create_refresh_token(authenticated_user)
    assert response.json() == {
        "access_token": access_token,
        "refresh_token": refresh_token, 
        "token_type": "bearer"
    }


async def test_login_invalid_credentials(
    client: TestClient, 
    mock_auth_service: AsyncMock, 
    mock_dependencies: Callable
) -> None:
    """Test login with invalid credentials."""
    # Arrange
    login_data = {"username": "testuser", "password": "wrongpassword"}
    
    # Act
    response = client.post("/api/v1/auth/login", json=login_data)
    
    # Assert
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "detail" in response.json()
    assert response.json()["detail"] == "Incorrect username or password"


async def test_login_inactive_account(
    client: TestClient, 
    mock_auth_service: AsyncMock, 
    mock_dependencies: Callable
) -> None:
    """Test login with an inactive account."""
    # Arrange
    login_data = {"username": "inactive", "password": "testpassword"}
    
    # Act
    response = client.post("/api/v1/auth/login", json=login_data)
    
    # Assert
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "detail" in response.json()
    assert response.json()["detail"] == "Account is inactive"


# Tests for refresh token endpoint
async def test_refresh_token_success(
    client: TestClient, 
    mock_auth_service: AsyncMock, 
    mock_dependencies: Callable
) -> None:
    """Test successful token refresh."""
    refresh_token = f"test_refresh_token_{TEST_USER_ID}"
    
    # Assuming refresh token is sent in a header or cookie
    # Adjust based on how the actual refresh endpoint expects the token
    headers = {"Authorization": f"Bearer {refresh_token}"} # Example: Header
    
    response = client.post("/api/v1/auth/refresh", headers=headers)
    
    assert response.status_code == status.HTTP_200_OK
    # Check response body for the new access token
    assert "access_token" in response.json()
    assert response.json().get("token_type") == "bearer"


async def test_refresh_token_invalid(
    client: TestClient, 
    mock_auth_service: AsyncMock, 
    mock_dependencies: Callable
) -> None:
    """Test refresh with invalid token."""
    invalid_token = "invalid_refresh_token"
    headers = {"Authorization": f"Bearer {invalid_token}"} # Example: Header
    
    response = client.post("/api/v1/auth/refresh", headers=headers)
    
    # Expecting an error (e.g., 401 Unauthorized or 400 Bad Request)
    assert response.status_code in [status.HTTP_401_UNAUTHORIZED, status.HTTP_400_BAD_REQUEST]


# Test for session info endpoint
async def test_session_info(
    client: TestClient, 
    mock_dependencies: Callable
) -> None:
    """Test session info endpoint."""
    # Need Authorization header with a valid token for get_current_user
    # Let's create a dummy token based on our mocked service
    # NOTE: This assumes the get_current_user dependency is correctly mocked
    # by mock_dependencies fixture to return the test_user.
    dummy_access_token = f"test_access_token_{TEST_USER_ID}" 
    headers = {"Authorization": f"Bearer {dummy_access_token}"} 

    response = client.get("/api/v1/auth/session", headers=headers)
    
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["authenticated"] is True
    assert data["user_id"] == TEST_USER_ID
    assert data["roles"] == ["provider"]