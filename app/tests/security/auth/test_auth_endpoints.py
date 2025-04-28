"""
Test suite for auth endpoints.

These tests verify the functionality of the authentication endpoints
using direct API calls to ensure proper behavior.
"""
import pytest
import json
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, MagicMock, patch
from app.main import app as application, create_application
from app.infrastructure.security.auth.authentication_service import AuthenticationService
from app.domain.entities.user import User
from app.domain.enums.role import Role
from app.presentation.api.dependencies.auth_service import get_auth_service_provider
from app.presentation.api.routes import setup_routers

# Create a test client
@pytest.fixture
def client(mock_auth_service):
    """Create a FastAPI test client with overridden dependencies."""
    
    # Define the override function
    def override_get_auth_service():
        return mock_auth_service
        
    # Create the app with the override
    app = create_application(dependency_overrides={
        get_auth_service_provider: override_get_auth_service
    })
    
    # Explicitly call setup_routers AFTER creating the app instance
    # This ensures routers are added to the specific app instance used by TestClient
    # setup_routers() # REMOVED - create_application should handle this now
    
    with TestClient(app) as test_client:
        yield test_client

@pytest.fixture
def mock_auth_service():
    """Create a mock authentication service."""
    mock = AsyncMock(spec=AuthenticationService)
    
    # Set up authenticate_user to return a user based on username
    async def mock_authenticate(username, password):
        if username == "testuser" and password == "testpassword":
            return User(
                id="user123",
                username="testuser",
                email="testuser@example.com",
                roles=[Role.PROVIDER],
                is_active=True,
                first_name="Test",
                last_name="User"
            )
        elif username == "inactive" and password == "testpassword":
            return User(
                id="inactive123",
                username="inactive",
                email="inactive@example.com",
                roles=[Role.PROVIDER],
                is_active=False,
                first_name="Inactive",
                last_name="User"
            )
        else:
            return None
            
    mock.authenticate_user.side_effect = mock_authenticate
    
    # Set up create_token_pair to return mock tokens
    async def mock_create_token_pair(user):
        return {
            "access_token": f"mock_access_token_for_{user.id}",
            "refresh_token": f"mock_refresh_token_for_{user.id}"
        }
        
    mock.create_token_pair.side_effect = mock_create_token_pair
    
    # Set up refresh_token to return new tokens
    async def mock_refresh_token(refresh_token):
        if refresh_token.startswith("mock_refresh_token_for_"):
            return {
                "access_token": "new_mock_access_token",
                "refresh_token": "new_mock_refresh_token"
            }
        else:
            raise ValueError("Invalid refresh token")
            
    mock.refresh_token.side_effect = mock_refresh_token
    
    # Set up logout
    async def mock_logout(tokens):
        return True
        
    mock.logout.side_effect = mock_logout
    
    return mock

# --- Tests ---

def test_login_success(client, mock_auth_service):
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
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"
    assert "expires_in" in data
    
    # Verify the mock was called correctly
    mock_auth_service.authenticate_user.assert_called_once_with(
        "testuser", "testpassword"
    )
    
    # Check that the cookies were set
    assert "access_token" in response.cookies
    assert "refresh_token" in response.cookies

def test_login_invalid_credentials(client, mock_auth_service):
    """Test login with invalid credentials."""
    # Arrange
    login_data = {
        "username": "wrong_user",
        "password": "wrong_password",
        "remember_me": False
    }
    
    # Act
    response = client.post("/api/v1/auth/login", json=login_data)
    
    # Assert
    assert response.status_code == 401
    data = response.json()
    assert "detail" in data
    assert data["detail"] == "Invalid credentials"
    
    # Verify the mock was called correctly
    mock_auth_service.authenticate_user.assert_called_once_with(
        "wrong_user", "wrong_password"
    )
    
    # Check that no cookies were set
    assert "access_token" not in response.cookies
    assert "refresh_token" not in response.cookies

def test_login_inactive_account(client, mock_auth_service):
    """Test login with inactive account."""
    # Arrange
    login_data = {
        "username": "inactive",
        "password": "testpassword",
        "remember_me": False
    }
    
    # Act
    response = client.post("/api/v1/auth/login", json=login_data)
    
    # Assert
    assert response.status_code == 401
    data = response.json()
    assert "detail" in data
    assert data["detail"] == "Account is inactive"
    
    # Verify the mock was called correctly
    mock_auth_service.authenticate_user.assert_called_once_with(
        "inactive", "testpassword"
    )
    
    # Check that no cookies were set
    assert "access_token" not in response.cookies
    assert "refresh_token" not in response.cookies

def test_refresh_token_success(client, mock_auth_service):
    """Test successful token refresh."""
    # Arrange
    refresh_data = {
        "refresh_token": "mock_refresh_token_for_user123"
    }
    
    # Act
    response = client.post("/api/v1/auth/refresh", json=refresh_data)
    
    # Assert
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"
    assert "expires_in" in data
    
    # Verify the mock was called correctly
    mock_auth_service.refresh_token.assert_called_once_with(
        "mock_refresh_token_for_user123"
    )
    
    # Check that the cookies were set
    assert "access_token" in response.cookies
    assert "refresh_token" in response.cookies

def test_refresh_token_invalid(client, mock_auth_service):
    """Test refresh with invalid token."""
    # Arrange
    refresh_data = {
        "refresh_token": "invalid_token"
    }
    
    # Act
    response = client.post("/api/v1/auth/refresh", json=refresh_data)
    
    # Assert
    assert response.status_code == 401
    data = response.json()
    assert "detail" in data
    assert data["detail"] == "Invalid or expired refresh token"
    
    # Verify the mock was called correctly
    mock_auth_service.refresh_token.assert_called_once_with(
        "invalid_token"
    )
    
    # Check that no cookies were set
    assert "access_token" not in response.cookies
    assert "refresh_token" not in response.cookies

def test_refresh_token_missing(client):
    """Test refresh with missing token."""
    # Act
    response = client.post("/api/v1/auth/refresh", json={})
    
    # Assert
    assert response.status_code == 401
    data = response.json()
    assert "detail" in data
    assert data["detail"] == "Refresh token required"
    
    # Check that no cookies were set
    assert "access_token" not in response.cookies
    assert "refresh_token" not in response.cookies

def test_logout(client, mock_auth_service):
    """Test logout."""
    # Arrange - Set a token in cookies
    client.cookies.set("access_token", "mock_access_token", domain="testserver")
    client.cookies.set("refresh_token", "mock_refresh_token", domain="testserver")
    
    # Mock auth headers
    headers = {"Authorization": "Bearer mock_access_token"}
    
    # Act
    response = client.post("/api/v1/auth/logout", headers=headers)
    
    # Assert
    assert response.status_code == 204
    
    # Verify cookies were cleared
    assert response.cookies.get("access_token") is None or response.cookies.get("access_token").value == ""
    assert response.cookies.get("refresh_token") is None or response.cookies.get("refresh_token").value == ""
    
    # Verify the mock was called correctly
    mock_auth_service.logout.assert_called_once()

def test_session_info_authenticated(client):
    """Test session info with authentication."""
    # Arrange - Mock user data in the token
    mock_user_data = {
        "sub": "user123",
        "roles": ["provider"],
        "permissions": ["read:patients", "write:notes"],
        "exp": 1619900000
    }
    
    with patch("app.presentation.api.dependencies.auth.get_optional_user", return_value=mock_user_data):
        # Act
        response = client.get("/api/v1/auth/session-info")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["authenticated"] is True
        assert data["session_active"] is True
        assert data["user_id"] == "user123"
        assert data["roles"] == ["provider"]
        assert data["permissions"] == ["read:patients", "write:notes"]
        assert data["exp"] == 1619900000

def test_session_info_not_authenticated(client):
    """Test session info without authentication."""
    # Arrange - No user data in the token
    with patch("app.presentation.api.dependencies.auth.get_optional_user", return_value=None):
        # Act
        response = client.get("/api/v1/auth/session-info")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["authenticated"] is False
        assert data["session_active"] is False 