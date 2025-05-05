"""
Test suite for auth endpoints using async httpx client.

These tests verify the functionality of the authentication endpoints
using direct API calls to ensure proper behavior with async handling.
"""
from unittest.mock import AsyncMock

import pytest
from httpx import AsyncClient

# --- Tests --- 

@pytest.mark.asyncio
async def test_login_success(
    client: AsyncClient, mock_auth_service: AsyncMock
) -> None:
    """Test successful login using async client."""
    # Arrange
    login_data = {
        "username": "testuser",
        "password": "testpassword",
        "remember_me": False
    }
    
    # Act
    response = await client.post("/api/v1/auth/login", json=login_data)
    
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

@pytest.mark.asyncio
async def test_login_invalid_credentials(
    client: AsyncClient, mock_auth_service: AsyncMock
) -> None:
    """Test login with invalid credentials using async client."""
    # Arrange
    login_data = {
        "username": "wrong_user",
        "password": "wrong_password",
        "remember_me": False
    }
    
    # Act
    response = await client.post("/api/v1/auth/login", json=login_data)
    
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

@pytest.mark.asyncio
async def test_login_inactive_account(
    client: AsyncClient, mock_auth_service: AsyncMock
) -> None:
    """Test login with inactive account using async client."""
    # Arrange
    login_data = {
        "username": "inactive",
        "password": "testpassword",
        "remember_me": False
    }
    
    # Act
    response = await client.post("/api/v1/auth/login", json=login_data)
    
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

@pytest.mark.asyncio
async def test_refresh_token_success(
    client: AsyncClient, mock_auth_service: AsyncMock
) -> None:
    """Test successful token refresh using async client."""
    # Arrange
    refresh_data = {
        "refresh_token": "mock_refresh_token_for_user123"
    }
    
    # Act
    response = await client.post("/api/v1/auth/refresh", json=refresh_data)
    
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

@pytest.mark.asyncio
async def test_refresh_token_invalid(
    client: AsyncClient, mock_auth_service: AsyncMock
) -> None:
    """Test refresh with invalid token using async client."""
    # Arrange
    refresh_data = {
        "refresh_token": "invalid_token"
    }
    
    # Act
    response = await client.post("/api/v1/auth/refresh", json=refresh_data)
    
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

@pytest.mark.asyncio
async def test_refresh_token_missing(client: AsyncClient) -> None:
    """Test refresh with missing token using async client."""
    # Arrange
    refresh_data = {}
    
    # Act
    response = await client.post("/api/v1/auth/refresh", json=refresh_data)
    
    # Assert
    assert response.status_code == 422

@pytest.mark.asyncio
async def test_logout(
    client: AsyncClient, mock_auth_service: AsyncMock
) -> None:
    """Test logout using async client."""
    # First, perform login to get tokens.
    login_data = {"username": "testuser", "password": "testpassword"}
    login_response = await client.post("/api/v1/auth/login", json=login_data)
    # Ensure login succeeded
    assert login_response.status_code == 200 
    
    # Act - Use the client instance which now has cookies from login
    response = await client.post("/api/v1/auth/logout")
    
    # Assert
    assert response.status_code == 204 # No content on successful logout
    
    # Verify cookies were cleared
    access_cookie = response.cookies.get("access_token")
    refresh_cookie = response.cookies.get("refresh_token")
    assert access_cookie is None or access_cookie.value == ""
    assert refresh_cookie is None or refresh_cookie.value == ""
    
    # Verify the mock was called correctly
    mock_auth_service.logout.assert_called_once()

@pytest.mark.asyncio
async def test_session_info_authenticated(client: AsyncClient) -> None:
    """Test session info with authentication using async client."""
    # Arrange
    # Perform login to establish authenticated session
    login_data = {"username": "testuser", "password": "testpassword"}
    login_response = await client.post(
        "/api/v1/auth/login", 
        json=login_data
    )
    assert login_response.status_code == 200
    
    # Act
    response = await client.get("/api/v1/auth/session-info")
    
    # Assert
    assert response.status_code == 200
    data = response.json()
    assert data["authenticated"] is True
    assert data["session_active"] is True
    assert data["user_id"] == "user123"
    assert data["roles"] == ["provider"]
    # Reformat long assert lines
    assert data["permissions"] == [
        "read:patients", 
        "write:notes",
    ]
    assert data["exp"] == 1619900000

@pytest.mark.asyncio
async def test_session_info_not_authenticated(client: AsyncClient) -> None:
    """Test session info without authentication using async client."""
    # Act
    response = await client.get("/api/v1/auth/session-info")
    
    # Assert
    assert response.status_code == 200
    data = response.json()
    assert data["authenticated"] is False
    assert data["session_active"] is False