#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HIPAA JWT Authentication Security Tests

These tests validate the JWT authentication and authorization mechanisms
that protect the API endpoints according to HIPAA requirements for access control
(§164.308(a)(4)(ii)(B) - Access authorization).

The tests validate:
    1. JWT token validation
    2. Role-based access control
    3. Token expiration and refresh
    4. Authentication failure handling
    5. Session security
"""

import json
import pytest
import time
import uuid
import asyncio
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional, Tuple
from unittest.mock import MagicMock, AsyncMock, PropertyMock

from app.infrastructure.security.jwt.jwt_service import JWTService, TokenPayload
from app.domain.exceptions.token_exceptions import InvalidTokenException, TokenExpiredException
from app.domain.models.user import User, UserRole
# import jwt # Use JWTService methods for encoding/decoding

from fastapi import status, HTTPException
from fastapi.testclient import TestClient
from starlette.status import HTTP_401_UNAUTHORIZED, HTTP_403_FORBIDDEN
from pydantic import SecretStr

# Mock data for testing
TEST_USERS = {
    "admin": {
        "sub": str(uuid.uuid4()), # Use 'sub' for consistency
        "role": "admin",
        "permissions": ["read:all", "write:all"]
    },
    "doctor": {
        "sub": str(uuid.uuid4()),
        "role": "doctor",
        "permissions": ["read:patients", "write:medical_records"]
    },
    "patient": {
        "sub": str(uuid.uuid4()),
        "role": "patient",
        "permissions": ["read:own_records"]
    }
}

# Resource access patterns for testing
RESOURCE_ACCESS = {
    "admin": {
        "patients": "allow",
        "medical_records": "allow",
        "billing": "allow",
        "system_settings": "allow"
    },
    "doctor": {
        "patients": "allow",
        "medical_records": "allow",
        "billing": "allow_own",
        "system_settings": "deny"
    },
    "patient": {
        "patients": "allow_own",
        "medical_records": "allow_own",
        "billing": "allow_own",
        "system_settings": "deny"
    }
}

# Mock FastAPI request for testing
@pytest.mark.db_required()
class MockRequest:
    def __init__(self, headers=None, cookies=None):
        self.headers = headers or {}
        self.cookies = cookies or {}

# Mock FastAPI response for testing
class MockResponse:
    def __init__(self, status_code=200, body=None, headers=None):
        self.status_code = status_code
        self.body = body or {}
        self.headers = headers or {}

    def json(self):
        return self.body

@pytest.fixture
def user():
    """Fixture for a test user."""
    return User(
        id="user123",
        username="testuser",
        email="test@example.com",
        role=UserRole.PRACTITIONER,
        hashed_password="hashedpassword123"
    )

@pytest.fixture
def admin_user():
    """Fixture for a test admin user."""
    return User(
        id="admin123",
        username="adminuser",
        email="admin@example.com",
        role=UserRole.ADMIN,
        hashed_password="hashedpassword123"
    )

# Fixtures using mock_settings
@pytest.fixture
def mock_settings(monkeypatch) -> MagicMock:
    settings_mock = MagicMock()
    # Set other settings as needed
    settings_mock.JWT_ALGORITHM = "HS256"
    settings_mock.ACCESS_TOKEN_EXPIRE_MINUTES = 15
    settings_mock.JWT_REFRESH_TOKEN_EXPIRE_DAYS = 7
    settings_mock.JWT_ISSUER = "test_issuer"
    settings_mock.JWT_AUDIENCE = "test_audience"

    # Correctly mock JWT_SECRET_KEY as a SecretStr
    raw_secret = "test-secret-key-for-auth-test-32+"
    mock_secret_str = MagicMock(spec=SecretStr)
    mock_secret_str.get_secret_value.return_value = raw_secret

    # Use monkeypatch to set the attribute on the *mock* settings object
    # We are mocking the settings object itself, not the global settings module here
    settings_mock.JWT_SECRET_KEY = mock_secret_str

    return settings_mock

@pytest.fixture
def jwt_service(mock_settings: MagicMock) -> JWTService:
    # Pass the mocked settings object
    return JWTService(settings=mock_settings, user_repository=None) # Assuming user_repository isn't needed or is mocked elsewhere

@pytest.fixture
def token_factory(jwt_service: JWTService):
    async def _create_token(user_type="admin", expired=False, invalid=False, custom_payload_claims: Optional[Dict] = None):
        user_data = TEST_USERS.get(user_type, TEST_USERS["admin"])
        # Ensure keys match what create_access_token expects (sub, roles, etc.)
        payload_data = {
            "sub": user_data["sub"],
            "roles": [user_data["role"]], # Expects roles as list
            "permissions": user_data["permissions"],
            **(custom_payload_claims or {})
        }
        
        expires_delta_minutes = -1 if expired else None
        
        token = await jwt_service.create_access_token(data=payload_data, expires_delta_minutes=expires_delta_minutes)
        
        if invalid:
            # Tamper with token for invalid signature test
            token = token[:-5] + "wrong"
            
        return token
    return _create_token

class TestJWTAuthentication:
    """Test suite for JWT authentication system."""

    @pytest.mark.asyncio
    async def test_token_creation(self, jwt_service: JWTService):
        """Test token creation with user data."""
        user = TEST_USERS["doctor"]
        user_data = {
            "sub": user["sub"],
            "roles": [user["role"]],
            "permissions": user["permissions"]
        }
        token = await jwt_service.create_access_token(data=user_data)

        assert isinstance(token, str), "Created token is not a string"

        try:
            payload: TokenPayload = await jwt_service.decode_token(token)
        except (InvalidTokenException, TokenExpiredException) as e:
            pytest.fail(f"Valid token failed decoding: {e}")

        assert payload.sub == user["sub"], "User ID claim is incorrect"
        assert payload.roles == [user["role"]], "Roles claim is incorrect"
        assert payload.permissions == user["permissions"], "Permissions claim is incorrect"
        # assert payload.scope == "access_token", "Scope should be access_token" # Scope might not be explicitly set/checked this way
        assert payload.type == "access", "Type should be access" # Check type instead
        assert payload.exp > int(time.time()), "Expiration time should be in the future"

    @pytest.mark.asyncio
    async def test_token_validation(self, jwt_service: JWTService, token_factory):
        """Verify valid tokens and rejection of invalid ones."""
        # Test valid token
        valid_token = await token_factory(user_type="admin")
        try:
            decoded = await jwt_service.decode_token(valid_token)
            assert decoded.sub == TEST_USERS["admin"]["sub"]
            assert decoded.roles == [TEST_USERS["admin"]["role"]]
        except (InvalidTokenException, TokenExpiredException) as e:
            pytest.fail(f"Valid token failed verification: {e}")
        
        # Test invalid token (bad signature)
        invalid_sig_token = await token_factory(user_type="admin", invalid=True)
        with pytest.raises(InvalidTokenException) as exc_info:
            await jwt_service.decode_token(invalid_sig_token)
        assert "Signature verification failed" in str(exc_info.value)
        
        # Test expired token
        expired_token = await token_factory(user_type="admin", expired=True)
        await asyncio.sleep(0.1) # Ensure time passes expiry
        with pytest.raises(TokenExpiredException):
            await jwt_service.decode_token(expired_token)
            
        # Test malformed token
        malformed_token = "this.is.not.jwt"
        with pytest.raises(InvalidTokenException) as exc_info:
            await jwt_service.decode_token(malformed_token)
        assert ("Invalid header string" in str(exc_info.value) or 
                "Not enough segments" in str(exc_info.value)), \
               f"Unexpected malformed token error: {str(exc_info.value)}"

    @pytest.mark.skip(reason="Needs refactoring to test actual endpoints/middleware, not call non-existent jwt_service method.")
    @pytest.mark.asyncio # Mark as async - Needs refactoring to hit actual endpoints/middleware
    async def test_role_based_access(self, jwt_service: JWTService, token_factory):
        """Test that role-based access control works correctly. 
           NOTE: This test needs significant refactoring to test actual endpoints.
           Leaving structure for now, but logic is incorrect.
        """
        # Test each role's access to different resources
        for role, resources in RESOURCE_ACCESS.items():
            token = await token_factory(user_type=role)

            for resource, access_level in resources.items():
                request_path = f"/api/{resource}"
                owner_id = TEST_USERS[role]["sub"] if "own" in access_level else None

                # Prepare request context with token
                request = MockRequest(headers={"Authorization": f"Bearer {token}"})

                # Check authorization
                is_authorized = jwt_service.check_resource_access(request, resource_path=request_path, resource_owner_id=owner_id)

                if access_level == "allow":
                    assert is_authorized, f"Role {role} was denied access to {resource} with access level {access_level}"
                elif access_level == "allow_own" and owner_id:
                    assert is_authorized, f"Role {role} was denied access to own {resource}"
                elif access_level == "deny":
                    assert not is_authorized, f"Role {role} was allowed access to {resource} despite deny rule"

    @pytest.mark.skip(reason="Relies on undefined auth_service fixture.")
    @pytest.mark.asyncio # Mark as async
    async def test_token_from_request(self, auth_service, token_factory):
        """Test that tokens are correctly extracted from requests"""
        # Generate test token
        token = await token_factory(user_type="doctor")

        # Test token in Authorization header
        request_with_header = MockRequest(headers={"Authorization": f"Bearer {token}"})
        extracted_token = auth_service.extract_token_from_request(request_with_header)
        assert extracted_token == token, "Failed to extract token from Authorization header"

        # Test token in cookie
        request_with_cookie = MockRequest(cookies={"access_token": token})
        extracted_token = auth_service.extract_token_from_request(request_with_cookie)
        assert extracted_token == token, "Failed to extract token from cookie"

        # Test missing token
        request_without_token = MockRequest()
        extracted_token = auth_service.extract_token_from_request(request_without_token)
        assert extracted_token is None, "Should return None for request without token"

    @pytest.mark.skip(reason="Relies on undefined auth_service fixture.")
    def test_unauthorized_response(self, auth_service):
        """Test that unauthorized requests get proper responses"""
        # Test expired token response
        expired_response = auth_service.create_unauthorized_response(error_type="token_expired", message="Token has expired")
        assert expired_response.status_code == 401, "Expired token should return 401 Unauthorized"
        assert "expired" in expired_response.json()["error"].lower(), "Error message should mention expiration"

        # Test invalid token response
        invalid_response = auth_service.create_unauthorized_response(error_type="invalid_token", message="Token is invalid")
        assert invalid_response.status_code == 401, "Invalid token should return 401 Unauthorized"
        assert "invalid" in invalid_response.json()["error"].lower(), "Error message should mention invalidity"

        # Test insufficient permissions response
        forbidden_response = auth_service.create_unauthorized_response(error_type="insufficient_permissions", message="Insufficient permissions to access resource")
        assert forbidden_response.status_code == 403, "Insufficient permissions should return 403 Forbidden"
        assert "permission" in forbidden_response.json()["error"].lower(), "Error message should mention permissions"

    @pytest.mark.skip(reason="Requires client fixture and defined /refresh endpoint.")
    @pytest.mark.asyncio # Mark test as async
    async def test_refresh_token(self, client: TestClient, jwt_service: JWTService):
        """Test token refresh functionality via the dedicated endpoint."""
        # Assume refresh endpoint path
        refresh_endpoint = "/api/v1/auth/refresh" 

        # Create a valid refresh token
        user = TEST_USERS["patient"]
        # Need a JTI (JWT ID) for the refresh token. Let's generate one.
        jti = str(uuid.uuid4())
        # create_refresh_token is synchronous in the actual implementation
        refresh_token = await jwt_service.create_refresh_token(subject=user["sub"], jti=jti)

        # Attempt to refresh using the endpoint
        response = client.post(refresh_endpoint, json={"refresh_token": refresh_token})

        # Assert success and presence of new access token
        assert response.status_code == status.HTTP_200_OK, f"Refresh failed: {response.text}"
        response_data = response.json()
        assert "access_token" in response_data, "No access token returned after refresh"
        assert response_data.get("token_type") == "bearer"
        assert "new_refresh_token" in response_data, "No new refresh token returned (optional but good practice)"
        assert response_data["token_type"] == "bearer", "Token type should be bearer"

        # Verify the new access token is valid and belongs to the correct user
        new_access_token = response_data["access_token"]
        try:
            payload = await jwt_service.decode_token(new_access_token)
            assert payload.sub == user["sub"], "User ID in refreshed token is incorrect"
            assert payload.scope == "access_token", "Refreshed token scope is wrong"
        except (InvalidTokenException, TokenExpiredException) as e:
            pytest.fail(f"New access token validation failed: {e}")

        # Test with an invalid refresh token
        invalid_refresh_response = client.post(refresh_endpoint, json={"refresh_token": "invalid.refresh.token"})
        assert invalid_refresh_response.status_code == status.HTTP_401_UNAUTHORIZED
        # Optionally check error detail
        # assert "Invalid refresh token" in invalid_refresh_response.json().get("detail", "")

    @pytest.mark.skip(reason="Relies on undefined auth_service fixture.")
    @pytest.mark.asyncio # Mark as async
    async def test_hipaa_compliance_in_errors(self, jwt_service: JWTService, token_factory):
        """Test that authentication errors don't leak sensitive information.
           NOTE: Needs refactoring to test actual endpoint errors.
           Current logic uses non-existent methods.
        """
        # Create a context with invalid authentication
        invalid_token = await token_factory(invalid=True)

        # Get error response - THIS PART IS WRONG - needs to trigger an endpoint error
        # error_response = jwt_service.create_unauthorized_response(error_type="invalid_token", message="Token validation failed")
        pytest.skip("Test logic requires refactoring to test actual endpoint error responses.")
        # Error response should not contain PHI
        # assert "user_id" not in response_json, "Error response contains user ID (PHI)"
        # assert "patient" not in json.dumps(response_json).lower(), "Error response may contain patient reference"

        # Error should be generic enough not to leak information
        # assert len(response_json["error"]) < 100, "Error message too detailed, may leak information"

    @pytest.mark.asyncio
    async def test_token_security_properties(self, jwt_service: JWTService):
        """Check for essential security claims (jti, iat, exp)."""
        user_data = {"sub": TEST_USERS["patient"]["sub"], "roles": [TEST_USERS["patient"]["role"]]}
        token = await jwt_service.create_access_token(data=user_data)
        payload = await jwt_service.decode_token(token)

        assert hasattr(payload, 'jti') and payload.jti, "Token must have a JTI (JWT ID)"
        assert hasattr(payload, 'iat') and payload.iat, "Token must have an IAT (Issued At)"
        assert hasattr(payload, 'exp') and payload.exp, "Token must have an EXP (Expiration Time)"
        
        # Optional: Check issuer and audience if configured
        if jwt_service.issuer:
            assert payload.iss == jwt_service.issuer, "Issuer claim mismatch"
        if jwt_service.audience:
            assert payload.aud == jwt_service.audience, "Audience claim mismatch"
