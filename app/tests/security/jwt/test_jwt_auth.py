#!/usr/bin/env python3
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

import asyncio
import time
import uuid
from unittest.mock import MagicMock
from datetime import timedelta, datetime, timezone
import jwt
from jose import jwt as jose_jwt

import pytest
from app.tests.utils.asyncio_helpers import run_with_timeout

# import jwt # Use JWTService methods for encoding/decoding
from fastapi import status, FastAPI, Depends
from fastapi.testclient import TestClient
from pydantic import SecretStr, BaseModel

from app.domain.exceptions.token_exceptions import InvalidTokenException, TokenExpiredException
from app.domain.models.user import User, UserRole
from app.infrastructure.security.jwt.jwt_service import JWTService, TokenPayload, TokenType
from app.infrastructure.security.jwt.jwt_service import get_jwt_service

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
def jwt_service(mock_settings: MagicMock, monkeypatch) -> JWTService:
    # Pass the mocked settings object
    # return JWTService(settings=mock_settings, user_repository=None) # OLD way

    # Configure environment variables for get_jwt_service() using values from mock_settings
    monkeypatch.setenv("JWT_SECRET_KEY", mock_settings.JWT_SECRET_KEY.get_secret_value())
    monkeypatch.setenv("JWT_ALGORITHM", mock_settings.JWT_ALGORITHM)
    monkeypatch.setenv("ACCESS_TOKEN_EXPIRE_MINUTES", str(mock_settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    monkeypatch.setenv("REFRESH_TOKEN_EXPIRE_DAYS", str(mock_settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS))

    # Import the factory locally to ensure it picks up monkeypatched env vars if needed by its imports
    return get_jwt_service() # This should now return a fully implemented JWTService instance

@pytest.fixture
def token_factory(jwt_service: JWTService):
    async def _create_token(user_type="admin", expired=False, invalid=False, custom_payload_claims: dict | None = None, token_type=TokenType.ACCESS):
        user_data = TEST_USERS.get(user_type, TEST_USERS["admin"])
        payload_data = {
            "sub": user_data["sub"],
            "roles": [user_data["role"]], 
            "permissions": user_data["permissions"],
            **(custom_payload_claims or {})
        }
        
        expires_delta_arg = None
        if expired:
            expires_delta_arg = timedelta(minutes=-1) # Expired in the past
        # If a specific positive duration is needed, the caller can set it via custom_payload_claims or another param
        
        # Create token based on token type
        if token_type == TokenType.REFRESH:
            token = jwt_service.create_refresh_token(data=payload_data, expires_delta=expires_delta_arg)
        else:
            token = jwt_service.create_access_token(data=payload_data, expires_delta=expires_delta_arg)
        
        if invalid:
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
        token = jwt_service.create_access_token(data=user_data)

        assert isinstance(token, str), "Created token is not a string"

        try:
            payload: TokenPayload = jwt_service.decode_token(token)
        except (InvalidTokenException, TokenExpiredException) as e:
            pytest.fail(f"Valid token failed decoding: {e}")

        assert payload.sub == user["sub"], "User ID claim is incorrect"
        assert payload.roles == [user["role"]], "Roles claim is incorrect"
        assert payload.permissions == user["permissions"], "Permissions claim is incorrect"
        # assert payload.scope == "access_token", "Scope should be access_token" # Scope might not be explicitly set/checked this way
        assert payload.type == "access", "Type should be access" # Check type instead
        assert payload.exp > int(time.time()), "Expiration time should be in the future"

    @pytest.mark.asyncio
    async def test_token_validation(self, jwt_service: JWTService, token_factory, monkeypatch):
        """Verify valid tokens and rejection of invalid ones."""
        # Test valid token
        valid_token = await token_factory(user_type="admin")
        try:
            decoded = jwt_service.decode_token(valid_token)
            assert decoded.sub == TEST_USERS["admin"]["sub"]
            assert decoded.roles == [TEST_USERS["admin"]["role"]]
        except (InvalidTokenException, TokenExpiredException) as e:
            pytest.fail(f"Valid token failed verification: {e}")
        
        # Test invalid token (bad signature)
        invalid_sig_token = await token_factory(user_type="admin", invalid=True)
        with pytest.raises(InvalidTokenException) as exc_info:
            jwt_service.decode_token(invalid_sig_token)
        assert "Signature verification failed" in str(exc_info.value)
        
        # Create an explicitly expired token - avoid the special testing logic
        # 1. Create a token with a fixed expiration time in the past
        user_data = {
            "sub": TEST_USERS["admin"]["sub"],
            "roles": [TEST_USERS["admin"]["role"]],
            "permissions": TEST_USERS["admin"]["permissions"],
            "exp": int((datetime.now(timezone.utc) - timedelta(minutes=5)).timestamp()),  # 5 minutes ago
            "iat": int((datetime.now(timezone.utc) - timedelta(minutes=10)).timestamp()), # 10 minutes ago (to ensure iat < exp)
            "jti": str(uuid.uuid4()),
            "type": "access"
        }
        
        # Directly encode the token with explicit claims, bypassing the service's methods
        expired_token = jwt.encode(
            user_data,
            jwt_service.secret_key,
            algorithm=jwt_service.algorithm
        )
        
        # The token should be rejected as expired
        with pytest.raises(TokenExpiredException):
            jwt_service.decode_token(expired_token)
        
        # Test malformed token
        malformed_token = "this.is.not.jwt"
        with pytest.raises(InvalidTokenException) as exc_info:
            jwt_service.decode_token(malformed_token)
        assert ("Invalid header string" in str(exc_info.value) or 
                "Not enough segments" in str(exc_info.value)), \
               f"Unexpected malformed token error: {exc_info.value!s}"

    @pytest.mark.asyncio # Mark as async - Needs refactoring to hit actual endpoints/middleware
    async def test_role_based_access(self, jwt_service: JWTService, token_factory):
        """Test that role-based access control works correctly. 
           Now tests against the implemented check_resource_access method.
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

    @pytest.mark.asyncio
    async def test_token_from_request(self, jwt_service: JWTService, token_factory):
        """Test that tokens are correctly extracted from requests"""
        # Generate test token
        token = await token_factory(user_type="doctor")

        # Test token in Authorization header
        request_with_header = MockRequest(headers={"Authorization": f"Bearer {token}"})
        extracted_token = jwt_service.extract_token_from_request(request_with_header)
        assert extracted_token == token, "Failed to extract token from Authorization header"

        # Test token in cookie
        request_with_cookie = MockRequest(cookies={"access_token": token})
        extracted_token = jwt_service.extract_token_from_request(request_with_cookie)
        assert extracted_token == token, "Failed to extract token from cookie"

        # Test missing token
        request_without_token = MockRequest()
        extracted_token = jwt_service.extract_token_from_request(request_without_token)
        assert extracted_token is None, "Should return None for request without token"

    def test_unauthorized_response(self, jwt_service: JWTService):
        """Test that unauthorized requests get proper responses"""
        # Test expired token response
        expired_response = jwt_service.create_unauthorized_response(error_type="token_expired", message="Token has expired")
        assert expired_response["status_code"] == 401, "Expired token should return 401 Unauthorized"
        assert "expired" in expired_response["body"]["error"].lower(), "Error message should mention expiration"

        # Test invalid token response
        invalid_response = jwt_service.create_unauthorized_response(error_type="invalid_token", message="Token is invalid")
        assert invalid_response["status_code"] == 401, "Invalid token should return 401 Unauthorized"
        assert "invalid" in invalid_response["body"]["error"].lower(), "Error message should mention invalidity"

        # Test insufficient permissions response
        forbidden_response = jwt_service.create_unauthorized_response(error_type="insufficient_permissions", message="Insufficient permissions to access resource")
        assert forbidden_response["status_code"] == 403, "Insufficient permissions should return 403 Forbidden"
        assert "permission" in forbidden_response["body"]["error"].lower(), "Error message should mention permissions"

    @pytest.mark.asyncio
    async def test_refresh_token(self, jwt_service: JWTService, client: TestClient, token_factory):
        """Test refresh token functionality.
           Now updated to work with our test client and verify_refresh_token implementation.
        """
        # Create a valid refresh token for our test
        token = await token_factory(user_type="patient", token_type=TokenType.REFRESH)
        
        # Send the refresh token to our endpoint
        response = client.post("/api/v1/auth/refresh", json={"refresh_token": token})
        
        # Check that we got a successful response
        assert response.status_code == 200, f"Refresh failed: {response.text}"
        
        # Parse the response
        data = response.json()
        
        # Verify we got both tokens
        assert "access_token" in data, "No access token in response"
        assert "refresh_token" in data, "No refresh token in response"
        assert data["token_type"] == "bearer", "Incorrect token type"
        
        # Verify the new access token is valid
        new_token = data["access_token"]
        try:
            payload = jwt_service.decode_token(new_token)
            assert payload.sub == TEST_USERS["patient"]["sub"], "User ID in token payload is wrong"
        except Exception as e:
            pytest.fail(f"Failed to validate the new access token: {str(e)}")
            
        # Test with an invalid token 
        response = client.post("/api/v1/auth/refresh", json={"refresh_token": "invalid.token.string"})
        assert response.status_code == 401 or response.json().get("status_code") == 401, "Invalid token should be rejected"

    @pytest.mark.asyncio
    async def test_hipaa_compliance_in_errors(self, jwt_service: JWTService, token_factory):
        """Test that authentication errors don't leak sensitive information."""
        # Get invalid token
        invalid_token = await token_factory(invalid=True)
        
        # Test with UUID in message (should be redacted)
        test_uuid = "550e8400-e29b-41d4-a716-446655440000"
        message_with_uuid = f"Failed to authenticate user with ID {test_uuid}"
        response = jwt_service.create_unauthorized_response(
            error_type="invalid_token", 
            message=message_with_uuid
        )
        
        # Check that the UUID is redacted in the response
        assert test_uuid not in response["body"]["message"], "UUID should be redacted in error message"
        assert "[REDACTED]" in response["body"]["message"], "UUID should be replaced with [REDACTED]"
        
        # Test with email in message (should be redacted)
        test_email = "patient@example.com"
        message_with_email = f"Cannot identify user with email {test_email}"
        response = jwt_service.create_unauthorized_response(
            error_type="invalid_token", 
            message=message_with_email
        )
        
        # Check that the email is redacted in the response
        assert test_email not in response["body"]["message"], "Email should be redacted in error message"
        assert "[REDACTED]" in response["body"]["message"], "Email should be replaced with [REDACTED]"
        
        # Test with patient reference in message (should be redacted)
        message_with_patient = "Patient data access denied for this token"
        response = jwt_service.create_unauthorized_response(
            error_type="insufficient_permissions", 
            message=message_with_patient
        )
        
        # Check that "patient" is redacted
        assert "patient" not in response["body"]["message"].lower(), "Word 'patient' should be redacted"
        assert "[REDACTED]" in response["body"]["message"], "'patient' should be replaced with [REDACTED]"
        
        # Test message length (should be limited)
        long_message = "Error " * 50  # A very long message
        response = jwt_service.create_unauthorized_response(
            error_type="invalid_token", 
            message=long_message
        )
        
        # Check that the message is truncated
        assert len(response["body"]["message"]) <= 100, "Error message should be limited to 100 characters"
        assert "..." in response["body"]["message"], "Truncated message should end with ..."

    @pytest.mark.asyncio
    async def test_token_security_properties(self, jwt_service: JWTService):
        """Check for essential security claims (jti, iat, exp)."""
        user_data = {"sub": TEST_USERS["patient"]["sub"], "roles": [TEST_USERS["patient"]["role"]]}
        token = jwt_service.create_access_token(data=user_data)
        payload = jwt_service.decode_token(token)

        assert hasattr(payload, 'jti') and payload.jti, "Token must have a JTI (JWT ID)"
        assert hasattr(payload, 'iat') and payload.iat, "Token must have an IAT (Issued At)"
        assert hasattr(payload, 'exp') and payload.exp, "Token must have an EXP (Expiration Time)"
        
        # Optional: Check issuer and audience if configured
        if jwt_service.issuer:
            assert payload.iss == jwt_service.issuer, "Issuer claim mismatch"
        if jwt_service.audience:
            assert payload.aud == jwt_service.audience, "Audience claim mismatch"

# Test client for REST endpoint testing
@pytest.fixture
def test_app() -> FastAPI:
    """Create a minimal FastAPI application for testing."""
    from fastapi import FastAPI
    from pydantic import BaseModel
    
    app = FastAPI()
    
    # Define refresh token request model
    class RefreshTokenRequest(BaseModel):
        refresh_token: str
    
    # Define auth endpoints
    @app.post("/api/v1/auth/refresh")
    async def refresh_token_endpoint(request: RefreshTokenRequest, jwt_service=Depends(get_jwt_service)):
        """Refresh an access token."""
        try:
            # Validate the refresh token
            token_payload = jwt_service.verify_refresh_token(request.refresh_token)
            
            # Create a new access token
            access_token = jwt_service.create_access_token(data={
                "sub": token_payload.sub,
                "roles": token_payload.roles if hasattr(token_payload, "roles") else [],
            })
            
            # Create a new refresh token (optional)
            new_refresh_token = jwt_service.create_refresh_token(data={
                "sub": token_payload.sub,
                "roles": token_payload.roles if hasattr(token_payload, "roles") else [],
            })
            
            # Return response
            return {
                "access_token": access_token,
                "refresh_token": new_refresh_token,
                "token_type": "bearer"
            }
        except Exception as e:
            return {"status_code": 401, "detail": str(e)}
    
    return app

@pytest.fixture
def client(test_app: FastAPI) -> TestClient:
    """Create a test client for the application."""
    return TestClient(test_app)
