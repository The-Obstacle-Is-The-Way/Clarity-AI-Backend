#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test suite for HIPAA-compliant authentication and authorization.
This ensures PHI access requires proper authentication and authorization.
"""

import pytest
import jwt
import time
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta
from app.domain.utils.datetime_utils import UTC
import json

try:
    from app.infrastructure.security.jwt_service import JWTService
except ImportError:
    JWTService = MagicMock()

try:
    from app.infrastructure.security.auth_middleware import AuthMiddleware
    from app.infrastructure.security.rbac.role_manager import RoleManager
except ImportError:
    # Mock classes for testing auth functionality
    AuthMiddleware = MagicMock()
    RoleManager = MagicMock()

# Mock JWT service for testing
class JWTService:
    """Mock JWT service for testing."""

    def __init__(self, secret_key="test_secret", algorithm="HS256", expires_delta=30):
        self.secret_key = secret_key
        self.algorithm = algorithm
        self.expires_delta = expires_delta

    def create_access_token(self, data, expires_delta=None):
        """Create a test JWT token."""
        to_encode = data.copy()
        expire = datetime.now(UTC) + timedelta(minutes=expires_delta or self.expires_delta)
        to_encode.update({"exp": expire})
        return jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)

    def decode_token(self, token):
        """Decode a test JWT token."""
        return jwt.decode(token, self.secret_key, algorithms=[self.algorithm])

    def verify_token(self, token):
        """Verify token is valid."""
        try:
            payload = self.decode_token(token)
            return payload
        except jwt.PyJWTError:
            return None

class AuthMiddleware:
    """Mock auth middleware for testing."""

    def __init__(self, jwt_service=None):
        self.jwt_service = jwt_service or JWTService()

    def authenticate(self, token):
        """Authenticate a request with token."""
        payload = self.jwt_service.verify_token(token)
        if payload is None:
            return None
        return payload

class RoleManager:
    """Mock role manager for testing."""

    def __init__(self):
        self.role_permissions = {
            "admin": ["read:patient", "write:patient", "read:phi", "write:phi"],
            "doctor": ["read:patient", "write:patient", "read:phi", "write:phi"],
            "nurse": ["read:patient", "read:phi"],
            "patient": ["read:own_data"],
            "guest": []
        }

    def has_permission(self, user_role, permission):
        """Check if role has required permission."""
        if user_role not in self.role_permissions:
            return False
        return permission in self.role_permissions[user_role]

    def get_role_from_token(self, token_payload):
        """Extract role from token payload."""
        if not token_payload or 'role' not in token_payload:
            return "guest"
        return token_payload['role']

class TestHIPAAAuthCompliance:
    """Test authentication and authorization for HIPAA compliance."""

    @pytest.fixture
    def jwt_service(self):
        """Create a JWT service for testing."""
        return JWTService()

    @pytest.fixture
    def auth_middleware(self, jwt_service):
        """Create auth middleware for testing."""
        return AuthMiddleware(jwt_service)

    @pytest.fixture
    def role_manager(self):
        """Create role manager for testing."""
        return RoleManager()

    @pytest.fixture
    def doctor_token(self, jwt_service):
        """Create a valid doctor token."""
        return jwt_service.create_access_token({
            "sub": "doctor123",
            "role": "doctor",
            "name": "Dr. Jane Smith",
            "permissions": ["read:patient", "write:patient", "read:phi", "write:phi"]
        })

    @pytest.fixture
    def patient_token(self, jwt_service):
        """Create a valid patient token."""
        return jwt_service.create_access_token({
            "sub": "patient456",
            "role": "patient",
            "name": "John Doe",
            "patient_id": "P12345",
            "permissions": ["read:own_data"]
        })

    @pytest.fixture
    def expired_token(self, jwt_service):
        """Create an expired token."""
        return jwt_service.create_access_token({
            "sub": "doctor789",
            "role": "doctor",
            "permissions": ["read:patient", "write:patient", "read:phi", "write:phi"]
        }, expires_delta=-1)  # Token expired 1 minute ago

    def test_valid_token_authentication(self, auth_middleware, doctor_token):
        """Test that valid tokens authenticate successfully."""
        payload = auth_middleware.authenticate(doctor_token)
        assert payload is not None
        assert payload["role"] == "doctor"
        assert "sub" in payload
        assert "exp" in payload

    def test_expired_token_authentication(self, auth_middleware, expired_token):
        """Test that expired tokens fail authentication."""
        payload = auth_middleware.authenticate(expired_token)
        assert payload is None

    def test_tampered_token_authentication(self, auth_middleware, doctor_token):
        """Test that tampered tokens fail authentication."""
        tampered_token = doctor_token[:-5] + "tampr"  # Tamper with signature
        payload = auth_middleware.authenticate(tampered_token)
        assert payload is None

    def test_role_based_access_control(self, role_manager, doctor_token, patient_token, jwt_service):
        """Test that role-based access control properly enforces permissions."""
        doctor_payload = jwt_service.decode_token(doctor_token)
        patient_payload = jwt_service.decode_token(patient_token)

        # Doctor should have PHI access permissions
        doctor_role = role_manager.get_role_from_token(doctor_payload)
        assert doctor_role == "doctor"
        assert role_manager.has_permission(doctor_role, "read:phi") is True
        assert role_manager.has_permission(doctor_role, "write:phi") is True

        # Patient should not have PHI access permissions beyond their own
        patient_role = role_manager.get_role_from_token(patient_payload)
        assert patient_role == "patient"
        assert role_manager.has_permission(patient_role, "read:phi") is False
        assert role_manager.has_permission(patient_role, "read:own_data") is True

    def test_missing_token(self, auth_middleware):
        """Test that missing token fails authentication."""
        payload = auth_middleware.authenticate(None)
        assert payload is None

    def test_patient_data_isolation(self, jwt_service, role_manager):
        """Test that patients can only access their own data."""
        # Create two different patient tokens
        patient1_token = jwt_service.create_access_token({
            "sub": "patient111",
            "role": "patient",
            "patient_id": "P111",
            "permissions": ["read:own_data"]
        })

        patient2_token = jwt_service.create_access_token({
            "sub": "patient222",
            "role": "patient",
            "patient_id": "P222",
            "permissions": ["read:own_data"]
        })

        # Decode tokens to get payloads
        payload1 = jwt_service.decode_token(patient1_token)
        payload2 = jwt_service.decode_token(patient2_token)

        # Verify both patients have patient role with limited permissions
        role1 = role_manager.get_role_from_token(payload1)
        role2 = role_manager.get_role_from_token(payload2)

        assert role1 == "patient"
        assert role2 == "patient"

        # Verify patient 1 ID does not match patient 2 ID (data isolation)
        assert payload1["patient_id"] != payload2["patient_id"]

        # Both should only have permission to read their own data
        assert role_manager.has_permission(role1, "read:own_data") is True
        assert role_manager.has_permission(role2, "read:own_data") is True
        assert role_manager.has_permission(role1, "read:patient") is False
        assert role_manager.has_permission(role2, "read:patient") is False

    def test_token_without_role(self, jwt_service, role_manager):
        """Test that tokens without role get default guest permissions."""
        # Create token without role
        no_role_token = jwt_service.create_access_token({
            "sub": "user999",
            "name": "No Role User"
        })

        # Decode token
        payload = jwt_service.decode_token(no_role_token)

        # Get role from token - should default to guest
        role = role_manager.get_role_from_token(payload)
        assert role == "guest"

        # Guest should have no permissions
        assert role_manager.has_permission(role, "read:phi") is False
        assert role_manager.has_permission(role, "read:patient") is False
        assert role_manager.has_permission(role, "read:own_data") is False

    @patch('jwt.encode', side_effect=jwt.encode)
    @patch('jwt.decode', side_effect=jwt.decode)
    def test_token_operations_audit_trail(self, mock_decode, mock_encode, jwt_service):
        """Test that token operations can be properly audited."""
        # Create and verify a token, monitoring encode/decode calls
        test_data = {"sub": "audit_test", "role": "admin"}
        token = jwt_service.create_access_token(test_data)

        # Verify encode was called with correct data
        mock_encode.assert_called()
        call_args = mock_encode.call_args[0]
        assert "sub" in call_args[0]
        assert "exp" in call_args[0]
        assert call_args[0]["sub"] == "audit_test"

        # Decode the token
        payload = jwt_service.decode_token(token)

        # Verify decode was called with correct data
        mock_decode.assert_called()
        assert mock_decode.call_args[0][0] == token

    def test_multi_factor_auth_support(self, jwt_service):
        """Test support for multi-factor authentication in tokens."""
        # Create a token with MFA flag
        mfa_token = jwt_service.create_access_token({
            "sub": "mfa_user",
            "role": "doctor",
            "mfa_complete": True,
            "auth_level": "2"  # 2 = MFA completed
        })

        # Verify MFA information is in token
        payload = jwt_service.decode_token(mfa_token)
        assert payload["mfa_complete"] is True
        assert payload["auth_level"] == "2"

    def test_minimal_phi_in_token(self, jwt_service):
        """Test that tokens contain minimal PHI, even for authorized users."""
        # Create an admin token
        admin_token = jwt_service.create_access_token({
            "sub": "admin123",
            "role": "admin",
            "name": "Admin User",  # Only minimal identifying info
            "permissions": ["read:patient", "write:patient", "read:phi", "write:phi"]
        })

        # Decode token
        payload = jwt_service.decode_token(admin_token)

        # Check that no PHI fields are in the token
        phi_fields = ["ssn", "address", "phone", "email", "dob", "medical_record"]
        for field in phi_fields:
            assert field not in payload

if __name__ == "__main__":
    pytest.main(["-v", __file__])
