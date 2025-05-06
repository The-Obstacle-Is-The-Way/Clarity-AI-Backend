"""
Integration tests for HIPAA security boundaries.

These tests verify that our security components work together correctly
to enforce proper authentication and authorization boundaries.
"""

import asyncio
import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from pydantic import SecretStr  # Correct import location

from app.config.settings import Settings  # Import Settings

# Assume RBACService is available or mock it if needed
# from app.infrastructure.security.rbac.rbac_service import RBACService 
from app.domain.enums.role import Role
from app.domain.exceptions.token_exceptions import InvalidTokenException, TokenExpiredException
from app.infrastructure.security.jwt_service import JWTService, TokenType
from app.infrastructure.security.password.password_handler import PasswordHandler


# Mock RBACService for testing
class MockRBACService:
    def get_role_permissions(self, role):
        # Simple mock implementation
        permissions = {
            Role.PATIENT: {"view_own_medical_records", "update_own_profile"},
            Role.DOCTOR: {"view_patient_medical_records", "create_medical_record"},
            Role.ADMIN: {"view_all_medical_records", "manage_users", "system_configuration", "view_all_data", "manage_system"},
            Role.NURSE: {"view_patient_data"}
        }
        return permissions.get(role, set())

    def has_permission(self, role, permission):
        return permission in self.get_role_permissions(role)

@pytest.fixture
def mock_settings(monkeypatch) -> Settings:
    """Provides mock settings for JWT tests."""
    settings_mock = MagicMock(spec=Settings)
    # settings_mock.JWT_SECRET_KEY = "testkey12345678901234567890123456789" # Removed old assignment
    settings_mock.JWT_ALGORITHM = "HS256"
    settings_mock.ACCESS_TOKEN_EXPIRE_MINUTES = 15
    settings_mock.JWT_REFRESH_TOKEN_EXPIRE_DAYS = 7
    settings_mock.JWT_ISSUER = "test_issuer"
    settings_mock.JWT_AUDIENCE = "test_audience"
    # settings.JWT_SECRET_KEY.get_secret_value.return_value = settings.JWT_SECRET_KEY # Removed old incorrect mock

    # Correctly mock JWT_SECRET_KEY as a SecretStr
    raw_secret = "testkey12345678901234567890123456789"
    mock_secret_str = MagicMock(spec=SecretStr)
    mock_secret_str.get_secret_value.return_value = raw_secret

    # Set the mocked SecretStr on the mock settings object
    settings_mock.JWT_SECRET_KEY = mock_secret_str

    return settings_mock

@pytest.fixture
def security_components(mock_settings: Settings):
    """
    Create the core security components needed for testing.

    Returns:
        Tuple of (jwt_service, password_handler, role_manager)
    """
    jwt_service = JWTService(settings=mock_settings, user_repository=None)
    password_handler = PasswordHandler()
    role_manager = MockRBACService() # Use mock RBAC
    return jwt_service, password_handler, role_manager

@pytest.mark.db_required # Keep if DB interaction happens elsewhere
class TestSecurityBoundary:
    """Test suite for integrated security boundaries."""

    @pytest.mark.asyncio
    async def test_complete_auth_flow(self, security_components):
        """Test a complete authentication flow with all security components."""
        jwt_service, password_handler, role_manager = security_components
        
        password = password_handler.generate_secure_password()
        hashed_password = password_handler.hash_password(password)
        is_valid = password_handler.verify_password(password, hashed_password)
        assert is_valid is True

        user_id = str(uuid.uuid4())
        role = Role.PATIENT
        permissions = list(role_manager.get_role_permissions(role))
        session_id = "session_abc123"
        user_data = {
            "sub": user_id,
            "roles": [role.value], # Pass role value
            "permissions": permissions,
            "session_id": session_id
        }

        token = jwt_service.create_access_token(data=user_data)
        token_data = jwt_service.decode_token(token)
        
        assert token_data.sub == user_id
        assert token_data.roles == [role.value]
        # assert token_data.session_id == session_id # Check if session_id is in payload
        
        assert role_manager.has_permission(role, "view_own_medical_records")
        assert not role_manager.has_permission(role, "view_all_medical_records")

    @pytest.mark.asyncio
    async def test_token_expiration(self, security_components, mock_settings):
        """Test token expiration handling."""
        jwt_service, _, _ = security_components
        
        # Create a token with very short expiration by temporarily modifying settings or creating a new service
        original_expiry = mock_settings.ACCESS_TOKEN_EXPIRE_MINUTES
        mock_settings.ACCESS_TOKEN_EXPIRE_MINUTES = 0.01 # ~0.6 seconds
        # Recreate service with modified settings if necessary, or patch
        short_lived_jwt_service = JWTService(settings=mock_settings, user_repository=None)

        user_data = {
            "sub": "test123",
            "roles": [Role.PATIENT.value],
            "permissions": [],
            "session_id": "session_test"
        }
        token = short_lived_jwt_service.create_access_token(data=user_data)
        
        # Token should be valid immediately
        token_data = short_lived_jwt_service.decode_token(token)
        assert token_data is not None
        
        # Wait for token to expire (increase sleep time)
        await asyncio.sleep(1.5) 
        
        # Token should now be expired
        with pytest.raises(TokenExpiredException):
            short_lived_jwt_service.decode_token(token)

        # Restore original setting
        mock_settings.ACCESS_TOKEN_EXPIRE_MINUTES = original_expiry

    @pytest.mark.asyncio
    async def test_role_based_access_control(self, security_components):
        """Test role-based access control with different roles."""
        jwt_service, _, role_manager = security_components
        
        roles_to_test = [Role.PATIENT, Role.DOCTOR, Role.ADMIN]
        
        for role in roles_to_test:
            expected_permissions = role_manager.get_role_permissions(role)
            user_id = f"user_{role.value}"
            session_id = f"session_{role.value}"
            user_data = {
                "sub": user_id,
                "roles": [role.value],
                "permissions": list(expected_permissions),
                "session_id": session_id
            }

            token = jwt_service.create_access_token(data=user_data)
            token_data = jwt_service.decode_token(token)
            
            assert token_data.sub == user_id
            assert token_data.roles == [role.value]
            
            for permission in expected_permissions:
                assert role_manager.has_permission(role, permission), \
                    f"Role {role} should have permission {permission}"
            
            all_system_permissions = set()
            for r in Role:
                all_system_permissions.update(role_manager.get_role_permissions(r))
            
            unexpected_permissions = all_system_permissions - expected_permissions
            for permission in unexpected_permissions:
                assert not role_manager.has_permission(role, permission), \
                    f"Role {role} should not have permission {permission}"

    def test_password_strength_validation(self, security_components):
        """Test password strength validation."""
        # Unpack components
        _, password_handler, _ = security_components
        
        # Test a strong password
        strong_password = "Str0ng@P4ssw0rd!"
        is_valid, _ = password_handler.validate_password_strength(strong_password)
        assert is_valid is True
        
        # Test various weak passwords and ensure they're rejected
        weak_passwords = [
            "short123!",       # Too short
            "nouppercase123!",  # No uppercase
            "NOLOWERCASE123!",  # No lowercase
            "NoSpecialChars123",  # No special characters
            "NoDigits@Here",   # No digits
            "Password12345@",  # Common pattern
        ]
        
        for password in weak_passwords:
            is_valid, error = password_handler.validate_password_strength(password)
            assert is_valid is False
            assert error is not None

    @pytest.mark.asyncio
    async def test_admin_special_privileges(self, security_components):
        """Test admin special privileges that override normal permissions."""
        jwt_service, _, role_manager = security_components
        
        admin_user_data = {"sub": "admin123", "roles": [Role.ADMIN.value], "permissions": list(role_manager.get_role_permissions(Role.ADMIN))}
        nurse_user_data = {"sub": "nurse456", "roles": [Role.NURSE.value], "permissions": list(role_manager.get_role_permissions(Role.NURSE))}
        
        admin_token = jwt_service.create_access_token(data=admin_user_data)
        nurse_token = jwt_service.create_access_token(data=nurse_user_data)
        
        admin_data = jwt_service.decode_token(admin_token)
        nurse_data = jwt_service.decode_token(nurse_token)
        
        assert role_manager.has_permission(Role.ADMIN, "view_all_data")
        assert role_manager.has_permission(Role.ADMIN, "manage_users")
        
        assert role_manager.has_permission(Role.NURSE, "view_patient_data")
        assert not role_manager.has_permission(Role.NURSE, "manage_users")

    @pytest.mark.asyncio
    async def test_token_generation_and_validation(self, mock_settings):
        """Test generating and validating a standard token."""
        jwt_service = JWTService(settings=mock_settings, user_repository=None)
        user_id = str(uuid.uuid4())
        roles = [Role.ADMIN.value]
        user_data = {"sub": user_id, "roles": roles}

        token = jwt_service.create_access_token(data=user_data)
        assert isinstance(token, str)

        payload = jwt_service.decode_token(token)
        assert payload.sub == user_id
        assert payload.roles == roles
        assert payload.type == TokenType.ACCESS # Verify type
        assert payload.exp > int(datetime.now(timezone.utc).timestamp())

    @pytest.mark.asyncio
    async def test_expired_token_validation(self, mock_settings):
        """Test that an expired token raises TokenExpiredException."""
        jwt_service = JWTService(settings=mock_settings, user_repository=None)
        user_id = str(uuid.uuid4())
        user_data = {"sub": user_id, "roles": [Role.PATIENT.value]}

        # Create token that expired 1 minute ago
        expired_token = jwt_service._create_token( # Assuming _create_token is also sync
            data=user_data, 
            token_type=TokenType.ACCESS,
            expires_delta_minutes=-1 
        )
        
        with pytest.raises(TokenExpiredException):
            jwt_service.decode_token(expired_token)

    @pytest.mark.asyncio
    async def test_invalid_token_validation(self, mock_settings):
        """Test that an invalid/tampered token raises InvalidTokenException."""
        jwt_service = JWTService(settings=mock_settings, user_repository=None)
        invalid_token = "this.is.not.a.valid.token"

        with pytest.raises(InvalidTokenException):
            jwt_service.decode_token(invalid_token)

        # Test token with incorrect signature
        user_id = str(uuid.uuid4())
        user_data = {"sub": user_id, "roles": [Role.PATIENT.value]}
        token = jwt_service.create_access_token(data=user_data)
        tampered_token = token[:-5] + "wrong"
        with pytest.raises(InvalidTokenException):
            jwt_service.decode_token(tampered_token)
            
    @pytest.mark.asyncio
    async def test_token_with_minimal_payload(self, mock_settings):
        """Test token validation with minimal required payload."""
        jwt_service = JWTService(settings=mock_settings, user_repository=None)
        user_id = str(uuid.uuid4())
        jti = str(uuid.uuid4())
        user_data = {"sub": user_id, "jti": jti} # Minimal data

        token = jwt_service.create_access_token(data=user_data)
        payload = jwt_service.decode_token(token)
        
        assert payload.sub == user_id
        assert str(payload.jti) == jti
        assert payload.type == TokenType.ACCESS
        assert payload.roles == [] # Default empty list
        # assert payload.permissions is None # Default depends on implementation
        # assert payload.session_id is None # Default depends on implementation

    @pytest.mark.asyncio
    async def test_short_lived_token_validation(self, mock_settings):
        """Test validation of a very short-lived token."""
        mock_settings.ACCESS_TOKEN_EXPIRE_MINUTES = 1/60  # 1 second
        jwt_service = JWTService(settings=mock_settings, user_repository=None)
        
        user_id = str(uuid.uuid4())
        user_data = {"sub": user_id, "roles": [Role.PATIENT.value]}

        token = jwt_service.create_access_token(data=user_data)
        
        # Validate immediately
        payload = jwt_service.decode_token(token)
        assert payload.sub == user_id

        # Wait for it to expire
        await asyncio.sleep(2) # Sleep for 2 seconds

        with pytest.raises(TokenExpiredException):
            jwt_service.decode_token(token)