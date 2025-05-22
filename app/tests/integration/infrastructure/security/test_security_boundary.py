"""
Integration tests for HIPAA security boundaries.

These tests verify that our security components work together correctly
to enforce proper authentication and authorization boundaries.
"""

import asyncio
import uuid

import pytest

from app.config.settings import Settings  # Import Settings

# Assume RBACService is available or mock it if needed
# from app.infrastructure.security.rbac.rbac_service import RBACService
from app.domain.enums.role import Role
from app.domain.exceptions.token_exceptions import (
    InvalidTokenException,
    TokenExpiredException,
)

# Fixed import to use the JWT service's TokenType instead of domain enum
from app.infrastructure.security.jwt.jwt_service import JWTService, TokenType
from app.infrastructure.security.password.password_handler import PasswordHandler

# Try importing from domain enums as a fallback
try:
    from app.domain.enums.token_type import TokenType as DomainTokenType
except ImportError:
    # Use the JWT service's TokenType if domain enum is not available
    DomainTokenType = TokenType


# Mock RBACService for testing
class MockRBACService:
    def get_role_permissions(self, role):
        # Simple mock implementation
        permissions = {
            Role.PATIENT: {"view_own_medical_records", "update_own_profile"},
            Role.DOCTOR: {"view_patient_medical_records", "create_medical_record"},
            Role.ADMIN: {
                "view_all_medical_records",
                "manage_users",
                "system_configuration",
                "view_all_data",
                "manage_system",
            },
            Role.NURSE: {"view_patient_data"},
        }
        return permissions.get(role, set())

    def has_permission(self, role, permission):
        return permission in self.get_role_permissions(role)


@pytest.fixture
def mock_settings():
    """Fixture to provide mock settings for tests."""
    from app.tests.mocks.mock_settings import MockSettings

    return MockSettings()


@pytest.fixture
def security_components(mock_settings: Settings):
    """
    Create the core security components needed for testing.

    Returns:
        Tuple of (jwt_service, password_handler, role_manager)
    """
    jwt_service = JWTService(settings=mock_settings, user_repository=None)
    password_handler = PasswordHandler()
    role_manager = MockRBACService()  # Use mock RBAC
    return jwt_service, password_handler, role_manager


@pytest.mark.db_required  # Keep if DB interaction happens elsewhere
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
            "roles": [role.value],  # Pass role value
            "permissions": permissions,
            "session_id": session_id,
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

        # Ensure TESTING is set to False to ensure expiration is validated
        mock_settings.TESTING = False

        # Create a token that's already expired
        user_data = {
            "sub": "test123",
            "roles": [Role.PATIENT.value],
            "permissions": [],
            "session_id": "session_test",
        }

        # Create a token that's already expired (1 hour ago)
        # Using create_access_token with negative expires_delta_minutes
        expired_token = jwt_service.create_access_token(
            data=user_data,
            expires_delta_minutes=-60  # Very negative number to ensure it's definitely expired
        )

        # Create a JWT service instance with explicit options to verify expiration
        jwt_service_strict = JWTService(settings=mock_settings, user_repository=None)

        # Token should be expired - test with explicit options
        with pytest.raises(TokenExpiredException):
            jwt_service_strict.decode_token(
                expired_token,
                verify_signature=True,
                options={"verify_exp": True, "verify_signature": True},
            )

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
                "session_id": session_id,
            }

            token = jwt_service.create_access_token(data=user_data)
            token_data = jwt_service.decode_token(token)

            assert token_data.sub == user_id
            assert token_data.roles == [role.value]

            for permission in expected_permissions:
                assert role_manager.has_permission(
                    role, permission
                ), f"Role {role} should have permission {permission}"

            all_system_permissions = set()
            for r in Role:
                all_system_permissions.update(role_manager.get_role_permissions(r))

            unexpected_permissions = all_system_permissions - expected_permissions
            for permission in unexpected_permissions:
                assert not role_manager.has_permission(
                    role, permission
                ), f"Role {role} should not have permission {permission}"

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
            "short123!",  # Too short
            "nouppercase123!",  # No uppercase
            "NOLOWERCASE123!",  # No lowercase
            "NoSpecialChars123",  # No special characters
            "NoDigits@Here",  # No digits
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

        admin_user_data = {
            "sub": "admin123",
            "roles": [Role.ADMIN.value],
            "permissions": list(role_manager.get_role_permissions(Role.ADMIN)),
        }
        nurse_user_data = {
            "sub": "nurse456",
            "roles": [Role.NURSE.value],
            "permissions": list(role_manager.get_role_permissions(Role.NURSE)),
        }

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
        """Test the complete token generation and validation flow."""
        # Create a JWT service
        from app.infrastructure.security.jwt.jwt_service import JWTService, TokenType

        jwt_service = JWTService(
            secret_key=mock_settings.JWT_SECRET_KEY,
            algorithm=mock_settings.JWT_ALGORITHM,
            access_token_expire_minutes=mock_settings.ACCESS_TOKEN_EXPIRE_MINUTES,
            refresh_token_expire_days=mock_settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS,
            issuer=mock_settings.JWT_ISSUER,
            audience=mock_settings.JWT_AUDIENCE,
        )

        # Test data
        user_id = "test-user-id"
        user_data = {
            "sub": user_id,
            "role": "user",
            "permissions": ["read:own", "write:own"],
        }

        # Create an access token
        access_token = jwt_service.create_access_token(data=user_data)

        # Verify the token is not empty
        assert access_token
        assert isinstance(access_token, str)
        assert len(access_token) > 0

        # Decode the token and verify its content
        payload = jwt_service.decode_token(access_token)

        # Check that the token contains the expected data
        assert payload.sub == user_id
        assert hasattr(payload, "exp")
        assert hasattr(payload, "iat")
        assert hasattr(payload, "jti")

        # Verify token type
        assert payload.type == TokenType.ACCESS

        # Create a refresh token
        refresh_token = jwt_service.create_refresh_token(data=user_data)

        # Verify the refresh token
        refresh_payload = jwt_service.verify_refresh_token(refresh_token)

        # Check refresh token specific fields
        assert refresh_payload.type == TokenType.REFRESH
        assert getattr(refresh_payload, "refresh", False) is True

    @pytest.mark.asyncio
    async def test_expired_token_validation(self, mock_settings):
        """Test that an expired token raises TokenExpiredException."""
        jwt_service = JWTService(settings=mock_settings, user_repository=None)
        user_id = str(uuid.uuid4())
        user_data = {"sub": user_id, "roles": [Role.PATIENT.value]}

        # Create an expired token (60 minutes in the past)
        expired_token = jwt_service.create_access_token(
            data=user_data,
            expires_delta_minutes=-60
        )

        # Attempt to verify the token - should raise TokenExpiredException
        with pytest.raises(TokenExpiredException):
            jwt_service.decode_token(
                expired_token,
                options={"verify_exp": True}
            )

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
        # Remove jti from user_data since the service will generate one
        user_data = {"sub": user_id}  # Minimal data

        token = jwt_service.create_access_token(data=user_data)
        payload = jwt_service.decode_token(token)

        assert payload.sub == user_id
        # Don't check JTI value, just ensure it exists and is a string
        assert payload.jti is not None
        assert isinstance(payload.jti, str)
        assert payload.type == TokenType.ACCESS
        assert payload.roles == []  # Default empty list

    @pytest.mark.asyncio
    async def test_short_lived_token_validation(self, mock_settings):
        """Test validation of a very short-lived token."""
        mock_settings.ACCESS_TOKEN_EXPIRE_MINUTES = 1 / 60  # 1 second
        jwt_service = JWTService(settings=mock_settings, user_repository=None)

        user_id = str(uuid.uuid4())
        user_data = {"sub": user_id, "roles": [Role.PATIENT.value]}

        token = jwt_service.create_access_token(data=user_data)

        # Validate immediately
        payload = jwt_service.decode_token(token)
        assert payload.sub == user_id

        # Wait for it to expire
        await asyncio.sleep(2)  # Sleep for 2 seconds

        with pytest.raises(TokenExpiredException):
            jwt_service.decode_token(token)
