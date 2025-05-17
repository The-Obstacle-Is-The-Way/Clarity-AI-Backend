import asyncio
import uuid
from datetime import timedelta

import pytest
from jose import JWTError

from app.core.config import Settings
from app.core.interfaces.services.rbac_service_interface import IRBACService
from app.domain.enums.role_enum import Role
from app.domain.exceptions.token_exceptions import (
    InvalidTokenException,
    TokenExpiredException,
)
from app.infrastructure.security.jwt.jwt_service import JWTService
from app.infrastructure.security.password_handler import PasswordHandler

class MockRBACService(IRBACService):
    """A mock implementation of the RBAC service for testing purposes."""

    def __init__(self) -> None:
        self.role_permissions: dict[Role, set[str]] = {
            Role.ADMIN: {"read_patient_data", "write_patient_data", "manage_users"},
            Role.PROVIDER: {"read_patient_data", "write_patient_data"},
            Role.PATIENT: {"read_own_data"},
        }

    async def get_role_permissions(self, role: Role) -> set[str]:
        return self.role_permissions.get(role, set())

    async def has_permission(self, role: Role, permission: str) -> bool:
        permissions = await self.get_role_permissions(role)
        return permission in permissions

@pytest.fixture
def mock_settings() -> Settings:
    """Provide mock settings for tests."""
    return Settings(
        JWT_SECRET_KEY="testsecretkey", 
        JWT_ALGORITHM="HS256",
        ACCESS_TOKEN_EXPIRE_MINUTES=30,
        JWT_REFRESH_TOKEN_EXPIRE_DAYS=7,
        JWT_ISSUER="test_issuer",
        JWT_AUDIENCE="test_audience",
    )

@pytest.fixture
def security_components(
    mock_settings: Settings,
) -> tuple[JWTService, PasswordHandler, MockRBACService]:
    """Create the core security components needed for testing."""
    jwt_service = JWTService(
        secret_key=str(mock_settings.JWT_SECRET_KEY), 
        algorithm=mock_settings.JWT_ALGORITHM,
        token_blacklist_repository=None 
    )
    password_handler = PasswordHandler()
    role_manager = MockRBACService() 
    return jwt_service, password_handler, role_manager

@pytest.mark.db_required 
class TestSecurityBoundary:
    """Test cases for the security boundary, focusing on integration aspects."""

    @pytest.mark.asyncio
    async def test_complete_auth_flow(
        self,
        security_components: tuple[JWTService, PasswordHandler, MockRBACService],
    ) -> None:
        """Test the complete authentication flow: password hashing, token creation, and validation."""
        jwt_service, password_handler, _ = security_components
        user_id = str(uuid.uuid4())
        raw_password = "Str0ngP@ssw0rd!"
        hashed_password = password_handler.hash_password(raw_password)

        assert password_handler.verify_password(raw_password, hashed_password)

        user_data = {"sub": user_id, "roles": [Role.PATIENT.value]}
        access_token = jwt_service.create_access_token(data=user_data)
        refresh_token = jwt_service.create_refresh_token(subject=user_id)

        assert access_token
        assert refresh_token

        payload = jwt_service.validate_token(access_token)
        assert payload["sub"] == user_id
        assert Role.PATIENT.value in payload["roles"]

        refresh_payload = jwt_service.validate_token(refresh_token)
        assert refresh_payload["sub"] == user_id
        assert refresh_payload["type"] == "refresh"

    @pytest.mark.asyncio
    async def test_token_expiration(
        self,
        security_components: tuple[JWTService, PasswordHandler, MockRBACService],
        mock_settings: Settings,
    ) -> None:
        """Test that token expiration is handled correctly."""
        _, _, _ = security_components 
        original_expiry = mock_settings.ACCESS_TOKEN_EXPIRE_MINUTES
        mock_settings.ACCESS_TOKEN_EXPIRE_MINUTES = 0.01 
        short_lived_jwt_service = JWTService(
            secret_key=str(mock_settings.JWT_SECRET_KEY), 
            algorithm=mock_settings.JWT_ALGORITHM,
            token_blacklist_repository=None 
        )

        user_data = {
            "sub": "test123",
            "roles": [Role.PROVIDER.value]
        }
        token = short_lived_jwt_service.create_access_token(data=user_data)

        await asyncio.sleep(1) 

        with pytest.raises(TokenExpiredException):
            short_lived_jwt_service.validate_token(token)

        mock_settings.ACCESS_TOKEN_EXPIRE_MINUTES = original_expiry

    @pytest.mark.asyncio
    async def test_role_based_access_control(
        self,
        security_components: tuple[JWTService, PasswordHandler, MockRBACService],
    ) -> None:
        """Test role-based access control using mocked RBAC service."""
        jwt_service, _, role_manager = security_components
        admin_id = str(uuid.uuid4())
        provider_id = str(uuid.uuid4())

        admin_token_data = {"sub": admin_id, "roles": [Role.ADMIN.value]}
        admin_token = jwt_service.create_access_token(data=admin_token_data)

        provider_token_data = {"sub": provider_id, "roles": [Role.PROVIDER.value]}
        provider_token = jwt_service.create_access_token(data=provider_token_data)

        admin_payload = jwt_service.validate_token(admin_token)
        provider_payload = jwt_service.validate_token(provider_token)

        assert Role.ADMIN.value in admin_payload["roles"]
        assert await role_manager.has_permission(Role.ADMIN, "manage_users")
        assert not await role_manager.has_permission(Role.PROVIDER, "manage_users")

        assert Role.PROVIDER.value in provider_payload["roles"]
        assert await role_manager.has_permission(Role.PROVIDER, "read_patient_data")
        assert not await role_manager.has_permission(Role.PATIENT, "write_patient_data")

    @pytest.mark.asyncio
    async def test_password_strength_validation(
        self, security_components: tuple[JWTService, PasswordHandler, MockRBACService]
    ) -> None:
        """Test password strength validation (conceptual, as PasswordHandler doesn't enforce)."""
        _, password_handler, _ = security_components
        weak_password = "password"
        strong_password = "Str0ngP@ssw0rd!23"

        assert password_handler.hash_password(weak_password)
        assert password_handler.hash_password(strong_password)

        hashed_weak = password_handler.hash_password(weak_password)
        assert password_handler.verify_password(weak_password, hashed_weak)

        hashed_strong = password_handler.hash_password(strong_password)
        assert password_handler.verify_password(strong_password, hashed_strong)

    @pytest.mark.asyncio
    async def test_admin_special_privileges(
        self,
        security_components: tuple[JWTService, PasswordHandler, MockRBACService],
        mock_settings: Settings,
    ) -> None:
        """Test that admin users have special privileges as defined in MockRBACService."""
        jwt_service, _, role_manager = security_components

        admin_user_id = str(uuid.uuid4())
        admin_user_data = {"sub": admin_user_id, "roles": [Role.ADMIN.value]}
        admin_token = jwt_service.create_access_token(data=admin_user_data)
        admin_payload = jwt_service.validate_token(token=admin_token)

        assert Role.ADMIN.value in admin_payload.get("roles", [])
        assert await role_manager.has_permission(Role.ADMIN, "manage_users")
        assert await role_manager.has_permission(Role.ADMIN, "read_patient_data")
        assert await role_manager.has_permission(Role.ADMIN, "write_patient_data")

        assert not await role_manager.has_permission(Role.PROVIDER, "manage_users")

    @pytest.mark.asyncio
    async def test_token_generation_and_validation(
        self, mock_settings: Settings
    ) -> None:
        """Test detailed aspects of token generation and validation."""
        jwt_service = JWTService(
            secret_key=str(mock_settings.JWT_SECRET_KEY),
            algorithm=mock_settings.JWT_ALGORITHM,
            token_blacklist_repository=None
        )
        
        user_id = str(uuid.uuid4())
        user_roles = [Role.PATIENT.value, Role.PROVIDER.value]
        custom_claim_key = "custom_data"
        custom_claim_value = "important_value"
        user_data = {
            "sub": user_id,
            "roles": user_roles,
            custom_claim_key: custom_claim_value
        }

        access_token = jwt_service.create_access_token(data=user_data)
        assert isinstance(access_token, str)

        payload = jwt_service.validate_token(access_token)
        assert payload["sub"] == user_id
        assert payload["iss"] == mock_settings.JWT_ISSUER
        assert payload["aud"] == mock_settings.JWT_AUDIENCE
        assert all(role in payload["roles"] for role in user_roles)
        assert payload[custom_claim_key] == custom_claim_value
        assert "exp" in payload
        assert "iat" in payload
        assert "nbf" in payload
        assert "jti" in payload

        refresh_token = jwt_service.create_refresh_token(subject=user_id)
        assert isinstance(refresh_token, str)

        refresh_payload = jwt_service.validate_token(refresh_token)
        assert refresh_payload["sub"] == user_id
        assert refresh_payload["type"] == "refresh"
        assert "exp" in refresh_payload
        assert "jti" in refresh_payload

    @pytest.mark.asyncio
    async def test_expired_token_validation(self, mock_settings: Settings) -> None:
        """Test that an expired token raises TokenExpiredException."""
        jwt_service = JWTService(
            secret_key=str(mock_settings.JWT_SECRET_KEY), 
            algorithm=mock_settings.JWT_ALGORITHM,
            token_blacklist_repository=None 
        )
        user_id = str(uuid.uuid4())
        user_data = {"sub": user_id, "roles": [Role.PATIENT.value]}

        expired_token = jwt_service.create_access_token(
            data=user_data, expires_delta=timedelta(seconds=0.001)
        )
        await asyncio.sleep(0.1)  

        with pytest.raises(TokenExpiredException):
            jwt_service.validate_token(expired_token)

    @pytest.mark.asyncio
    async def test_invalid_token_validation(self, mock_settings: Settings) -> None:
        """Test that an invalid/tampered token raises InvalidTokenException."""
        jwt_service = JWTService(
            secret_key=str(mock_settings.JWT_SECRET_KEY), 
            algorithm=mock_settings.JWT_ALGORITHM,
            token_blacklist_repository=None 
        )
        invalid_token = "this.is.not.a.valid.token"

        with pytest.raises(InvalidTokenException):
            jwt_service.validate_token(invalid_token)

        user_id = str(uuid.uuid4())
        user_data = {"sub": user_id}
        legit_token_parts = jwt_service.create_access_token(data=user_data).split('.')
        tampered_token = f"{legit_token_parts[0]}.{legit_token_parts[1]}.tampered_signature"
        with pytest.raises(InvalidTokenException):
            jwt_service.validate_token(tampered_token)

    @pytest.mark.asyncio
    async def test_token_with_minimal_payload(self, mock_settings: Settings) -> None:
        """Test token validation with minimal required payload."""
        jwt_service = JWTService(
            secret_key=str(mock_settings.JWT_SECRET_KEY), 
            algorithm=mock_settings.JWT_ALGORITHM,
            token_blacklist_repository=None 
        )
        user_id = str(uuid.uuid4())
        user_data = {"sub": user_id} 
        token = jwt_service.create_access_token(data=user_data)
        
        payload = jwt_service.validate_token(token)
        assert payload["sub"] == user_id
        assert "jti" in payload 
        assert "exp" in payload
        assert "iat" in payload
        assert "nbf" in payload

    @pytest.mark.asyncio
    async def test_short_lived_token_validation(self, mock_settings: Settings) -> None:
        """Test validation of a very short-lived token."""
        mock_settings.ACCESS_TOKEN_EXPIRE_MINUTES = 1/60  
        jwt_service = JWTService(
            secret_key=str(mock_settings.JWT_SECRET_KEY), 
            algorithm=mock_settings.JWT_ALGORITHM,
            token_blacklist_repository=None 
        )
        
        user_id = str(uuid.uuid4())
        user_data = {"sub": user_id, "roles": [Role.PATIENT.value]}
        token = jwt_service.create_access_token(data=user_data)

        try:
            jwt_service.validate_token(token)
        except JWTError as e:
            pytest.fail(f"Short-lived token validation failed prematurely: {e}")

        await asyncio.sleep(1.5)  

        with pytest.raises(TokenExpiredException):
            jwt_service.validate_token(token)