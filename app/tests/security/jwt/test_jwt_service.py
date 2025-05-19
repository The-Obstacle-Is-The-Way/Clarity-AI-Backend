# import jwt # Use service methods instead of direct jwt calls
import asyncio
import uuid
from unittest.mock import MagicMock, PropertyMock

import pytest
from app.tests.utils.asyncio_helpers import run_with_timeout
from pydantic import SecretStr  # Import SecretStr

from app.config.settings import Settings  # Import Settings
from app.domain.exceptions.token_exceptions import (
    InvalidTokenException,
    TokenExpiredException,
)
from app.infrastructure.security.jwt.jwt_service import (
    JWTService,
    TokenPayload,
    TokenType,
)


@pytest.fixture
def mock_settings() -> MagicMock:
    """Provides mock settings for JWT service tests."""
    settings = MagicMock(spec=Settings)

    # Mock JWT_SECRET_KEY to behave like SecretStr
    mock_jwt_secret = MagicMock(spec=SecretStr)
    mock_jwt_secret.get_secret_value.return_value = (
        "test-secret-for-service-test-32-bytes"
    )
    type(settings).JWT_SECRET_KEY = PropertyMock(
        return_value=mock_jwt_secret
    )  # Use PropertyMock

    settings.JWT_ALGORITHM = "HS256"
    settings.ACCESS_TOKEN_EXPIRE_MINUTES = 15
    settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS = 7
    settings.JWT_ISSUER = "test_issuer_service"
    settings.JWT_AUDIENCE = "test_audience_service"

    return settings


@pytest.fixture
def jwt_service(mock_settings: MagicMock) -> JWTService:
    """Creates a JWTService instance with mock settings."""
    # Get the secret key from the mock settings
    secret_key = mock_settings.JWT_SECRET_KEY.get_secret_value()

    return JWTService(
        secret_key=secret_key,
        algorithm=mock_settings.JWT_ALGORITHM,
        access_token_expire_minutes=mock_settings.ACCESS_TOKEN_EXPIRE_MINUTES,
        refresh_token_expire_days=mock_settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS,
        issuer=mock_settings.JWT_ISSUER,
        audience=mock_settings.JWT_AUDIENCE,
        settings=mock_settings,
        user_repository=None,
    )


@pytest.mark.venv_only()  # Keep marker if it has specific meaning
class TestJWTService:
    """
    Tests for the JWT Service implementation.
    """

    user_subject = str(uuid.uuid4())
    user_roles = ["patient"]

    @pytest.mark.asyncio
    async def test_create_access_token_structure(self, jwt_service: JWTService):
        """Test structure and basic claims of a created access token."""
        user_data = {"sub": self.user_subject, "roles": self.user_roles}
        token = jwt_service.create_access_token(data=user_data)

        payload = jwt_service.decode_token(token)

        assert isinstance(token, str)
        assert payload.sub == self.user_subject
        assert payload.type == TokenType.ACCESS  # Check type
        assert payload.roles == self.user_roles
        assert isinstance(payload.exp, int)
        assert isinstance(payload.iat, int)
        assert isinstance(payload.jti, (str, uuid.UUID))  # JTI can be UUID or str

        # Check if issuer/audience match settings
        assert payload.iss == jwt_service.issuer
        assert payload.aud == jwt_service.audience

        # Verify no unexpected PHI fields were included by mistake
        phi_fields = ["name", "email", "dob", "ssn", "address", "phone"]
        payload_dict = payload.model_dump()  # Use model_dump if available
        for field in phi_fields:
            assert (
                field not in payload_dict
            ), f"Unexpected PHI field '{field}' found in token payload: {payload_dict}"

    @pytest.mark.asyncio
    async def test_create_access_token_expiration(self, jwt_service: JWTService):
        """Test that access tokens have correct expiration times based on settings."""
        user_data = {"sub": self.user_subject, "roles": self.user_roles}
        token = jwt_service.create_access_token(data=user_data)
        payload = jwt_service.decode_token(token)

        issued_at = payload.iat
        expiration = payload.exp
        expected_lifetime_seconds = jwt_service.access_token_expire_minutes * 60
        actual_lifetime_seconds = expiration - issued_at

        # Allow a small tolerance (e.g., 1 second)
        assert (
            abs(actual_lifetime_seconds - expected_lifetime_seconds) <= 1
        ), f"Token lifetime ({actual_lifetime_seconds}s) differs significantly from expected ({expected_lifetime_seconds}s)"

    @pytest.mark.asyncio
    async def test_decode_token_valid(self, jwt_service: JWTService):
        """Test that valid tokens are properly decoded and validated."""
        user_data = {"sub": self.user_subject, "roles": self.user_roles}
        token = jwt_service.create_access_token(data=user_data)

        payload = jwt_service.decode_token(token)

        assert isinstance(payload, TokenPayload)
        assert payload.sub == self.user_subject
        assert payload.roles == self.user_roles
        assert payload.type == TokenType.ACCESS

    @pytest.mark.asyncio
    async def test_decode_token_expired(self, jwt_service: JWTService):
        """Test that expired tokens raise TokenExpiredException during decoding."""
        user_data = {"sub": self.user_subject, "roles": self.user_roles}
        # Create token that expired 1 minute ago
        expired_token = jwt_service.create_access_token(
            data=user_data, expires_delta_minutes=-1
        )

        await asyncio.sleep(0.1)  # Ensure time passes expiry

        with pytest.raises(TokenExpiredException):
            jwt_service.decode_token(expired_token)

    @pytest.mark.asyncio
    async def test_decode_token_invalid_signature(self, jwt_service: JWTService):
        """Test that tokens with invalid signatures raise InvalidTokenException."""
        user_data = {"sub": self.user_subject, "roles": self.user_roles}
        token = jwt_service.create_access_token(data=user_data)

        parts = token.split(".")
        if len(parts) == 3:
            tampered_signature = parts[2] + "X"
            tampered_token = f"{parts[0]}.{parts[1]}.{tampered_signature}"
        else:
            pytest.fail("Generated token does not have 3 parts separated by dots.")

        with pytest.raises(InvalidTokenException) as exc_info:
            jwt_service.decode_token(tampered_token)
        assert "Signature verification failed" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_decode_token_invalid_format(self, jwt_service: JWTService):
        """Test that tokens with invalid format raise InvalidTokenException."""
        # Create a truly unparseable token - binary data will cause UTF-8 decode issues
        invalid_token = bytes([0x9E, 0x8F]) + b"invalid"

        with pytest.raises(InvalidTokenException) as exc_info:
            jwt_service.decode_token(invalid_token)

        # The exact error message may vary based on the JWT library version
        # So we'll check for common error patterns instead of exact text
        error_msg = str(exc_info.value)
        assert any(
            pattern in error_msg
            for pattern in [
                "Invalid header",
                "codec can't decode",
                "Not enough segments",
                "Invalid token",
            ]
        ), f"Unexpected error message: {error_msg}"

    # Keep skipped tests as placeholders if functionality might be added later
    # ... skipped tests for role permissions and refresh token logic ...


if __name__ == "__main__":
    pytest.main(["-xvs", __file__])
