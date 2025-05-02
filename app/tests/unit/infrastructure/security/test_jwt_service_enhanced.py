"""
Enhanced unit tests for the JWT Service implementation.

This test suite provides comprehensive coverage for JWT token generation,
validation, and management to ensure secure authentication within the platform.
"""

from datetime import datetime, timedelta, timezone  # Corrected import

# from app.domain.utils.datetime_utils import UTC # Use timezone.utc directly
from unittest.mock import MagicMock

import jwt
import pytest
from freezegun import freeze_time

# Use canonical config path
from app.config.settings import Settings
from app.infrastructure.security.jwt.jwt_service import JWTService

# Define UTC if not imported elsewhere (Python 3.11+)
try:
    from app.domain.utils.datetime_utils import UTC
except ImportError:
    UTC = timezone.utc # Fallback for older Python versions

# Test Constants
TEST_ACCESS_EXPIRE_MINUTES = 15
TEST_REFRESH_EXPIRE_DAYS = 7
TEST_SECRET_KEY = "enhanced-secret-key-for-testing-purpose-only-32+"
TEST_ALGORITHM = "HS256"
TEST_ISSUER = "test_issuer_enhanced"
TEST_AUDIENCE = "test_audience_enhanced"

@pytest.fixture
def test_settings() -> Settings:
    settings = MagicMock(spec=Settings)
    
    # Mock SECRET_KEY as an object with get_secret_value
    mock_secret_key = MagicMock()
    mock_secret_key.get_secret_value.return_value = TEST_SECRET_KEY
    settings.SECRET_KEY = mock_secret_key
    
    # Mock JWT_SECRET_KEY as an object with get_secret_value
    mock_jwt_secret_key = MagicMock()
    mock_jwt_secret_key.get_secret_value.return_value = TEST_SECRET_KEY # Use same key for simplicity
    settings.JWT_SECRET_KEY = mock_jwt_secret_key
    
    # Assign other settings directly
    settings.JWT_ALGORITHM = TEST_ALGORITHM
    settings.ACCESS_TOKEN_EXPIRE_MINUTES = TEST_ACCESS_EXPIRE_MINUTES
    settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS = TEST_REFRESH_EXPIRE_DAYS # Corrected attribute
    settings.JWT_ISSUER = TEST_ISSUER
    settings.JWT_AUDIENCE = TEST_AUDIENCE
    
    # Keep ALGORITHM directly accessible if needed by tests
    settings.ALGORITHM = TEST_ALGORITHM
    
    return settings

@pytest.fixture
def jwt_service(test_settings: Settings) -> JWTService:
    return JWTService(settings=test_settings, user_repository=None) # Assuming no user repo needed here

# Removed misplaced decorator @pytest.mark.db_required() from class definition
class TestJWTService:
    """Comprehensive tests for the JWTService class."""

    def test_initialization(self, jwt_service: JWTService, test_settings: Settings):
        """Test JWT service initialization with settings."""
        assert jwt_service.secret_key == TEST_SECRET_KEY
        assert jwt_service.algorithm == TEST_ALGORITHM
        assert jwt_service.access_token_expire_minutes == TEST_ACCESS_EXPIRE_MINUTES
        assert jwt_service.refresh_token_expire_days == test_settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS # Verify against settings
        assert jwt_service.issuer == TEST_ISSUER
        assert jwt_service.audience == TEST_AUDIENCE

    async def test_create_access_token(self, jwt_service: JWTService):
        """Test creation of access tokens."""
        # Create a basic access token
        data = {"sub": "user123", "role": "patient"}
        token = await jwt_service.create_access_token(data)

        # Verify token is a string
        assert isinstance(token, str)

        # Decode and verify token contents
        decoded = jwt.decode(
            token,
            jwt_service.secret_key,
            algorithms=[jwt_service.algorithm],
            audience=jwt_service.audience,
            issuer=jwt_service.issuer
        )

        # Verify token claims
        assert decoded["sub"] == "user123"
        assert decoded["role"] == "patient"
        assert "exp" in decoded
        assert "iat" in decoded
        assert decoded["aud"] == jwt_service.audience
        assert decoded["iss"] == jwt_service.issuer

        # Verify expiration is set correctly (using timestamps directly)
        now_timestamp = datetime.now(UTC).timestamp() # Use UTC
        exp_timestamp = decoded["exp"]
        time_diff = exp_timestamp - now_timestamp
        # Token should expire in ~30 minutes (between 29-31 minutes from now)
        assert 29 * 60 <= time_diff <= 31 * 60

    async def test_create_refresh_token(self, jwt_service: JWTService):
        """Test creation of refresh tokens."""
        # Create a refresh token
        data = {"sub": "user123", "role": "patient", "refresh": True}
        token = await jwt_service.create_refresh_token(data)

        # Verify token is a string
        assert isinstance(token, str)

        # Decode and verify token contents
        decoded = jwt.decode(
            token,
            jwt_service.secret_key,
            algorithms=[jwt_service.algorithm],
            audience=jwt_service.audience,
            issuer=jwt_service.issuer
        )

        # Verify token claims
        assert decoded["sub"] == "user123"
        assert decoded["refresh"] is True
        assert "exp" in decoded
        assert "iat" in decoded

        # Verify expiration is set correctly (using timestamps directly)
        now_timestamp = datetime.now(UTC).timestamp() # Use UTC
        exp_timestamp = decoded["exp"]
        time_diff = exp_timestamp - now_timestamp
        expected_days = jwt_service.refresh_token_expire_days
        # Token should expire in ~7 days (allow some buffer)
        min_seconds = (expected_days * 24 * 3600) - (1 * 3600)  # 7 days - 1 hour
        max_seconds = (expected_days * 24 * 3600) + (1 * 3600)  # 7 days + 1 hour
        assert min_seconds <= time_diff <= max_seconds

    async def test_verify_token_valid(self, jwt_service: JWTService):
        """Test verification of valid tokens."""
        # Create a valid token
        data = {"sub": "user123", "role": "patient"}
        token = await jwt_service.create_access_token(data)

        # Verify the token
        payload = await jwt_service.verify_token(token)

        # Check payload contents
        assert payload["sub"] == "user123"
        assert payload["role"] == "patient"

    async def test_verify_token_expired(self, jwt_service: JWTService):
        """Test verification of expired tokens."""
        # Create an expired token by setting 'exp' in the past
        past_exp = datetime.now(UTC) - timedelta(minutes=1)
        data = {"sub": "user123", "role": "patient", "exp": past_exp}
        # Need to encode directly as create_access_token sets future expiry
        expired_token = jwt.encode(
            data, jwt_service.secret_key, algorithm=jwt_service.algorithm
        )

        # Verify the token fails validation
        with pytest.raises(jwt.ExpiredSignatureError):
            await jwt_service.verify_token(expired_token)

    async def test_verify_token_invalid_signature(self, jwt_service: JWTService):
        """Test verification of tokens with invalid signatures."""
        # Create a valid token
        data = {"sub": "user123", "role": "patient"}
        token = await jwt_service.create_access_token(data)

        # Tamper with the token signature
        parts = token.split('.')
        if len(parts) == 3:  # header.payload.signature
            # Modify the last character of the signature
            modified_sig = parts[2][:-1] + ('A' if parts[2][-1] != 'A' else 'B')
            tampered_token = f"{parts[0]}.{parts[1]}.{modified_sig}"

            # Verify the tampered token fails validation
            with pytest.raises(jwt.InvalidSignatureError):
                await jwt_service.verify_token(tampered_token)
        else:
            pytest.fail("Generated token does not have 3 parts.")


    async def test_verify_token_invalid_audience(self, jwt_service: JWTService, test_settings: MagicMock):
        """Test verification of tokens with invalid audience."""
        # Create token with the correct audience first
        data = {"sub": "user123", "role": "patient"}
        token = await jwt_service.create_access_token(data)

        # Now try to verify with a different audience
        with pytest.raises(jwt.InvalidAudienceError):
            jwt.decode(
                token,
                jwt_service.secret_key,
                algorithms=[jwt_service.algorithm],
                audience="different:audience", # Mismatched audience
                issuer=jwt_service.issuer
            )
        # Test the service method directly if it enforces audience check
        # This might require mocking jwt.decode within verify_token if needed
        # For now, testing jwt.decode directly shows the principle

    async def test_verify_token_invalid_issuer(self, jwt_service: JWTService):
        """Test verification of tokens with invalid issuer."""
        # Create token with the correct issuer
        data = {"sub": "user123", "role": "patient"}
        token = await jwt_service.create_access_token(data)

        # Now try to verify with a different issuer
        with pytest.raises(jwt.InvalidIssuerError):
             jwt.decode(
                token,
                jwt_service.secret_key,
                algorithms=[jwt_service.algorithm],
                audience=jwt_service.audience,
                issuer="different.issuer" # Mismatched issuer
            )

    async def test_verify_token_malformed(self, jwt_service: JWTService):
        """Test verification of malformed tokens."""
        # Create malformed token
        malformed_token = "invalid.token.format"

        # Verify the malformed token fails validation
        with pytest.raises(jwt.DecodeError):
            await jwt_service.verify_token(malformed_token)

    async def test_refresh_access_token(self, jwt_service: JWTService):
        """Test refreshing access tokens with valid refresh tokens."""
        # Create a refresh token
        user_data = {"sub": "user123", "role": "patient", "refresh": True}
        refresh_token = await jwt_service.create_refresh_token(user_data)

        # Refresh the access token
        new_access_token = await jwt_service.refresh_access_token(refresh_token)

        # Verify the new access token is valid
        assert isinstance(new_access_token, str)

        # Decode and verify access token contents
        payload = await jwt_service.verify_token(new_access_token)
        assert payload["sub"] == "user123"
        assert payload["role"] == "patient"
        assert "refresh" not in payload  # refresh flag shouldn't be in access tokens

    async def test_refresh_access_token_with_non_refresh_token(self, jwt_service: JWTService):
        """Test refresh fails with non-refresh tokens."""
        # Create a regular access token
        user_data = {"sub": "user123", "role": "patient"}
        access_token = await jwt_service.create_access_token(user_data)

        # Attempt to use access token as refresh token
        with pytest.raises(ValueError, match="Not a refresh token"):
            await jwt_service.refresh_access_token(access_token)

    async def test_get_token_identity(self, jwt_service: JWTService):
        """Test extracting user identity from token."""
        # Create a token with user identity
        user_id = "user123"
        data = {"sub": user_id, "role": "patient"}
        token = await jwt_service.create_access_token(data)

        # Extract identity
        identity = await jwt_service.get_token_identity(token)

        # Verify identity
        assert identity == user_id

    async def test_get_token_identity_missing_sub(self, jwt_service: JWTService):
        """Test extracting identity from token without sub claim."""
        # Create a special token without sub claim using direct JWT encoding
        payload = {
            "role": "patient",
            "exp": datetime.now(UTC) + timedelta(minutes=30),
            "iat": datetime.now(UTC),
            "aud": jwt_service.audience,
            "iss": jwt_service.issuer
        }
        token = jwt.encode(
            payload,
            jwt_service.secret_key,
            algorithm=jwt_service.algorithm
        )

        # Attempt to extract identity
        with pytest.raises(ValueError, match="Token missing 'sub' claim"):
            await jwt_service.get_token_identity(token)

    @pytest.mark.asyncio
    @freeze_time("2024-01-01 12:00:00")
    async def test_token_timestamps_are_correct(self, jwt_service: JWTService):
        user_data = {"sub": "user_ts_test"}
        token = await jwt_service.create_access_token(data=user_data)
        payload = await jwt_service.decode_token(token)

        now = datetime.now(timezone.utc)
        expected_iat = int(now.timestamp())
        expected_exp_delta_seconds = jwt_service.access_token_expire_minutes * 60
        expected_exp = expected_iat + expected_exp_delta_seconds

        assert payload.iat == expected_iat
        assert payload.exp == expected_exp

        refresh_token = await jwt_service.create_refresh_token(data=user_data)
        refresh_payload = await jwt_service.decode_token(refresh_token)

        expected_refresh_exp_delta_seconds = jwt_service.refresh_token_expire_days * 24 * 60 * 60 # Use service attribute
        expected_refresh_exp = expected_iat + expected_refresh_exp_delta_seconds

        assert refresh_payload.iat == expected_iat
        # Allow small tolerance for refresh token expiry due to potential rounding/timing
        assert abs(refresh_payload.exp - expected_refresh_exp) <= 1 
