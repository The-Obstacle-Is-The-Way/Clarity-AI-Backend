"""Unit tests for JWT Service functionality.

This module tests the JWT service that handles authentication tokens,
a critical component for HIPAA-compliant user authentication and authorization.
"""

import datetime
from datetime import timezone
from typing import Any
from unittest.mock import MagicMock
import uuid

import pytest

# Conditionally import freezegun or skip the tests if it's not available
try:
    from freezegun import freeze_time

    FREEZEGUN_AVAILABLE = True
except ImportError:
    FREEZEGUN_AVAILABLE = False

    # Create a no-op placeholder for freeze_time decorator to avoid syntax errors
    def freeze_time(time_str):
        return lambda x: x


from app.config.settings import Settings  # Import actual Settings
from app.domain.exceptions import InvalidTokenError, TokenExpiredError

# Corrected imports for clean architecture implementation
from app.core.interfaces.services.jwt_service_interface import JWTServiceInterface
from app.infrastructure.security.jwt.jwt_service_impl import JWTServiceImpl
from app.infrastructure.security.jwt.jwt_service import TokenPayload

# Define test constants directly
TEST_SECRET_KEY = "test-jwt-secret-key-must-be-at-least-32-chars-long"
TEST_ALGORITHM = "HS256"
TEST_ACCESS_EXPIRE_MINUTES = 15
TEST_REFRESH_EXPIRE_DAYS = 7
TEST_ISSUER = "test_issuer"
TEST_AUDIENCE = "test_audience"

# Define UTC if not imported elsewhere (Python 3.11+)
try:
    from app.domain.utils.datetime_utils import UTC
except ImportError:
    UTC = timezone.utc  # Fallback for older Python versions


@pytest.fixture
def mock_settings() -> Settings:
    """Create mock settings for JWT service tests."""
    settings = MagicMock(spec=Settings)

    # Mock SECRET_KEY as an object with get_secret_value
    mock_secret_key = MagicMock()
    mock_secret_key.get_secret_value.return_value = TEST_SECRET_KEY
    settings.SECRET_KEY = mock_secret_key

    # Mock JWT_SECRET_KEY as an object with get_secret_value
    mock_jwt_secret_key = MagicMock()
    mock_jwt_secret_key.get_secret_value.return_value = (
        TEST_SECRET_KEY  # Use same key for simplicity
    )
    settings.JWT_SECRET_KEY = mock_jwt_secret_key

    # Assign other settings directly
    settings.JWT_ALGORITHM = TEST_ALGORITHM
    settings.ACCESS_TOKEN_EXPIRE_MINUTES = TEST_ACCESS_EXPIRE_MINUTES
    settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS = TEST_REFRESH_EXPIRE_DAYS
    settings.JWT_ISSUER = TEST_ISSUER
    settings.JWT_AUDIENCE = TEST_AUDIENCE

    # Keep ALGORITHM directly accessible if needed by tests
    settings.ALGORITHM = TEST_ALGORITHM

    return settings


@pytest.fixture
def mock_user_repository():
    """Create a mock user repository (can be None if not needed)."""
    return None  # Or MagicMock(spec=IUserRepository) if interactions are needed


@pytest.fixture
def jwt_service(mock_settings: Settings, mock_user_repository):
    """Create a JWT service instance for testing using mock settings."""
    # Instantiate JWTServiceImpl with required parameters following clean architecture
    service = JWTServiceImpl(
        secret_key=TEST_SECRET_KEY,
        algorithm=TEST_ALGORITHM,
        access_token_expire_minutes=TEST_ACCESS_EXPIRE_MINUTES,
        refresh_token_expire_days=TEST_REFRESH_EXPIRE_DAYS,
        user_repository=mock_user_repository,
        token_blacklist_repository=None,
        audit_logger=None,
        issuer=TEST_ISSUER,
        audience=TEST_AUDIENCE,
        settings=mock_settings
    )
    return service


@pytest.fixture
def user_claims() -> dict[str, Any]:
    """Create test user claims."""
    return {
        "sub": "user123",
        "user_id": "user123",  # Include user_id if create_access_token expects it
        "name": "Dr. Jane Smith",
        "email": "jane.smith@example.com",
        "roles": ["psychiatrist"],
        "permissions": ["read:patient", "write:clinical_note", "prescribe:medication"],
    }


@pytest.mark.skipif(not FREEZEGUN_AVAILABLE, reason="freezegun library not installed")
class TestJWTService:
    """Test suite for the JWT service."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up test environment."""
        # Initialize the JWT service with testing values
        self.jwt_service = JWTServiceImpl(
            secret_key="test-secret-key",
            algorithm="HS256",
            access_token_expire_minutes=15,
            refresh_token_expire_days=7,
            issuer="test-issuer",
            audience="test-audience"
        )
        yield

    @pytest.mark.asyncio
    async def test_create_access_token(self, jwt_service: JWTServiceImpl, user_claims: dict[str, Any]):
        """Test creating an access token with user claims."""
        # Pass necessary data directly to create_access_token
        access_token = jwt_service.create_access_token(data=user_claims)

        assert access_token is not None
        assert isinstance(access_token, str)

        # Use decode_token method for consistency if possible, or jwt.decode for direct check
        payload: TokenPayload = jwt_service.decode_token(access_token)

        assert payload.sub == user_claims["sub"]
        assert payload.roles == user_claims["roles"]
        assert payload.exp is not None
        assert payload.iat is not None
        assert payload.jti is not None
        assert payload.iss == TEST_ISSUER
        assert payload.aud == TEST_AUDIENCE
        assert payload.type == "access"

    @pytest.mark.asyncio
    async def test_create_refresh_token(self, jwt_service: JWTServiceImpl, user_claims: dict[str, Any]):
        """Test creating a refresh token with user claims."""
        # Pass necessary data directly to create_refresh_token
        refresh_token = jwt_service.create_refresh_token(
            data=user_claims  # Pass relevant subset if needed
        )

        assert refresh_token is not None
        assert isinstance(refresh_token, str)

        payload: TokenPayload = jwt_service.decode_token(refresh_token)

        assert payload.sub == user_claims["sub"]
        assert payload.exp is not None
        assert payload.iat is not None
        assert payload.jti is not None
        assert payload.iss == TEST_ISSUER
        assert payload.aud == TEST_AUDIENCE
        assert payload.type == "refresh"

    @pytest.mark.asyncio
    async def test_decode_token_valid(self, jwt_service: JWTServiceImpl, user_claims: dict[str, Any]):
        """Test validation of a valid token."""
        token = jwt_service.create_access_token(data=user_claims)

        payload = jwt_service.decode_token(token)

        assert payload is not None
        assert payload.sub == "user123"
        assert payload.type == "access"  # Verify token type

    @freeze_time("2025-03-27 12:00:00")
    @pytest.mark.asyncio
    async def test_decode_token_expired(self, jwt_service: JWTServiceImpl, user_claims: dict[str, Any]):
        """Test validation of an expired token."""
        # Create a token that is already expired
        expired_token = jwt_service.create_access_token(
            data=user_claims,
            expires_delta_minutes=-1,  # Ensure it's expired relative to frozen time
        )

        # No need to sleep or fast-forward time, decode should fail immediately
        with pytest.raises(TokenExpiredError):
            jwt_service.decode_token(expired_token)

    @pytest.mark.asyncio
    async def test_decode_token_invalid_signature(
        self, jwt_service: JWTServiceImpl, user_claims: dict[str, Any]
    ):
        """Test validation of a token with invalid signature."""
        token = jwt_service.create_access_token(data=user_claims)

        # Tamper with the signature
        tampered_token = token[:-5] + "XXXXX"

        with pytest.raises(InvalidTokenError) as exc_info:
            jwt_service.decode_token(tampered_token)
        assert "Signature verification failed" in str(exc_info.value) or "Invalid signature" in str(
            exc_info.value
        )

    @pytest.mark.asyncio
    async def test_decode_token_invalid_format(self, jwt_service: JWTServiceImpl):
        """Test validation of a token with invalid format."""
        invalid_token = "not.a.valid.jwt.token.format"

        with pytest.raises(InvalidTokenError) as exc_info:
            jwt_service.decode_token(invalid_token)
        assert "Invalid header string" in str(exc_info.value) or "Not enough segments" in str(
            exc_info.value
        )

    @freeze_time("2025-03-27 12:00:00")
    @pytest.mark.asyncio
    async def test_token_expiry_time(self, jwt_service: JWTServiceImpl, user_claims: dict[str, Any]):
        """Test that the token expiry time matches the expected duration."""
        token = jwt_service.create_access_token(data=user_claims)

        # Decode the token to check expiry
        payload = jwt_service.decode_token(token)

        # Calculate expected expiry timestamp
        expected_expiry_ts = (
            datetime.datetime.now(UTC) + datetime.timedelta(minutes=TEST_ACCESS_EXPIRE_MINUTES)
        ).timestamp()

        # Allow for a small delta (e.g., 1 second) due to processing time
        assert payload.exp == pytest.approx(expected_expiry_ts, abs=1)

    @pytest.mark.asyncio
    async def test_token_audience_validation(
        self, jwt_service: JWTServiceImpl, user_claims: dict[str, Any]
    ):
        """Test token audience validation."""
        # Original audience from settings
        original_audience = jwt_service.audience

        # Test with correct audience
        token_correct_aud = jwt_service.create_access_token(data=user_claims)
        payload_correct = jwt_service.decode_token(token_correct_aud)
        assert payload_correct.aud == TEST_AUDIENCE

        # For invalid audience test, create a token with a different audience
        # First, create a new JWT service with different audience
        modified_settings = MagicMock(spec=Settings)

        # Copy all properties from the original mock
        for key, value in vars(jwt_service.settings).items():
            setattr(modified_settings, key, value)

        # Override the audience
        modified_settings.JWT_AUDIENCE = "wrong_audience"

        # Create new service with modified settings
        wrong_aud_service = JWTServiceImpl(
            secret_key=TEST_SECRET_KEY,
            algorithm=TEST_ALGORITHM,
            access_token_expire_minutes=TEST_ACCESS_EXPIRE_MINUTES,
            refresh_token_expire_days=TEST_REFRESH_EXPIRE_DAYS,
            issuer=TEST_ISSUER,
            audience="wrong-audience",  # Different audience
            token_blacklist_repository=None,
            user_repository=None,
            audit_logger=None,
            settings=modified_settings
        )

        # Create token with wrong audience
        token_wrong_aud = wrong_aud_service.create_access_token(data=user_claims)

        # Attempt to decode with original service (expecting original audience)
        # This should fail now with our fixed verification
        with pytest.raises(InvalidTokenError) as exc_info:
            jwt_service.decode_token(token_wrong_aud)

        assert (
            "Invalid audience" in str(exc_info.value) or "audience" in str(exc_info.value).lower()
        )

    @freeze_time("2023-01-01 12:00:00")
    def test_token_issuer_validation(self):
        """Test issuer validation."""
        # Create JWT service with a specific issuer
        jwt_service = JWTServiceImpl(
            secret_key="test-secret",
            algorithm="HS256",
            issuer="test-issuer.com"
        )
        
        # Create a token with the correct issuer
        subject = "user123"
        token_correct_iss = jwt_service.create_access_token(subject=subject)
        
        # Create another service with a different issuer
        jwt_service_wrong_iss = JWTServiceImpl(
            secret_key="test-secret",
            algorithm="HS256",
            issuer="wrong-issuer.com"
        )
        
        # Create a token with the wrong issuer
        token_wrong_iss = jwt_service_wrong_iss.create_access_token(subject=subject)
        
        # Validate token with correct issuer - should pass
        # Disable nbf validation to avoid time-related issues in tests
        options = {"verify_nbf": False}
        payload = jwt_service.decode_token(token_correct_iss, options=options)
        assert payload.sub == subject
        assert payload.iss == "test-issuer.com"
        
        # Validate token with wrong issuer - should fail
        with pytest.raises(InvalidTokenError) as exc_info:
            jwt_service.decode_token(token_wrong_iss, options=options)
        
        # Check error message contains issuer-related text
        error_msg = str(exc_info.value)
        assert "issuer" in error_msg.lower() or "iss" in error_msg.lower()

    # Add more tests as needed, e.g., for blacklisting, etc.

    @pytest.mark.asyncio
    @freeze_time("2023-01-01 12:00:00")
    async def test_refresh_token_family(self):
        """Test family token creation and validation."""
        # Create a family of refresh tokens
        user_id = "family-test-user"
        family_id = str(uuid.uuid4())
        
        # Create first token in the family
        token1 = self.jwt_service.create_refresh_token(
            subject=user_id,
            additional_claims={"family_id": family_id}
        )
        
        # Create second token in the same family
        token2 = self.jwt_service.create_refresh_token(
            subject=user_id,
            additional_claims={"family_id": family_id}
        )
        
        # Create a token in a different family
        different_family_id = str(uuid.uuid4())
        token3 = self.jwt_service.create_refresh_token(
            subject=user_id,
            additional_claims={"family_id": different_family_id}
        )
        
        # Verify that tokens can be decoded properly - disable expiration and nbf checks for test
        options = {"verify_exp": False, "verify_nbf": False}
        payload1 = self.jwt_service.decode_token(token1, options=options)
        payload2 = self.jwt_service.decode_token(token2, options=options)
        payload3 = self.jwt_service.decode_token(token3, options=options)
        
        # Verify family ID was correctly set
        assert payload1.family_id == family_id
        assert payload2.family_id == family_id
        assert payload3.family_id == different_family_id
        
        # Verify token types
        assert payload1.type == "refresh"
        assert payload2.type == "refresh"
        assert payload3.type == "refresh"
        
        # Verify all tokens have the same subject
        assert payload1.sub == user_id
        assert payload2.sub == user_id
        assert payload3.sub == user_id
