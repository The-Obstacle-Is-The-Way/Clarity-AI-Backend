"""Unit tests for JWT Service functionality.

This module tests the JWT service that handles authentication tokens,
a critical component for HIPAA-compliant user authentication and authorization.
"""

import datetime
from datetime import timezone
from typing import Any
from unittest.mock import MagicMock

import asyncio
import pytest
from app.tests.utils.asyncio_helpers import run_with_timeout
from freezegun import freeze_time

from app.config.settings import Settings  # Import actual Settings
from app.domain.exceptions import InvalidTokenException, TokenExpiredException
from app.domain.exceptions.base_exceptions import AuthenticationError

# Corrected imports
from app.infrastructure.security.jwt.jwt_service import JWTService, TokenPayload

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
    UTC = timezone.utc # Fallback for older Python versions


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
    mock_jwt_secret_key.get_secret_value.return_value = TEST_SECRET_KEY # Use same key for simplicity
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
    return None # Or MagicMock(spec=IUserRepository) if interactions are needed

@pytest.fixture
def jwt_service(mock_settings: Settings, mock_user_repository) -> JWTService:
    """Create a JWT service instance for testing using mock settings."""
    # Instantiate JWTService with mock settings and repository
    service = JWTService(
        settings=mock_settings,
        user_repository=mock_user_repository
    )
    # No need to set refresh_token_expire_days directly anymore
    return service

@pytest.fixture
def user_claims() -> dict[str, Any]:
    """Create test user claims."""
    return {
        "sub": "user123",
        "user_id": "user123", # Include user_id if create_access_token expects it
        "name": "Dr. Jane Smith",
        "email": "jane.smith@example.com",
        "roles": ["psychiatrist"],
        "permissions": ["read:patient", "write:clinical_note", "prescribe:medication"]
    }


class TestJWTService:
    """Test suite for the JWT service."""

    @pytest.mark.asyncio
    async def test_create_access_token(self, jwt_service: JWTService, user_claims: dict[str, Any]):
        """Test creating an access token with user claims."""
        # Pass necessary data directly to create_access_token
        access_token = jwt_service.create_access_token(
            data=user_claims 
        )

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
    async def test_create_refresh_token(self, jwt_service: JWTService, user_claims: dict[str, Any]):
        """Test creating a refresh token with user claims."""
        # Pass necessary data directly to create_refresh_token
        refresh_token = jwt_service.create_refresh_token(
            data=user_claims # Pass relevant subset if needed
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
    async def test_decode_token_valid(self, jwt_service: JWTService, user_claims: dict[str, Any]):
        """Test validation of a valid token."""
        token = jwt_service.create_access_token(data=user_claims)
        
        payload = jwt_service.decode_token(token)

        assert payload is not None
        assert payload.sub == "user123"
        assert payload.type == "access" # Verify token type


    @freeze_time("2025-03-27 12:00:00")
    @pytest.mark.asyncio
    async def test_decode_token_expired(self, jwt_service: JWTService, user_claims: dict[str, Any]):
        """Test validation of an expired token."""
        # Create a token that is already expired
        expired_token = jwt_service.create_access_token(
            data=user_claims,
            expires_delta_minutes=-1 # Ensure it's expired relative to frozen time
        )

        # No need to sleep or fast-forward time, decode should fail immediately
        with pytest.raises(TokenExpiredException):
            jwt_service.decode_token(expired_token)


    @pytest.mark.asyncio
    async def test_decode_token_invalid_signature(self, jwt_service: JWTService, user_claims: dict[str, Any]):
        """Test validation of a token with invalid signature."""
        token = jwt_service.create_access_token(data=user_claims)
        
        # Tamper with the signature
        tampered_token = token[:-5] + "XXXXX"

        with pytest.raises(InvalidTokenException) as exc_info:
            jwt_service.decode_token(tampered_token)
        assert "Signature verification failed" in str(exc_info.value) or "Invalid signature" in str(exc_info.value)


    @pytest.mark.asyncio
    async def test_decode_token_invalid_format(self, jwt_service: JWTService):
        """Test validation of a token with invalid format."""
        invalid_token = "not.a.valid.jwt.token.format"

        with pytest.raises(InvalidTokenException) as exc_info:
            jwt_service.decode_token(invalid_token)
        assert "Invalid header string" in str(exc_info.value) or "Not enough segments" in str(exc_info.value)


    @freeze_time("2025-03-27 12:00:00")
    @pytest.mark.asyncio
    async def test_token_expiry_time(self, jwt_service: JWTService, user_claims: dict[str, Any]):
        """Test that the token expiry time matches the expected duration."""
        token = jwt_service.create_access_token(data=user_claims)
        
        # Decode the token to check expiry
        payload = jwt_service.decode_token(token)
        
        # Calculate expected expiry timestamp
        expected_expiry_ts = (datetime.datetime.now(UTC) + datetime.timedelta(minutes=TEST_ACCESS_EXPIRE_MINUTES)).timestamp()
        
        # Allow for a small delta (e.g., 1 second) due to processing time
        assert payload.exp == pytest.approx(expected_expiry_ts, abs=1)


    @pytest.mark.asyncio
    async def test_token_audience_validation(self, jwt_service: JWTService, user_claims: dict[str, Any]):
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
        wrong_aud_service = JWTService(settings=modified_settings)
        
        # Create token with wrong audience
        token_wrong_aud = wrong_aud_service.create_access_token(data=user_claims)
        
        # Attempt to decode with original service (expecting original audience)
        # This should fail now with our fixed verification
        with pytest.raises(InvalidTokenException) as exc_info:
            jwt_service.decode_token(token_wrong_aud)
        
        assert "Invalid audience" in str(exc_info.value) or "audience" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_token_issuer_validation(self, jwt_service: JWTService, user_claims: dict[str, Any]):
        """Test token issuer validation."""
        # Arrange
        wrong_issuer_jwt = JWTService(
            secret_key=jwt_service.secret_key,
            algorithm=jwt_service.algorithm,
            issuer="wrong-issuer"
        )
        
        data = {"sub": "user123"}
        token_wrong_iss = wrong_issuer_jwt.create_access_token(data)
        
        # Act & Assert
        with pytest.raises(InvalidTokenException, match="Invalid issuer"):
            jwt_service.decode_token(token_wrong_iss)

    # Add more tests as needed, e.g., for blacklisting, etc.

    @pytest.mark.asyncio
    async def test_refresh_token_family(self, jwt_service: JWTService, user_claims: dict[str, Any]):
        """Test refresh token family functionality."""
        # Arrange
        user_id = "user123"
        data = {
            "sub": user_id,
            "name": "John Doe",  # PHI field that should be removed
            "email": "john@example.com",  # PHI field that should be removed
            "role": "admin",
        }
        
        # Act - Create initial refresh token
        refresh_token = jwt_service.create_refresh_token(data)
        
        # Decode the token to get payload (without verification)
        from jose import jwt
        payload = jwt.decode(
            refresh_token, 
            jwt_service.secret_key,  # Use the service's secret key
            options={"verify_signature": False, "verify_exp": False}
        )
        
        # Assert that the family_id field is present in the token payload
        assert "family_id" in payload
        
        # Generate new token using the first token
        new_refresh_token = jwt_service.refresh_token(refresh_token)
        
        # Decode the new token
        new_payload = jwt.decode(
            new_refresh_token, 
            jwt_service.secret_key,  # Use the service's secret key
            options={"verify_signature": False, "verify_exp": False}
        )
        
        # Assert that the family ID is the same 
        assert new_payload.get("family_id") == payload.get("family_id")
        
        # Assert that the new token has a different JTI
        assert new_payload.get("jti") != payload.get("jti")
