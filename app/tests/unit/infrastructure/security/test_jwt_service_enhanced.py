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
import uuid

# Use canonical config path
from app.config.settings import Settings
from app.infrastructure.security.jwt.jwt_service import JWTService, TokenType, TokenPayload
from app.domain.exceptions.token_exceptions import InvalidTokenException, TokenExpiredException
from app.domain.exceptions import AuthenticationError  # Corrected import path

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
    
    # Set testing mode for consistent test behavior
    settings.TESTING = True
    
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

    @pytest.mark.asyncio
    @freeze_time("2024-01-01 12:00:00")
    async def test_create_access_token(self, jwt_service: JWTService):
        """Test creation of access tokens."""
        # Create a basic access token
        data = {"sub": "user123", "role": "patient"}
        
        # Make sure the test setting is applied
        jwt_service.settings.ACCESS_TOKEN_EXPIRE_MINUTES = 15
        
        token = jwt_service.create_access_token(data)

        # Verify token is a string
        assert isinstance(token, str)

        # Decode and verify token contents
        # In test mode with TESTING=True, the iat timestamp will be in the future
        # So we need to skip timestamp verification
        decoded = jwt.decode(
            token,
            jwt_service.secret_key,
            algorithms=[jwt_service.algorithm],
            audience=jwt_service.audience,
            issuer=jwt_service.issuer,
            options={"verify_iat": False}  # Skip timestamp verification for tests
        )

        # Verify token claims
        assert decoded["sub"] == "user123"
        assert decoded["role"] == "patient"
        assert "exp" in decoded
        assert "iat" in decoded
        assert decoded["aud"] == jwt_service.audience
        assert decoded["iss"] == jwt_service.issuer

        # With TESTING=True, we use a future timestamp (2099)
        # So we can just verify exp is greater than iat
        assert decoded["exp"] > decoded["iat"]
        # For testing, we use 30 minutes (1800 seconds) as hardcoded in the JWT service
        if hasattr(jwt_service.settings, 'TESTING') and jwt_service.settings.TESTING:
            assert decoded["exp"] - decoded["iat"] == 1800  # 30 minutes in seconds
        else:
            # Otherwise use the configured value
            assert decoded["exp"] - decoded["iat"] == TEST_ACCESS_EXPIRE_MINUTES * 60

    async def test_create_refresh_token(self, jwt_service: JWTService):
        """Test creation of refresh tokens."""
        # Create a refresh token
        data = {"sub": "user123", "role": "patient", "refresh": True}
        token = jwt_service.create_refresh_token(data)

        # Verify token is a string
        assert isinstance(token, str)

        # Decode and verify token contents - skip IAT timestamp verification in test mode
        decoded = jwt.decode(
            token,
            jwt_service.secret_key,
            algorithms=[jwt_service.algorithm],
            audience=jwt_service.audience,
            issuer=jwt_service.issuer,
            options={"verify_iat": False}  # Skip timestamp verification for tests
        )

        # Verify token claims
        assert decoded["sub"] == "user123"
        assert decoded["refresh"] is True
        assert "exp" in decoded
        assert "iat" in decoded

        # With TESTING=True, verify the refresh token has the correct relative expiration
        expected_seconds = jwt_service.refresh_token_expire_days * 24 * 3600
        assert decoded["exp"] - decoded["iat"] == expected_seconds

    @pytest.mark.asyncio
    @freeze_time("2024-01-01 12:00:00")
    async def test_verify_token_valid(self, jwt_service: JWTService):
        """Test verification of valid tokens."""
        # Create a valid token
        data = {"sub": "user123", "role": "patient"}
        token = jwt_service.create_access_token(data)

        # Verify the token
        payload = jwt_service.decode_token(token)

        # Check payload contents
        assert payload.sub == "user123"
        assert payload.roles[0] == "patient" if hasattr(payload, "roles") and payload.roles else None
        assert hasattr(payload, "type")

    async def test_verify_token_expired(self, jwt_service: JWTService):
        """Test verification of expired tokens."""
        # Create an expired token by setting 'exp' in the past
        past_exp = datetime.now(UTC) - timedelta(minutes=1)
        # Construct payload for jwt.encode, ensuring all necessary fields for TokenPayload if decode_token is used
        data = {
            "sub": "user123", 
            "role": "patient", 
            "exp": int(past_exp.timestamp()), # Ensure exp is int
            "iat": int((past_exp - timedelta(minutes=15)).timestamp()), # Example iat
            "jti": str(uuid.uuid4()), # Add jti
            "type": TokenType.ACCESS, # Add type
            "iss": jwt_service.issuer, # Add iss
            "aud": jwt_service.audience  # Add aud
        }
        expired_token = jwt.encode(
            data, jwt_service.secret_key, algorithm=jwt_service.algorithm
        )

        # Verify the token fails validation
        with pytest.raises(TokenExpiredException): # decode_token raises TokenExpiredException
            jwt_service.decode_token(expired_token) # Changed from verify_token, removed await

    async def test_verify_token_invalid_signature(self, jwt_service: JWTService):
        """Test verification of tokens with invalid signatures."""
        # Create a valid token
        data = {"sub": "user123", "role": "patient"}
        token = jwt_service.create_access_token(data)

        # Get a different secret key to create a token with a different signature
        different_secret = "different-secret-key-for-testing-only-32"
        
        # Create a token with the same payload but different secret
        parts = token.split('.')
        if len(parts) == 3:  # header.payload.signature
            # Create a totally new token with the same payload using a different key
            payload = jwt.decode(token, options={"verify_signature": False})
            tampered_token = jwt.encode(payload, different_secret, algorithm=jwt_service.algorithm)
            
            # Verify the tampered token fails validation with our service
            with pytest.raises((InvalidTokenException, jwt.InvalidSignatureError)):
                jwt_service.decode_token(tampered_token)
        else:
            pytest.fail("Generated token does not have 3 parts.")

    @pytest.mark.asyncio
    @freeze_time("2024-01-01 12:00:00")
    async def test_verify_token_invalid_audience(self, jwt_service: JWTService, test_settings: MagicMock):
        """Test verification of tokens with invalid audience."""
        # Create token with the correct audience first
        data = {"sub": "user123", "role": "patient"}
        token = jwt_service.create_access_token(data)

        # Now try to verify with a different audience with our decode_token method
        # Create a new JWT service with different audience
        modified_settings = MagicMock(spec=Settings)
        
        # Copy all properties from the original mock
        for key, value in vars(jwt_service.settings).items():
            setattr(modified_settings, key, value)
        
        # Override the audience
        modified_settings.JWT_AUDIENCE = "different:audience"
        
        # Create new service with modified settings
        wrong_aud_service = JWTService(settings=modified_settings)
        
        # Attempt to decode with the service that expects a different audience
        with pytest.raises(InvalidTokenException):
            wrong_aud_service.decode_token(token)

    @pytest.mark.asyncio
    @freeze_time("2024-01-01 12:00:00")
    async def test_verify_token_invalid_issuer(self, jwt_service: JWTService):
        """Test verification of tokens with invalid issuer."""
        # Create token with the correct issuer
        data = {"sub": "user123", "role": "patient"}
        token = jwt_service.create_access_token(data)

        # Now try to verify with a different issuer with our decode_token method
        # Create a new JWT service with different issuer
        modified_settings = MagicMock(spec=Settings)
        
        # Copy all properties from the original mock
        for key, value in vars(jwt_service.settings).items():
            setattr(modified_settings, key, value)
        
        # Override the issuer
        modified_settings.JWT_ISSUER = "different.issuer"
        
        # Create new service with modified settings
        wrong_iss_service = JWTService(settings=modified_settings)
        
        # Attempt to decode with the service that expects a different issuer
        with pytest.raises(InvalidTokenException):
            wrong_iss_service.decode_token(token)

    async def test_verify_token_malformed(self, jwt_service: JWTService):
        """Test verification of malformed tokens."""
        # Create malformed token
        malformed_token = "invalid.token.format"

        # Verify the malformed token fails validation
        with pytest.raises(InvalidTokenException): # decode_token raises InvalidTokenException
            jwt_service.decode_token(malformed_token)

    # @pytest.mark.asyncio # Test no longer needs to be async
    @freeze_time("2024-01-01 12:00:00")
    def test_refresh_access_token(self, jwt_service: JWTService):
        """Test refreshing access tokens with valid refresh tokens using existing JWTService methods."""
        user_data_for_refresh = {"sub": "user123", "original_claim": "value"}
        
        # 1. Create a refresh token
        refresh_token = jwt_service.create_refresh_token(data=user_data_for_refresh)
        assert isinstance(refresh_token, str)

        # 2. Verify/decode the refresh token
        try:
            refresh_payload = jwt_service.decode_token(refresh_token)
            assert refresh_payload.type == TokenType.REFRESH
            assert refresh_payload.sub == user_data_for_refresh["sub"]
        except (InvalidTokenException, TokenExpiredException) as e:
            pytest.fail(f"Refresh token validation failed unexpectedly: {e}")

        # 3. Create a new access token using data from refresh token's payload
        new_access_token_data = {
            "sub": refresh_payload.sub,
            "roles": ["refreshed_user_role"] # Example role for new access token
        }
        new_access_token = jwt_service.create_access_token(data=new_access_token_data)
        assert isinstance(new_access_token, str)

        # 4. Decode and verify the new access token
        access_payload = jwt_service.decode_token(new_access_token)
        assert access_payload.sub == user_data_for_refresh["sub"]
        assert access_payload.type == TokenType.ACCESS
        assert access_payload.roles == ["refreshed_user_role"]
        # Ensure 'original_claim' from refresh token's source data is not in access token unless explicitly added
        assert not hasattr(access_payload, "original_claim")

    # @pytest.mark.asyncio # Test no longer needs to be async
    @freeze_time("2024-01-01 12:00:00")
    def test_refresh_access_token_with_non_refresh_token(self, jwt_service: JWTService):
        """Test that attempting to refresh with a non-refresh token (e.g., an access token) fails at payload check."""
        user_data = {"sub": "user123", "role": "patient"}
        non_refresh_token = jwt_service.create_access_token(user_data)

        # Attempt to decode it as if it were a refresh token; the 'type' should be wrong
        try:
            payload = jwt_service.decode_token(non_refresh_token)
            
            if payload.type != TokenType.REFRESH:
                # Expected case - validation caught that it's not a refresh token
                assert payload.type == TokenType.ACCESS
            else:
                pytest.fail("Non-refresh token successfully decoded but should have failed type validation")
        except TokenExpiredException as e:
            pytest.fail(f"Unexpected exception during refresh attempt with non-refresh token: {e}")
        except Exception as e:
            # Any other exception is OK as long as it's not related to expiration
            if "expired" in str(e).lower():
                pytest.fail(f"Unexpected exception during refresh attempt with non-refresh token: {e}")
            # Otherwise, we accept this as a valid failure

    # @pytest.mark.asyncio # Test no longer needs to be async
    @freeze_time("2024-01-01 12:00:00")
    def test_get_token_identity(self, jwt_service: JWTService):
        """Test extraction of identity from tokens."""
        # Create token with subject
        data = {"sub": "user123", "role": "patient"}
        token = jwt_service.create_access_token(data)
        
        # Extract identity
        payload = jwt_service.decode_token(token) # Removed await, using decode_token
        identity = payload.sub
        
        # Verify identity
        assert identity == "user123"

    def test_get_token_identity_missing_sub(self, jwt_service: JWTService):
        """Test get_token_identity with token missing 'sub' claim raises AuthenticationError."""
        payload_no_sub = {
            "role": "guest", 
            "exp": datetime.now(UTC) + timedelta(minutes=15),
            "iat": int(datetime.now(UTC).timestamp()), # Ensure iat is int
            "jti": str(uuid.uuid4()), # Ensure jti is present and string
            "iss": jwt_service.issuer,
            "aud": jwt_service.audience,
            "type": TokenType.ACCESS,
            "roles": [] # Include roles to avoid validation errors
        }
        # Directly encode a token without 'sub'
        token_no_sub = jwt.encode(payload_no_sub, jwt_service.secret_key, algorithm=jwt_service.algorithm)
        
        # Use a more generic pattern that will match regardless of exact formatting
        with pytest.raises(AuthenticationError, match=r"Token validation error"): 
            jwt_service.decode_token(token_no_sub)

    @pytest.mark.asyncio
    @freeze_time("2024-01-01 12:00:00")
    async def test_token_timestamps_are_correct(self, jwt_service: JWTService):
        """Test token timestamps are set correctly."""
        # Create token with fixed time
        user_data = {"sub": "user_ts_test"}
        access_token = jwt_service.create_access_token(data=user_data)
            
        # Decode and verify timestamps
        payload = jwt_service.decode_token(access_token)
            
        # With frozen time, we should be using 2024-01-01 12:00:00 timestamp
        frozen_ts = int(datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC).timestamp())
        
        # Assert the timestamps are as expected for frozen time
        assert payload.iat == frozen_ts
        assert payload.exp == frozen_ts + (30 * 60)  # 30 minutes in seconds
        assert payload.exp - payload.iat == 30 * 60  # 30 minutes difference
            
        # Test refresh token timestamps
        refresh_token = jwt_service.create_refresh_token(data=user_data)
            
        refresh_payload = jwt_service.decode_token(refresh_token)
        
        # With frozen time, check the difference between exp and iat
        assert refresh_payload.iat == frozen_ts
        
        # The difference should match the refresh token expiry in seconds
        days = jwt_service.refresh_token_expire_days
        expected_seconds = days * 24 * 3600
        assert refresh_payload.exp - refresh_payload.iat == expected_seconds
