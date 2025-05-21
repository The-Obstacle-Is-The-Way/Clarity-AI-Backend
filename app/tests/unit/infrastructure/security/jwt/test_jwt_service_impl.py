"""
Unit tests for JWT Service Implementation.

Tests the concrete JWTServiceImpl that implements the IJwtService interface
according to clean architecture principles.
"""

import datetime
from datetime import timezone
from typing import Any, Dict
from unittest.mock import MagicMock

import pytest
from jose import jwt
from pydantic import BaseModel

from app.config.settings import Settings
from app.core.interfaces.repositories.token_blacklist_repository_interface import ITokenBlacklistRepository
from app.core.interfaces.repositories.user_repository_interface import IUserRepository
from app.core.interfaces.services.audit_logger_interface import IAuditLogger
from app.domain.exceptions import InvalidTokenError, TokenExpiredError
from app.infrastructure.security.jwt.jwt_service_impl import JWTServiceImpl

# Test constants
TEST_SECRET_KEY = "test-jwt-secret-key-must-be-at-least-32-chars-long"
TEST_ALGORITHM = "HS256"
TEST_ACCESS_EXPIRE_MINUTES = 15
TEST_REFRESH_EXPIRE_DAYS = 7
TEST_ISSUER = "test_issuer"
TEST_AUDIENCE = "test_audience"

# Define UTC timezone
UTC = timezone.utc


@pytest.fixture
def mock_settings() -> Settings:
    """Create mock settings for JWT service tests."""
    settings = MagicMock(spec=Settings)
    
    # Mock SECRET_KEY as an object with get_secret_value
    mock_secret_key = MagicMock()
    mock_secret_key.get_secret_value.return_value = TEST_SECRET_KEY
    
    # Configure the mock settings with test values
    settings.JWT_SECRET_KEY = mock_secret_key
    settings.JWT_ALGORITHM = TEST_ALGORITHM
    settings.ACCESS_TOKEN_EXPIRE_MINUTES = TEST_ACCESS_EXPIRE_MINUTES
    settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS = TEST_REFRESH_EXPIRE_DAYS
    settings.JWT_ISSUER = TEST_ISSUER
    settings.JWT_AUDIENCE = TEST_AUDIENCE
    
    return settings


@pytest.fixture
def mock_user_repository() -> IUserRepository:
    """Create a mock user repository."""
    return MagicMock(spec=IUserRepository)


@pytest.fixture
def mock_token_blacklist_repository() -> ITokenBlacklistRepository:
    """Create a mock token blacklist repository."""
    return MagicMock(spec=ITokenBlacklistRepository)


@pytest.fixture
def mock_audit_logger() -> IAuditLogger:
    """Create a mock audit logger."""
    return MagicMock(spec=IAuditLogger)


@pytest.fixture
def jwt_service_impl(
    mock_settings: Settings,
    mock_user_repository: IUserRepository,
    mock_token_blacklist_repository: ITokenBlacklistRepository,
    mock_audit_logger: IAuditLogger
) -> JWTServiceImpl:
    """Create a JWT service implementation for testing."""
    return JWTServiceImpl(
        secret_key=TEST_SECRET_KEY,
        algorithm=TEST_ALGORITHM,
        access_token_expire_minutes=TEST_ACCESS_EXPIRE_MINUTES,
        refresh_token_expire_days=TEST_REFRESH_EXPIRE_DAYS,
        user_repository=mock_user_repository,
        token_blacklist_repository=mock_token_blacklist_repository,
        audit_logger=mock_audit_logger,
        issuer=TEST_ISSUER,
        audience=TEST_AUDIENCE,
        settings=mock_settings
    )


@pytest.fixture
def user_claims() -> Dict[str, Any]:
    """Create test user claims."""
    return {
        "sub": "user123",
        "name": "Test User",
        "email": "test@example.com",
        "roles": ["user", "patient"]
    }


class TestJWTServiceImpl:
    """Test suite for the JWT service implementation."""

    def test_initialization(self, jwt_service_impl: JWTServiceImpl):
        """Test JWT service initialization with settings."""
        assert jwt_service_impl.secret_key == TEST_SECRET_KEY
        assert jwt_service_impl.algorithm == TEST_ALGORITHM
        assert jwt_service_impl.access_token_expire_minutes == TEST_ACCESS_EXPIRE_MINUTES
        assert jwt_service_impl.refresh_token_expire_days == TEST_REFRESH_EXPIRE_DAYS
        assert jwt_service_impl.issuer == TEST_ISSUER
        assert jwt_service_impl.audience == TEST_AUDIENCE

    def test_create_access_token(self, jwt_service_impl: JWTServiceImpl, user_claims: Dict[str, Any]):
        """Test creating an access token with user claims."""
        token = jwt_service_impl.create_access_token(
            subject=user_claims["sub"],
            additional_claims={"roles": user_claims["roles"]}
        )
        
        # Token should be a non-empty string
        assert isinstance(token, str)
        assert len(token) > 0
        
        # Verify token contents by decoding manually
        payload = jwt.decode(
            token, 
            TEST_SECRET_KEY,
            algorithms=[TEST_ALGORITHM],
            audience=TEST_AUDIENCE,
            issuer=TEST_ISSUER
        )
        
        # Check token claims
        assert payload["sub"] == user_claims["sub"]
        assert payload["roles"] == user_claims["roles"]
        assert payload["iss"] == TEST_ISSUER
        assert payload["aud"] == TEST_AUDIENCE
        assert "exp" in payload
        assert "iat" in payload
        assert "jti" in payload
        assert payload["type"] == "access"

    def test_create_refresh_token(self, jwt_service_impl: JWTServiceImpl, user_claims: Dict[str, Any]):
        """Test creating a refresh token with user claims."""
        token = jwt_service_impl.create_refresh_token(
            subject=user_claims["sub"]
        )
        
        # Token should be a non-empty string
        assert isinstance(token, str)
        assert len(token) > 0
        
        # Verify token contents by decoding manually
        payload = jwt.decode(
            token, 
            TEST_SECRET_KEY,
            algorithms=[TEST_ALGORITHM],
            audience=TEST_AUDIENCE,
            issuer=TEST_ISSUER
        )
        
        # Check token claims
        assert payload["sub"] == user_claims["sub"]
        assert payload["iss"] == TEST_ISSUER
        assert payload["aud"] == TEST_AUDIENCE
        assert "exp" in payload
        assert "iat" in payload
        assert "jti" in payload
        assert payload["type"] == "refresh"

    def test_decode_token_valid(self, jwt_service_impl: JWTServiceImpl, user_claims: Dict[str, Any]):
        """Test verification of a valid token."""
        token = jwt_service_impl.create_access_token(
            subject=user_claims["sub"],
            additional_claims={"roles": user_claims["roles"]}
        )
        
        # Decode and verify the token
        payload = jwt_service_impl.decode_token(token)
        
        # Check payload contents
        assert payload["sub"] == user_claims["sub"]
        assert payload["roles"] == user_claims["roles"]

    def test_decode_token_expired(self, jwt_service_impl: JWTServiceImpl, user_claims: Dict[str, Any]):
        """Test verification of an expired token."""
        # Create a token that's already expired
        jwt_service_impl.access_token_expire_minutes = -15  # Negative value to ensure expiration
        
        token = jwt_service_impl.create_access_token(
            subject=user_claims["sub"]
        )
        
        # Verification should raise TokenExpiredError
        with pytest.raises(TokenExpiredError):
            jwt_service_impl.decode_token(token)
            
    def test_decode_token_invalid_signature(self, jwt_service_impl: JWTServiceImpl, user_claims: Dict[str, Any]):
        """Test verification of a token with invalid signature."""
        token = jwt_service_impl.create_access_token(
            subject=user_claims["sub"]
        )
        
        # Tamper with the token by changing the last character
        tampered_token = token[:-1] + ('A' if token[-1] != 'A' else 'B')
        
        # Verification should raise InvalidTokenError
        with pytest.raises(InvalidTokenError):
            jwt_service_impl.decode_token(tampered_token)
            
    def test_token_blacklist(self, jwt_service_impl: JWTServiceImpl, user_claims: Dict[str, Any], mock_token_blacklist_repository: ITokenBlacklistRepository):
        """Test token blacklisting."""
        token = jwt_service_impl.create_access_token(
            subject=user_claims["sub"]
        )
        
        # Mock blacklist check to return True (token is blacklisted)
        mock_token_blacklist_repository.is_blacklisted.return_value = True
        
        # Set up the token blacklist to work synchronously in tests
        mock_token_blacklist_repository.is_blacklisted = lambda x: True
        
        # Verification should raise appropriate exception
        with pytest.raises(InvalidTokenError, match="blacklisted"):
            # Need to use a synchronous version for testing or mock the async call
            jwt_service_impl.decode_token(token)
            
        # Since we replaced is_blacklisted with a lambda, we can't verify the call

    def test_audit_logging(self, jwt_service_impl: JWTServiceImpl, user_claims: Dict[str, Any], mock_audit_logger: IAuditLogger):
        """Test audit logging during token operations."""
        # Create a token and verify it to trigger audit logs
        token = jwt_service_impl.create_access_token(
            subject=user_claims["sub"]
        )
        
        # Use the decode_token method which should log security events
        jwt_service_impl.decode_token(token)
        
        # Check that audit logger was called
        assert mock_audit_logger.log_security_event.call_count > 0
