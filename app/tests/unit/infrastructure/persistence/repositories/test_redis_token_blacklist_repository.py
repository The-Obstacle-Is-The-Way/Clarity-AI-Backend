"""
Unit tests for Redis Token Blacklist Repository.

This module tests the Redis implementation of token blacklist functionality,
a critical component for HIPAA-compliant authentication and session management.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest

from app.core.interfaces.services.redis_service_interface import IRedisService
from app.infrastructure.security.token.redis_token_blacklist_repository import (
    RedisTokenBlacklistRepository,
)


@pytest.fixture
def mock_redis_service() -> IRedisService:
    """Create a mock Redis service for testing."""
    redis_service = AsyncMock()
    # Mock the necessary Redis methods
    redis_service.set = AsyncMock(return_value=True)
    redis_service.get = AsyncMock(return_value=None)  # Default to not blacklisted
    redis_service.delete = AsyncMock(return_value=1)
    redis_service.exists = AsyncMock(return_value=0)  # Default to key not existing
    redis_service.expire = AsyncMock(return_value=True)
    redis_service.ttl = AsyncMock(return_value=3600)  # Default 1 hour TTL
    redis_service.scan = AsyncMock(return_value=(0, []))  # Empty scan result by default
    return redis_service


@pytest.fixture
def token_blacklist_repo(mock_redis_service: IRedisService) -> RedisTokenBlacklistRepository:
    """Create token blacklist repository with mocked Redis service."""
    return RedisTokenBlacklistRepository(redis_service=mock_redis_service)


@pytest.fixture
def mock_token() -> str:
    """Sample token for testing."""
    return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0LXVzZXIiLCJleHAiOjE2MDAwMDAwMDB9.signature"


@pytest.fixture
def mock_jti() -> str:
    """Sample JWT ID for testing."""
    return "123e4567-e89b-12d3-a456-426614174000"


@pytest.fixture
def future_expiry():
    """Future expiration time for tokens."""
    return datetime.now(timezone.utc) + timedelta(hours=1)


@pytest.fixture
def past_expiry():
    """Past expiration time for tokens."""
    return datetime.now(timezone.utc) - timedelta(minutes=5)


class TestRedisTokenBlacklistRepository:
    """Test suite for Redis-based token blacklist repository."""

    @pytest.mark.asyncio
    async def test_add_to_blacklist(
        self,
        token_blacklist_repo,
        mock_redis_service,
        mock_jti,
        future_expiry,
    ) -> None:
        """Test adding a token to the blacklist."""
        # Act
        await token_blacklist_repo.add_to_blacklist(mock_jti, future_expiry)

        # Assert
        # Should call set once for the JTI
        assert mock_redis_service.set.call_count == 1

        # The call should include the JTI prefix and blacklisted value
        calls = mock_redis_service.set.call_args_list
        assert "blacklist:jti:" in str(calls[0])
        assert "blacklisted" in str(calls[0])

    @pytest.mark.asyncio
    async def test_add_expired_token_to_blacklist(
        self,
        token_blacklist_repo,
        mock_redis_service,
        mock_jti,
        past_expiry,
    ) -> None:
        """Test that expired tokens aren't added to the blacklist."""
        # Act
        await token_blacklist_repo.add_to_blacklist(mock_jti, past_expiry)

        # Assert - Redis set should not be called since token is already expired
        mock_redis_service.set.assert_not_called()

    @pytest.mark.asyncio
    async def test_is_blacklisted_not_found(
        self, token_blacklist_repo, mock_redis_service, mock_token
    ) -> None:
        """Test checking a token that is not blacklisted."""
        # Arrange
        mock_redis_service.get.return_value = None

        # Act
        result = await token_blacklist_repo.is_blacklisted(mock_token)

        # Assert
        assert result is False
        mock_redis_service.get.assert_called_once()

    @pytest.mark.asyncio
    async def test_is_blacklisted_found(self, token_blacklist_repo, mock_redis_service, mock_token) -> None:
        """Test checking a token that is blacklisted."""
        # Arrange
        mock_redis_service.get.return_value = "mock_jti"

        # Act
        result = await token_blacklist_repo.is_blacklisted(mock_token)

        # Assert
        assert result is True
        mock_redis_service.get.assert_called_once()

    @pytest.mark.asyncio
    async def test_is_jti_blacklisted(self, token_blacklist_repo, mock_redis_service, mock_jti) -> None:
        """Test checking if JTI is blacklisted."""
        # Arrange
        mock_redis_service.get.return_value = None

        # Act
        result = await token_blacklist_repo.is_jti_blacklisted(mock_jti)

        # Assert
        assert result is False
        mock_redis_service.get.assert_called_once()
        assert mock_jti in str(mock_redis_service.get.call_args)

    @pytest.mark.asyncio
    async def test_blacklist_session(self, token_blacklist_repo, mock_redis_service, mock_jti) -> None:
        """Test blacklisting a session."""
        # Arrange
        session_id = "test-session-123"

        # Mock the session tokens
        session_tokens = [
            {"jti": mock_jti, "token_hash": "abc123"},
            {"jti": "another-jti", "token_hash": "def456"},
        ]
        mock_redis_service.get.return_value = session_tokens

        # Act
        await token_blacklist_repo.blacklist_session(session_id)

        # Assert
        # Redis set should be called multiple times (for each token)
        assert mock_redis_service.set.call_count > 0
        assert mock_jti in str(mock_redis_service.set.call_args_list)

    @pytest.mark.asyncio
    async def test_remove_expired_entries(self, token_blacklist_repo) -> None:
        """Test removing expired entries (no-op in Redis implementation)."""
        # Act
        result = await token_blacklist_repo.remove_expired_entries()

        # Assert - should always return 0 as Redis handles this automatically
        assert result == 0

    @pytest.mark.asyncio
    async def test_clear_expired_tokens(self, token_blacklist_repo) -> None:
        """Test clearing expired tokens (no-op in Redis implementation)."""
        # Act
        result = await token_blacklist_repo.clear_expired_tokens()

        # Assert - should always return 0 as Redis handles this automatically via TTL
        assert result == 0

    @pytest.mark.asyncio
    async def test_redis_exception_handling(
        self, token_blacklist_repo, mock_redis_service, mock_token
    ) -> None:
        """Test exception handling when Redis operations fail."""
        # Arrange
        mock_redis_service.get.side_effect = Exception("Redis connection error")

        # Act
        result = await token_blacklist_repo.is_blacklisted(mock_token)

        # Assert - for security, should return True (blacklisted) on errors
        assert result is True

    def test_hash_token(self, token_blacklist_repo, mock_token) -> None:
        """Test token hashing function."""
        # Act
        result = token_blacklist_repo._hash_token(mock_token)

        # Assert
        assert result is not None
        assert len(result) == 64  # SHA-256 hexdigest is 64 chars
        assert result != mock_token  # Should not be the same as input
