"""
Redis implementation of the token blacklist repository.

This module provides a Redis-based implementation of the ITokenBlacklistRepository interface,
using Redis' expiry features to automatically manage token lifetimes.
"""

import json
from datetime import datetime, timezone

from fastapi import Depends

from app.core.interfaces.repositories.token_blacklist_repository_interface import (
    ITokenBlacklistRepository,
)
from app.infrastructure.services.redis_service import RedisService, get_redis_service


class RedisTokenBlacklistRepository(ITokenBlacklistRepository):
    """Redis-based implementation of token blacklist repository.

    This implementation uses Redis as the storage mechanism for blacklisted tokens,
    taking advantage of Redis' built-in expiry functionality to automatically
    clean up expired tokens, with an additional manual cleanup method.
    """

    def __init__(self, redis_service: RedisService):
        """Initialize the Redis token blacklist repository.

        Args:
            redis_service: Redis service for interacting with Redis
        """
        self._redis = redis_service
        self._key_prefix = "token_blacklist:"

    def _get_full_key(self, token_jti: str) -> str:
        """Get the full Redis key for a token JTI.

        Args:
            token_jti: JWT ID

        Returns:
            str: Full Redis key
        """
        return f"{self._key_prefix}{token_jti}"

    async def add_to_blacklist(self, token_jti: str, expires_at: datetime) -> None:
        """Add a token to the blacklist with its expiration time.

        Args:
            token_jti: JWT ID to blacklist
            expires_at: When the token would normally expire
        """
        # Calculate TTL in seconds
        now = datetime.now(timezone.utc)
        if expires_at <= now:
            # Token already expired, no need to blacklist
            return

        ttl_seconds = int((expires_at - now).total_seconds())
        token_data = json.dumps({"jti": token_jti, "expires_at": expires_at.isoformat()})

        # Store in Redis with automatic expiration
        await self._redis.set(self._get_full_key(token_jti), token_data, ex=ttl_seconds)

    async def is_blacklisted(self, token_jti: str) -> bool:
        """Check if a token is blacklisted.

        Args:
            token_jti: JWT ID to check

        Returns:
            bool: True if token is blacklisted, False otherwise
        """
        result = await self._redis.get(self._get_full_key(token_jti))
        return result is not None

    async def remove_expired(self) -> int:
        """Remove expired tokens from the blacklist.

        This is generally unnecessary with Redis TTL, but can be used for maintenance.

        Returns:
            int: Number of expired tokens removed
        """
        # Get all blacklisted tokens
        pattern = f"{self._key_prefix}*"
        keys = await self._redis.keys(pattern)

        removed_count = 0
        now = datetime.now(timezone.utc)

        for key in keys:
            # Check if token is already expired but not auto-removed yet
            token_data_str = await self._redis.get(key)
            if token_data_str:
                try:
                    token_data = json.loads(token_data_str)
                    expires_at = datetime.fromisoformat(token_data["expires_at"])

                    if expires_at <= now:
                        # Expired, remove manually
                        await self._redis.delete(key)
                        removed_count += 1
                except (json.JSONDecodeError, KeyError, ValueError):
                    # Invalid data, remove it
                    await self._redis.delete(key)
                    removed_count += 1

        return removed_count

    async def get_all_blacklisted(self) -> list[dict]:
        """Get all blacklisted tokens.

        Returns:
            List[dict]: List of dictionaries containing token_jti and expires_at
        """
        pattern = f"{self._key_prefix}*"
        keys = await self._redis.keys(pattern)

        result = []
        for key in keys:
            token_data_str = await self._redis.get(key)
            if token_data_str:
                try:
                    token_data = json.loads(token_data_str)
                    token_data["key"] = key.decode("utf-8").replace(self._key_prefix, "")
                    result.append(token_data)
                except (json.JSONDecodeError, KeyError):
                    # Skip invalid data
                    continue

        return result

    async def remove_from_blacklist(self, token_jti: str) -> bool:
        """Remove a token from the blacklist.

        Args:
            token_jti: JWT ID to remove

        Returns:
            bool: True if token was removed, False if not found
        """
        key = self._get_full_key(token_jti)
        result = await self._redis.delete(key)
        return result > 0


async def get_token_blacklist_repository(
    redis_service: RedisService = Depends(get_redis_service),
) -> ITokenBlacklistRepository:
    """Dependency provider for token blacklist repository.

    Args:
        redis_service: Redis service dependency

    Returns:
        ITokenBlacklistRepository: Token blacklist repository implementation
    """
    return RedisTokenBlacklistRepository(redis_service)
