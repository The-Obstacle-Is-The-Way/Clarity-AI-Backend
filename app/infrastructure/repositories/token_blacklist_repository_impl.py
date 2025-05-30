"""
Redis implementation of the token blacklist repository interface.

Provides efficient token blacklisting and validation operations using Redis
for persistence, supporting HIPAA-compliant session management.
"""

import logging
from datetime import datetime, timedelta, timezone

from redis.asyncio import Redis as AsyncRedis
from redis.exceptions import RedisError

from app.core.config.settings import Settings
from app.core.interfaces.repositories.token_blacklist_repository_interface import (
    ITokenBlacklistRepository,
)

logger = logging.getLogger(__name__)

# Redis key prefixes
JTI_PREFIX = "token:blacklist:jti:"
USER_PREFIX = "token:blacklist:user:"
SESSION_PREFIX = "token:blacklist:session:"
TOKEN_PREFIX = "token:blacklist:token:"


class RedisTokenBlacklistRepository(ITokenBlacklistRepository):
    """Redis implementation of token blacklist repository.

    Uses Redis for efficient blacklist operations with support for automatic
    expiration of blacklisted tokens to maintain performance.
    """

    def __init__(
        self,
        redis_client: AsyncRedis | None = None,
        settings: Settings | None = None,
        jwt_secret_key: str | None = None,
        jwt_algorithm: str | None = None,
    ):
        """Initialize the Redis token blacklist repository.

        Args:
            redis_client: Redis client instance for async operations
            settings: Application settings for configuration
            jwt_secret_key: Secret key for JWT decoding (if not using settings)
            jwt_algorithm: Algorithm for JWT decoding (if not using settings)
        """
        self.redis = redis_client

        # Initialize from settings if provided
        if settings is not None:
            self.jwt_secret_key = getattr(
                settings.JWT_SECRET_KEY, "get_secret_value", lambda: settings.JWT_SECRET_KEY
            )()
            self.jwt_algorithm = settings.JWT_ALGORITHM
        else:
            # Direct initialization
            self.jwt_secret_key = jwt_secret_key
            self.jwt_algorithm = jwt_algorithm

        logger.info("Redis token blacklist repository initialized")

    async def add_to_blacklist(self, token_jti: str, expires_at: datetime) -> None:
        """Add a token ID to the blacklist.

        Args:
            token_jti: JWT token ID (jti) to blacklist
            expires_at: When the token expires
        """
        try:
            # Calculate TTL in seconds
            current_time = datetime.now(timezone.utc)
            ttl = int((expires_at - current_time).total_seconds())
            # Ensure positive TTL (min 60 seconds)
            ttl = max(60, ttl)

            # Store in Redis with expiration
            key = f"{JTI_PREFIX}{token_jti}"
            await self.redis.set(key, "1", ex=ttl)
            logger.debug(f"Added token {token_jti} to blacklist with TTL of {ttl} seconds")
        except RedisError as e:
            logger.error(f"Failed to add token to blacklist: {e!s}")
            raise

    async def is_blacklisted(self, token_jti: str) -> bool:
        """Check if a token is blacklisted by its JTI.

        Args:
            token_jti: JWT token ID to check

        Returns:
            True if token is blacklisted
        """
        try:
            key = f"{JTI_PREFIX}{token_jti}"
            result = await self.redis.get(key)
            return result is not None
        except RedisError as e:
            logger.error(f"Failed to check token blacklist: {e!s}")
            return False

    async def remove_expired(self) -> int:
        """Remove expired tokens from the blacklist.

        Redis automatically removes expired keys, but this method
        can be used to force cleanup of any manually tracked expirations.

        Returns:
            Number of tokens removed from blacklist
        """
        # Redis handles expiration automatically, so this is a no-op
        # but included for interface completeness
        return 0

    async def get_all_blacklisted(self) -> list[dict]:
        """Get all blacklisted tokens.

        Returns:
            List of dictionaries containing token_jti and expires_at
        """
        try:
            # Get all blacklisted JTIs
            pattern = f"{JTI_PREFIX}*"
            keys = await self.redis.keys(pattern)

            result = []
            for key in keys:
                # Extract JTI from key
                jti = key.replace(JTI_PREFIX, "")
                # Get TTL to estimate expires_at
                ttl = await self.redis.ttl(key)
                if ttl > 0:
                    expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl)
                    result.append({"token_jti": jti, "expires_at": expires_at})

            return result
        except RedisError as e:
            logger.error(f"Failed to get all blacklisted tokens: {e!s}")
            return []

    async def remove_from_blacklist(self, token_jti: str) -> bool:
        """Remove a specific token from the blacklist.

        Args:
            token_jti: The unique JWT ID to remove

        Returns:
            True if token was removed, False if not found
        """
        try:
            key = f"{JTI_PREFIX}{token_jti}"
            deleted = await self.redis.delete(key)
            return deleted > 0
        except RedisError as e:
            logger.error(f"Failed to remove token from blacklist: {e!s}")
            return False
