"""
Redis-based Token Blacklist Repository.

This module provides a concrete implementation of the token blacklist repository
interface using Redis as the storage backend. This implementation is designed
for production use to properly manage token invalidation for HIPAA compliance.
"""

import hashlib
from datetime import UTC, datetime

from app.core.interfaces.repositories.token_blacklist_repository_interface import (
    ITokenBlacklistRepository,
)
from app.domain.exceptions.repository import RepositoryException
from app.infrastructure.logging.logger import get_logger

# Import RedisCacheService from the correct path
from app.infrastructure.services.redis.redis_cache_service import RedisCacheService

logger = get_logger(__name__)


class RedisTokenBlacklistRepository(ITokenBlacklistRepository):
    """
    Redis-based implementation of token blacklist repository.

    This implementation uses Redis for storing blacklisted tokens with
    automatic expiration through Redis TTL mechanism. It supports:
    - Adding tokens to blacklist
    - Checking if tokens are blacklisted
    - Blacklisting all tokens for a session
    - Automatic cleanup of expired tokens
    """

    def __init__(self, redis_service: RedisCacheService):
        """
        Initialize the Redis token blacklist repository.

        Args:
            redis_service: Redis service for storage operations
        """
        self._redis = redis_service
        # Redis key prefixes for different blacklist types
        self._token_prefix = "blacklist:token:"
        self._jti_prefix = "blacklist:jti:"
        self._session_prefix = "blacklist:session:"
        logger.info("RedisTokenBlacklistRepository initialized")

    async def add_to_blacklist(
        self, token: str, jti: str, expires_at: datetime, reason: str | None = None
    ) -> None:
        """
        Add a token to the blacklist.

        Args:
            token: The token to blacklist (typically a hash of the token)
            jti: JWT ID - unique identifier for the token
            expires_at: When the token expires
            reason: Reason for blacklisting

        Raises:
            RepositoryException: If blacklisting fails
        """
        try:
            # Calculate remaining seconds until expiration
            now = datetime.now(UTC)
            if expires_at <= now:
                # Token already expired, no need to blacklist
                logger.debug(f"Token {jti} already expired, skipping blacklist")
                return

            seconds_until_expiry = int((expires_at - now).total_seconds())
            # Add a small buffer (1 hour) to ensure token remains blacklisted
            # even in case of clock skew between servers
            expiry_buffer = 3600  # 1 hour in seconds
            ttl = seconds_until_expiry + expiry_buffer

            # Store token hash
            token_hash = self._hash_token(token)
            token_key = f"{self._token_prefix}{token_hash}"
            await self._redis.set(token_key, jti, ttl=ttl)

            # Store JTI reference
            jti_key = f"{self._jti_prefix}{jti}"
            jti_data = {
                "expires_at": expires_at.isoformat(),
                "reason": reason or "manual_blacklist",
            }
            await self._redis.set(jti_key, jti_data, ttl=ttl)

            logger.info(f"Token {jti} blacklisted until {expires_at.isoformat()}, reason: {reason}")
        except Exception as e:
            logger.error(f"Failed to blacklist token: {e!s}")
            raise RepositoryException(f"Failed to blacklist token: {e!s}") from e

    async def is_blacklisted(self, token: str) -> bool:
        """
        Check if a token is blacklisted.

        Args:
            token: The token to check (typically a hash of the token)

        Returns:
            True if blacklisted, False otherwise

        Raises:
            RepositoryException: If check fails
        """
        try:
            token_hash = self._hash_token(token)
            token_key = f"{self._token_prefix}{token_hash}"
            result = await self._redis.get(token_key)
            return result is not None
        except Exception as e:
            logger.error(f"Failed to check token blacklist: {e!s}")
            # For security, assume token is blacklisted if check fails
            return True

    async def is_jti_blacklisted(self, jti: str) -> bool:
        """
        Check if a token with specific JWT ID is blacklisted.

        Args:
            jti: JWT ID to check

        Returns:
            True if blacklisted, False otherwise

        Raises:
            RepositoryException: If check fails
        """
        try:
            jti_key = f"{self._jti_prefix}{jti}"
            result = await self._redis.get(jti_key)
            return result is not None
        except Exception as e:
            logger.error(f"Failed to check JTI blacklist: {e!s}")
            # For security, assume JTI is blacklisted if check fails
            return True

    async def blacklist_session(self, session_id: str) -> None:
        """
        Blacklist all tokens for a specific session.

        This doesn't immediately blacklist existing tokens,
        but marks the session as invalid for future validation.

        Args:
            session_id: The session ID to blacklist

        Raises:
            RepositoryException: If blacklisting fails
        """
        try:
            # Default 30-day expiry for session blacklisting
            # (longer than any reasonable token lifetime)
            session_key = f"{self._session_prefix}{session_id}"
            expiry = 30 * 24 * 60 * 60  # 30 days in seconds
            await self._redis.set(
                session_key,
                {"blacklisted_at": datetime.now(UTC).isoformat()},
                ttl=expiry,
            )
            logger.info(f"Session {session_id} blacklisted for 30 days")
        except Exception as e:
            logger.error(f"Failed to blacklist session: {e!s}")
            raise RepositoryException(f"Failed to blacklist session: {e!s}") from e

    async def remove_expired_entries(self) -> int:
        """
        Remove expired entries from the blacklist.

        Redis automatically manages TTL expiration, so this is a no-op
        for this implementation. Included for interface compliance.

        Returns:
            Number of entries removed (always 0 for Redis implementation)

        Raises:
            RepositoryException: If cleanup fails
        """
        # Redis handles TTL expiration automatically
        logger.debug("Expired token cleanup not needed with Redis TTL")
        return 0

    async def clear_expired_tokens(self) -> int:
        """
        Remove expired tokens from the blacklist.

        This should be called periodically to clean up the blacklist.

        Returns:
            The number of tokens removed from the blacklist
        """
        # Redis handles TTL expiration automatically through its built-in TTL mechanism,
        # so this is a no-op implementation for interface compliance.
        logger.debug("Expired token cleanup not needed with Redis TTL - handled automatically")
        return 0

    async def hash_token(self, token: str) -> str:
        """
        Create a secure hash of a token for storage.

        Args:
            token: The token to hash

        Returns:
            str: Hashed token value for secure storage
        """
        # Use SHA-256 for token hashing - secure and suitable for tokens
        hash_obj = hashlib.sha256(token.encode())
        return hash_obj.hexdigest()

    async def get_all_blacklisted(self) -> list[dict]:
        """
        Get all blacklisted tokens.
        
        Returns:
            List[dict]: List of dictionaries containing token_jti and expires_at
        """
        try:
            # Get all keys matching the JTI pattern
            jti_keys = await self._redis.keys(f"{self._jti_prefix}*")
            
            result = []
            for key in jti_keys:
                # Extract the JTI from the key
                jti = key.replace(self._jti_prefix, "")
                
                # Get the expiration timestamp
                expires_at_str = await self._redis.get(key)
                if expires_at_str:
                    try:
                        expires_at = datetime.fromisoformat(expires_at_str)
                        result.append({"token_jti": jti, "expires_at": expires_at})
                    except (ValueError, TypeError):
                        logger.warning(f"Invalid expiration format for JTI {jti}")
            
            return result
        except Exception as e:
            logger.error(f"Error retrieving blacklisted tokens: {e!s}")
            raise RepositoryException(f"Failed to retrieve blacklisted tokens: {e!s}") from e

    async def remove_expired(self) -> int:
        """
        Remove expired tokens from the blacklist to maintain performance.
        
        Returns:
            int: Number of expired tokens removed from blacklist
        """
        try:
            # Current time for comparison
            now = datetime.now(UTC)
            
            # Get all blacklisted tokens
            all_tokens = await self.get_all_blacklisted()
            
            # Filter for expired tokens
            expired_tokens = [token for token in all_tokens if token["expires_at"] < now]
            
            # Remove each expired token
            removed_count = 0
            for token in expired_tokens:
                jti = token["token_jti"]
                removed = await self.remove_from_blacklist(jti)
                if removed:
                    removed_count += 1
            
            logger.info(f"Removed {removed_count} expired tokens from blacklist")
            return removed_count
        except Exception as e:
            logger.error(f"Error removing expired tokens: {e!s}")
            # Don't raise an exception here as this is typically called in background tasks
            return 0

    async def remove_from_blacklist(self, token_jti: str) -> bool:
        """
        Remove a specific token from the blacklist.
        
        Args:
            token_jti: The unique JWT ID to remove
            
        Returns:
            bool: True if token was removed, False if not found
        """
        try:
            # Check if JTI exists in blacklist
            jti_key = f"{self._jti_prefix}{token_jti}"
            exists = await self._redis.exists(jti_key)
            
            if not exists:
                return False
                
            # Remove the JTI entry
            await self._redis.delete(jti_key)
            
            # Also try to remove any token entry if it exists
            # Note: This is a best-effort approach since we may not have the original token
            token_pattern = f"{self._token_prefix}*"
            token_keys = await self._redis.keys(token_pattern)
            
            for key in token_keys:
                # Check if this token entry corresponds to our JTI
                stored_jti = await self._redis.get(key)
                if stored_jti == token_jti:
                    await self._redis.delete(key)
                    break
            
            logger.info(f"Removed token with JTI {token_jti} from blacklist")
            return True
        except Exception as e:
            logger.error(f"Error removing token from blacklist: {e!s}")
            raise RepositoryException(f"Failed to remove token from blacklist: {e!s}") from e
