"""
Redis implementation of the token blacklist repository.

This implementation provides a persistent, distributed token blacklist using Redis,
making it suitable for production use in a HIPAA-compliant environment.
"""

import json
from datetime import datetime
from typing import Optional

import redis.asyncio as redis
from redis.exceptions import RedisError

from app.core.config.settings import get_settings
from app.core.interfaces.repositories.token_blacklist_repository_interface import ITokenBlacklistRepository
from app.core.logger import get_logger

logger = get_logger(__name__)


class RedisTokenBlacklistRepository(ITokenBlacklistRepository):
    """
    Redis implementation of the token blacklist repository.
    
    This implementation uses Redis to store blacklisted tokens, providing:
    - Persistence across application restarts
    - Automatic expiration of blacklisted tokens
    - Distribution across multiple application instances
    """
    
    def __init__(self, redis_client: Optional[redis.Redis] = None, key_prefix: str = "blacklist:"):
        """
        Initialize the Redis token blacklist repository.
        
        Args:
            redis_client: Redis client instance. If not provided, one will be created.
            key_prefix: Prefix for Redis keys to avoid collisions
        """
        self._redis = redis_client
        self._key_prefix = key_prefix
        
        if self._redis is None:
            settings = get_settings()
            try:
                self._redis = redis.Redis.from_url(
                    settings.REDIS_URL,
                    decode_responses=True,
                )
                logger.info("Redis token blacklist repository initialized")
            except Exception as e:
                logger.error(f"Failed to initialize Redis client: {e}")
                raise
    
    async def add_to_blacklist(
        self, token: str, jti: str, expires_at: datetime, reason: Optional[str] = None
    ) -> None:
        """
        Add a token to the blacklist.
        
        Args:
            token: The token value to blacklist
            jti: JWT ID - unique identifier for the token
            expires_at: When the token expires
            reason: Reason for blacklisting (optional)
        """
        try:
            # Calculate TTL in seconds
            expiry_timestamp = expires_at.timestamp()
            current_timestamp = datetime.now().timestamp()
            ttl = max(int(expiry_timestamp - current_timestamp), 1)  # Ensure at least 1 second TTL
            
            # Store token data
            token_data = {
                "jti": jti,
                "reason": reason,
                "blacklisted_at": datetime.now().isoformat(),
                "expires_at": expires_at.isoformat()
            }
            
            # Store by JTI for faster lookups
            jti_key = f"{self._key_prefix}jti:{jti}"
            await self._redis.setex(jti_key, ttl, json.dumps(token_data))
            
            # Map token to JTI if needed
            token_key = f"{self._key_prefix}token:{token}"
            await self._redis.setex(token_key, ttl, jti)
            
            logger.debug(f"Token with JTI {jti} blacklisted until {expires_at}")
        except RedisError as e:
            logger.error(f"Redis error when adding token to blacklist: {e}")
            # Re-raise as application-specific exception if needed
            raise
    
    async def is_blacklisted(self, token: str) -> bool:
        """
        Check if a token is blacklisted.
        
        Args:
            token: The token value to check
            
        Returns:
            True if the token is blacklisted, False otherwise
        """
        try:
            token_key = f"{self._key_prefix}token:{token}"
            jti = await self._redis.get(token_key)
            
            if not jti:
                return False
                
            return await self.is_jti_blacklisted(jti)
        except RedisError as e:
            logger.error(f"Redis error when checking token blacklist: {e}")
            # Assume not blacklisted on Redis failure (fail-open)
            # For stricter security, return True here (fail-closed)
            return False
    
    async def is_jti_blacklisted(self, token_id: str) -> bool:
        """
        Check if a token ID (JTI) is blacklisted.
        
        Args:
            token_id: The token ID (JTI) to check
            
        Returns:
            True if the token ID is blacklisted, False otherwise
        """
        try:
            jti_key = f"{self._key_prefix}jti:{token_id}"
            return await self._redis.exists(jti_key) > 0
        except RedisError as e:
            logger.error(f"Redis error when checking JTI blacklist: {e}")
            # Assume not blacklisted on Redis failure (fail-open)
            # For stricter security, return True here (fail-closed)
            return False
