"""
Redis implementation of the token blacklist repository interface.

Provides efficient token blacklisting and validation operations using Redis
for persistence, supporting HIPAA-compliant session management.
"""

import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional, List
from uuid import UUID

from jose.jwt import decode
from redis import Redis
from redis.asyncio import Redis as AsyncRedis
from redis.exceptions import RedisError

from app.core.config.settings import Settings
from app.core.interfaces.repositories.token_blacklist_repository_interface import ITokenBlacklistRepository
from app.domain.exceptions import InvalidTokenException

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
        redis_client: Optional[AsyncRedis] = None,
        settings: Optional[Settings] = None,
        jwt_secret_key: Optional[str] = None,
        jwt_algorithm: Optional[str] = None
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
            self.jwt_secret_key = getattr(settings.JWT_SECRET_KEY, 'get_secret_value', 
                                      lambda: settings.JWT_SECRET_KEY)()
            self.jwt_algorithm = settings.JWT_ALGORITHM
        else:
            # Direct initialization
            self.jwt_secret_key = jwt_secret_key
            self.jwt_algorithm = jwt_algorithm
            
        logger.info("Redis token blacklist repository initialized")
    
    async def add_to_blacklist(self, token_id: str, expires_at: Optional[int] = None) -> bool:
        """Add a token ID to the blacklist.
        
        Args:
            token_id: JWT token ID (jti) to blacklist
            expires_at: Optional Unix timestamp when token expires
            
        Returns:
            True if successfully added to the blacklist
        """
        try:
            # Determine TTL based on expiration time
            if expires_at:
                # Calculate TTL in seconds
                ttl = expires_at - int(datetime.now(timezone.utc).timestamp())
                # Ensure positive TTL (min 60 seconds)
                ttl = max(60, ttl)
            else:
                # Default TTL of 7 days if no expiration provided
                ttl = 60 * 60 * 24 * 7  # 7 days in seconds
            
            # Store in Redis with expiration
            key = f"{JTI_PREFIX}{token_id}"
            await self.redis.set(key, "1", ex=ttl)
            logger.debug(f"Added token {token_id} to blacklist with TTL of {ttl} seconds")
            return True
        except RedisError as e:
            logger.error(f"Failed to add token to blacklist: {str(e)}")
            return False
    
    async def is_blacklisted(self, token: str) -> bool:
        """Check if a token is blacklisted by its full token string.
        
        Args:
            token: Full JWT token string
            
        Returns:
            True if token is blacklisted
        """
        try:
            # Extract JTI from token
            try:
                # Decode without verification to extract JTI
                payload = decode(
                    token=token,
                    key=self.jwt_secret_key,
                    algorithms=[self.jwt_algorithm],
                    options={"verify_signature": False, "verify_exp": False}
                )
                jti = payload.get("jti")
                
                if not jti:
                    logger.warning("Token has no JTI claim")
                    return False
                
                # Check if JTI is blacklisted
                return await self.is_jti_blacklisted(jti)
            except Exception as e:
                logger.error(f"Failed to decode token for blacklist check: {str(e)}")
                # Fallback: check by token hash
                key = f"{TOKEN_PREFIX}{hash(token)}"
                result = await self.redis.get(key)
                return result is not None
        except RedisError as e:
            logger.error(f"Failed to check token blacklist: {str(e)}")
            return False
    
    async def is_jti_blacklisted(self, jti: str) -> bool:
        """Check if a token ID is blacklisted.
        
        Args:
            jti: JWT token ID to check
            
        Returns:
            True if the token ID is blacklisted
        """
        try:
            key = f"{JTI_PREFIX}{jti}"
            result = await self.redis.get(key)
            return result is not None
        except RedisError as e:
            logger.error(f"Failed to check JTI blacklist: {str(e)}")
            return False
    
    async def blacklist_session(self, session_id: str) -> bool:
        """Blacklist all tokens associated with a session.
        
        Args:
            session_id: Session identifier to blacklist
            
        Returns:
            True if session was successfully blacklisted
        """
        try:
            # Store session in blacklist for 30 days (common session expiry)
            ttl = 60 * 60 * 24 * 30  # 30 days in seconds
            key = f"{SESSION_PREFIX}{session_id}"
            await self.redis.set(key, "1", ex=ttl)
            logger.info(f"Blacklisted session {session_id}")
            return True
        except RedisError as e:
            logger.error(f"Failed to blacklist session: {str(e)}")
            return False
    
    async def blacklist_user_tokens(self, user_id: str) -> bool:
        """Blacklist all tokens for a specific user.
        
        Args:
            user_id: User identifier whose tokens should be blacklisted
            
        Returns:
            True if user tokens were successfully blacklisted
        """
        try:
            # Store user in blacklist for 30 days
            ttl = 60 * 60 * 24 * 30  # 30 days in seconds
            key = f"{USER_PREFIX}{user_id}"
            await self.redis.set(key, str(int(time.time())), ex=ttl)
            logger.info(f"Blacklisted all tokens for user {user_id}")
            return True
        except RedisError as e:
            logger.error(f"Failed to blacklist user tokens: {str(e)}")
            return False
    
    async def clear_expired_tokens(self) -> int:
        """Remove expired tokens from the blacklist.
        
        Redis automatically removes expired keys, but this method
        can be used to force cleanup of any manually tracked expirations.
        
        Returns:
            Number of tokens removed from blacklist
        """
        # Redis handles expiration automatically, so this is a no-op
        # but included for interface completeness
        return 0
    
    async def is_user_blacklisted(self, user_id: str) -> bool:
        """Check if a user's tokens are blacklisted.
        
        Args:
            user_id: User identifier to check
            
        Returns:
            True if the user's tokens are blacklisted
        """
        try:
            key = f"{USER_PREFIX}{user_id}"
            result = await self.redis.get(key)
            return result is not None
        except RedisError as e:
            logger.error(f"Failed to check user blacklist: {str(e)}")
            return False
    
    async def is_session_blacklisted(self, session_id: str) -> bool:
        """Check if a session is blacklisted.
        
        Args:
            session_id: Session identifier to check
            
        Returns:
            True if the session is blacklisted
        """
        try:
            key = f"{SESSION_PREFIX}{session_id}"
            result = await self.redis.get(key)
            return result is not None
        except RedisError as e:
            logger.error(f"Failed to check session blacklist: {str(e)}")
            return False