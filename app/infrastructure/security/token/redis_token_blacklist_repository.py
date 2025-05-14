"""
Redis-based Token Blacklist Repository.

This module provides a HIPAA-compliant implementation of the token blacklist
repository interface using Redis as the storage backend, enabling secure
user session management and token invalidation.
"""

import hashlib
from datetime import datetime, timedelta, UTC
from typing import Optional, Dict, Any

from app.core.interfaces.repositories.token_blacklist_repository_interface import ITokenBlacklistRepository
from app.infrastructure.services.redis_cache_service import RedisCacheService
from app.domain.exceptions.repository import RepositoryException
from app.infrastructure.logging.logger import get_logger

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
        self._token_prefix = "blacklist:token:"
        self._jti_prefix = "blacklist:jti:"
        self._session_prefix = "blacklist:session:"
        logger.info("RedisTokenBlacklistRepository initialized")
    
    def _hash_token(self, token: str) -> str:
        """
        Create a secure hash of a token to avoid storing actual tokens.
        
        Args:
            token: The token to hash
        
        Returns:
            str: Secure hash of the token
        """
        return hashlib.sha256(token.encode()).hexdigest()
    
    async def add_to_blacklist(
        self,
        token: str,
        jti: str,
        expires_at: datetime,
        reason: Optional[str] = None
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
                "reason": reason or "manual_blacklist"
            }
            await self._redis.set(jti_key, jti_data, ttl=ttl)
            
            logger.info(f"Token {jti} blacklisted until {expires_at.isoformat()}, reason: {reason}")
        except Exception as e:
            logger.error(f"Failed to blacklist token: {str(e)}")
            raise RepositoryException(f"Failed to blacklist token: {str(e)}")
    
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
            logger.error(f"Failed to check token blacklist: {str(e)}")
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
            logger.error(f"Failed to check JTI blacklist: {str(e)}")
            # For security, assume JTI is blacklisted if check fails
            return True
    
    async def blacklist_session(self, session_id: str) -> None:
        """
        Blacklist all tokens for a specific session.
        
        Args:
            session_id: The session ID to blacklist
            
        Raises:
            RepositoryException: If blacklisting fails
        """
        try:
            # Get all JTIs for this session
            session_key = f"{self._session_prefix}{session_id}"
            session_jti_list = await self._redis.get(session_key) or []
            
            if not session_jti_list:
                logger.info(f"No tokens found for session {session_id}")
                return
                
            # Set expiration date to 1 year in the future to ensure tokens stay blacklisted
            # even beyond their natural expiration
            expires_at = datetime.now(UTC) + timedelta(days=365)
            
            # Blacklist each JTI
            for jti_info in session_jti_list:
                jti = jti_info.get("jti")
                token = jti_info.get("token_hash")
                
                if jti:
                    # Store JTI reference - no need for original token
                    jti_key = f"{self._jti_prefix}{jti}"
                    jti_data = {
                        "expires_at": expires_at.isoformat(),
                        "reason": "session_logout"
                    }
                    
                    # Use a pipeline for atomic operations
                    if token:
                        token_key = f"{self._token_prefix}{token}"
                        await self._redis.set(token_key, jti, ttl=int(timedelta(days=365).total_seconds()))
                        
                    await self._redis.set(jti_key, jti_data, ttl=int(timedelta(days=365).total_seconds()))
            
            logger.info(f"Blacklisted all tokens for session {session_id}")
        except Exception as e:
            logger.error(f"Failed to blacklist session tokens: {str(e)}")
            raise RepositoryException(f"Failed to blacklist session tokens: {str(e)}")
    
    async def remove_expired_entries(self) -> int:
        """
        Remove expired entries from the blacklist.
        
        Redis automatically removes expired keys through its TTL mechanism,
        so this method primarily exists for interface compliance and to
        handle any manual clean-up if needed.
        
        Returns:
            Number of entries removed
            
        Raises:
            RepositoryException: If cleanup fails
        """
        # Redis automatically handles expiration via TTL
        # This method exists to comply with the interface
        logger.debug("Redis handles TTL automatically, no explicit clean-up needed")
        return 0 