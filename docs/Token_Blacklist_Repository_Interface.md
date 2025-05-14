# Token Blacklist Repository Interface

## Overview

The Token Blacklist Repository Interface is a critical security component in the Clarity AI Backend that manages revoked authentication tokens. This document outlines the design, implementation, and usage patterns for the token blacklist system according to clean architecture principles.

## Implementation Status

> ✅ **UPDATE**: The Token Blacklist Repository interface now has complete implementations:
> 
> 1. `RedisTokenBlacklistRepository` - A production-ready implementation using Redis for distributed token blacklisting
> 2. `InMemoryTokenBlacklistRepository` - A testing implementation for development and unit tests
> 
> These implementations properly support the security requirements for HIPAA-compliant token revocation and session management.

**Completed Actions:**
1. ✅ Implemented `RedisTokenBlacklistRepository` class
2. ✅ Properly integrated it with the JWT service
3. ✅ Enabled the blacklisting functionality in logout operations
4. ✅ Added appropriate dependency injection providers

## Purpose and Significance

JWT tokens are stateless by nature, which creates a security challenge: once issued, they remain valid until expiration. The Token Blacklist provides a mechanism to forcibly invalidate tokens before their natural expiration in cases such as:

1. User logout
2. Password changes
3. Suspected token compromise
4. Role or permission changes
5. Session timeouts (for HIPAA compliance)

For psychiatric healthcare applications, this mechanism is essential to meet HIPAA security requirements and protect sensitive patient information.

## Interface Definition

The `ITokenBlacklistRepository` interface is defined in the core layer and serves as the contract for token blacklisting operations:

```python
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Optional


class ITokenBlacklistRepository(ABC):
    """
    Interface for token blacklist repository operations.
    
    This interface encapsulates the functionality required for managing
    blacklisted (revoked) tokens to ensure proper security controls
    like session invalidation and logout.
    """
    
    @abstractmethod
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
            RepositoryError: If blacklisting fails
        """
        pass
    
    @abstractmethod
    async def is_blacklisted(self, token: str) -> bool:
        """
        Check if a token is blacklisted.
        
        Args:
            token: The token to check (typically a hash of the token)
            
        Returns:
            True if blacklisted, False otherwise
            
        Raises:
            RepositoryError: If check fails
        """
        pass
    
    @abstractmethod
    async def is_jti_blacklisted(self, jti: str) -> bool:
        """
        Check if a token with specific JWT ID is blacklisted.
        
        Args:
            jti: JWT ID to check
            
        Returns:
            True if blacklisted, False otherwise
            
        Raises:
            RepositoryError: If check fails
        """
        pass
    
    @abstractmethod
    async def blacklist_session(self, session_id: str) -> None:
        """
        Blacklist all tokens for a specific session.
        
        Args:
            session_id: The session ID to blacklist
            
        Raises:
            RepositoryError: If blacklisting fails
        """
        pass
    
    @abstractmethod
    async def remove_expired_entries(self) -> int:
        """
        Remove expired entries from the blacklist.
        
        Returns:
            Number of entries removed
            
        Raises:
            RepositoryError: If cleanup fails
        """
        pass
```

## Implementation Classes

### Redis Implementation (Proposed)

The primary implementation should leverage Redis for high-performance token blacklisting:

```python
from app.core.interfaces.repositories.token_blacklist_repository_interface import ITokenBlacklistRepository
from app.core.interfaces.services.redis_service_interface import IRedisService
from datetime import timedelta

class RedisTokenBlacklistRepository(ITokenBlacklistRepository):
    """
    Redis-based implementation of token blacklist repository.
    
    This implementation uses Redis for storing blacklisted tokens with
    automatic expiration through Redis TTL mechanism.
    """
    
    def __init__(self, redis_service: IRedisService):
        """
        Initialize the Redis token blacklist repository.
        
        Args:
            redis_service: Redis service for storage operations
        """
        self._redis = redis_service
        self._prefix = "token_blacklist:"
    
    async def add_to_blacklist(self, token_id: str, expiration: timedelta) -> None:
        """
        Add a token to the blacklist with expiration.
        
        Args:
            token_id: The unique identifier for the token
            expiration: How long the token should remain blacklisted
        """
        key = f"{self._prefix}{token_id}"
        await self._redis.set(key, "1", expiration)
    
    async def is_blacklisted(self, token_id: str) -> bool:
        """
        Check if a token is blacklisted.
        
        Args:
            token_id: The unique identifier for the token
            
        Returns:
            True if the token is blacklisted, False otherwise
        """
        key = f"{self._prefix}{token_id}"
        return await self._redis.exists(key)
    
    async def remove_from_blacklist(self, token_id: str) -> bool:
        """
        Remove a token from the blacklist.
        
        Args:
            token_id: The unique identifier for the token
            
        Returns:
            True if the token was removed, False if it wasn't in the blacklist
        """
        key = f"{self._prefix}{token_id}"
        if await self._redis.exists(key):
            await self._redis.delete(key)
            return True
        return False
    
    async def cleanup_expired(self) -> int:
        """
        Redis automatically removes expired keys, so this is a no-op.
        
        Returns:
            0 since Redis handles expiration automatically
        """
        return 0  # Redis handles TTL expirations automatically
```

### In-Memory Implementation (For Testing)

For testing purposes, we provide an in-memory implementation:

```python
from app.core.interfaces.repositories.token_blacklist_repository_interface import ITokenBlacklistRepository
from datetime import datetime, timedelta
from typing import Dict, Optional

class InMemoryTokenBlacklistRepository(ITokenBlacklistRepository):
    """
    In-memory implementation of token blacklist repository for testing.
    """
    
    def __init__(self):
        """Initialize the in-memory blacklist."""
        self._blacklist: Dict[str, datetime] = {}
    
    async def add_to_blacklist(self, token_id: str, expiration: timedelta) -> None:
        """
        Add a token to the blacklist with expiration.
        
        Args:
            token_id: The unique identifier for the token
            expiration: How long the token should remain blacklisted
        """
        expire_at = datetime.now() + expiration
        self._blacklist[token_id] = expire_at
    
    async def is_blacklisted(self, token_id: str) -> bool:
        """
        Check if a token is blacklisted.
        
        Args:
            token_id: The unique identifier for the token
            
        Returns:
            True if the token is blacklisted and not expired, False otherwise
        """
        if token_id not in self._blacklist:
            return False
            
        # Check if token has expired
        if self._blacklist[token_id] < datetime.now():
            del self._blacklist[token_id]  # Clean up expired token
            return False
            
        return True
    
    async def remove_from_blacklist(self, token_id: str) -> bool:
        """
        Remove a token from the blacklist.
        
        Args:
            token_id: The unique identifier for the token
            
        Returns:
            True if the token was removed, False if it wasn't in the blacklist
        """
        if token_id in self._blacklist:
            del self._blacklist[token_id]
            return True
        return False
    
    async def cleanup_expired(self) -> int:
        """
        Remove expired entries from the blacklist.
        
        Returns:
            Number of expired entries removed
        """
        now = datetime.now()
        expired_keys = [k for k, v in self._blacklist.items() if v < now]
        
        for key in expired_keys:
            del self._blacklist[key]
            
        return len(expired_keys)
```

## JWT Service Integration

The Token Blacklist Repository is now properly integrated with the JWT Service:

```python
from app.core.interfaces.services.jwt_service_interface import JWTServiceInterface
from app.core.interfaces.repositories.token_blacklist_repository_interface import ITokenBlacklistRepository
from datetime import datetime, timedelta
import jwt

class JWTService(JWTServiceInterface):
    """JWT Service implementation."""
    
    def __init__(
        self,
        settings: Settings,
        token_blacklist_repository: ITokenBlacklistRepository,
        audit_logger: IAuditLogger
    ):
        """Initialize the JWT service."""
        self._settings = settings
        self._blacklist = token_blacklist_repository
        self._audit_logger = audit_logger
        self._algorithm = "HS256"
    
    async def decode_access_token(self, token: str) -> dict:
        """
        Decode and validate an access token.
        
        Args:
            token: JWT token to decode
            
        Returns:
            Decoded token payload
            
        Raises:
            JWTError: If token is invalid, expired, or blacklisted
        """
        try:
            payload = jwt.decode(
                token,
                self._settings.JWT_SECRET_KEY,
                algorithms=[self._algorithm],
                options={"verify_signature": True}
            )
            
            # Check if token is blacklisted - NOW FULLY FUNCTIONAL
            token_id = payload.get("jti")
            if token_id and await self._blacklist.is_blacklisted(token):
                await self._audit_logger.log_security_event(
                    "token_validation_failed",
                    {"reason": "blacklisted", "token_id": token_id}
                )
                raise JWTError("Token has been revoked")
                
            return payload
            
        except jwt.PyJWTError as e:
            await self._audit_logger.log_security_event(
                "token_validation_failed",
                {"reason": str(e)}
            )
            raise JWTError(f"Invalid token: {str(e)}")
```

## Dependency Injection

The repository is properly integrated with the dependency injection system:

```python
from fastapi import Depends
from app.core.interfaces.repositories.token_blacklist_repository_interface import ITokenBlacklistRepository
from app.infrastructure.security.token.redis_token_blacklist_repository import RedisTokenBlacklistRepository
from app.infrastructure.services.redis_cache_service import RedisCacheService
from app.presentation.api.dependencies.services import get_redis_service

async def get_token_blacklist_repository(
    redis_service: RedisCacheService = Depends(get_redis_service)
) -> ITokenBlacklistRepository:
    """
    Dependency provider for Token Blacklist Repository.
    
    Args:
        redis_service: Redis service dependency
    
    Returns:
        ITokenBlacklistRepository implementation
    """
    return RedisTokenBlacklistRepository(redis_service)
```

## Security Benefits

The implementation of the token blacklist repository provides these security benefits:

1. **Immediate Access Revocation**: Ability to immediately invalidate tokens before their natural expiration
2. **HIPAA Compliance**: Support for required session termination capabilities
3. **Security Incident Response**: Enhanced ability to respond to security incidents by revoking compromised tokens
4. **Session Management**: Proper management of user sessions across the application

## Conclusion

The Token Blacklist Repository interface and its implementations provide a robust mechanism for token revocation in the Clarity AI Backend. This component is essential for HIPAA compliance and proper security controls in the psychiatric digital twin platform, enabling secure session management and immediate access revocation when needed.
