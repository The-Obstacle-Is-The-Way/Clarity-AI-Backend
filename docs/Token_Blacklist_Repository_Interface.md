# Token Blacklist Repository Interface

## Overview

The Token Blacklist Repository Interface is a critical security component in the Clarity AI Backend that manages revoked authentication tokens. This document outlines the design, implementation, and usage patterns for the token blacklist system according to clean architecture principles.

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

### Redis Implementation

The primary implementation leverages Redis for high-performance token blacklisting:

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

## Integration with JWT Service

The Token Blacklist Repository is a critical dependency for the JWT Service, which handles token validation:

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
            
            # Check if token is blacklisted
            token_id = payload.get("jti")
            if token_id and await self._blacklist.is_blacklisted(token_id):
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
    
    async def blacklist_token(self, token: str) -> None:
        """
        Add a token to the blacklist.
        
        Args:
            token: JWT token to blacklist
            
        Raises:
            JWTError: If token cannot be decoded
        """
        try:
            # Decode without verification to get claims
            # (we want to blacklist even if the token signature is invalid)
            payload = jwt.decode(
                token,
                options={"verify_signature": False}
            )
            
            token_id = payload.get("jti")
            if not token_id:
                raise JWTError("Token does not have a JTI claim")
            
            # Calculate remaining lifetime for the token
            exp = payload.get("exp")
            if not exp:
                # If no expiration, blacklist for maximum token lifetime
                expiration = timedelta(minutes=self._settings.ACCESS_TOKEN_EXPIRE_MINUTES)
            else:
                # Blacklist until the token would naturally expire
                expiration_time = datetime.fromtimestamp(exp)
                current_time = datetime.now()
                
                # If already expired, no need to blacklist
                if expiration_time <= current_time:
                    return
                
                expiration = expiration_time - current_time
            
            # Add to blacklist
            await self._blacklist.add_to_blacklist(token_id, expiration)
            
            await self._audit_logger.log_security_event(
                "token_blacklisted",
                {"token_id": token_id}
            )
            
        except Exception as e:
            raise JWTError(f"Failed to blacklist token: {str(e)}")
```

## Dependency Injection

The Token Blacklist Repository is provided through FastAPI's dependency injection system:

```python
from fastapi import Depends
from app.core.interfaces.repositories.token_blacklist_repository_interface import ITokenBlacklistRepository
from app.infrastructure.security.token.redis_token_blacklist_repository import RedisTokenBlacklistRepository
from app.core.interfaces.services.redis_service_interface import IRedisService
from app.presentation.dependencies.redis import get_redis_service

async def get_token_blacklist_repository(
    redis_service: IRedisService = Depends(get_redis_service)
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

## Usage in Authentication Flow

The Token Blacklist is instrumental in the user authentication flow:

### Login Process

```python
@router.post("/login", response_model=TokenResponse)
async def login(
    credentials: UserCredentials,
    jwt_service: JWTServiceInterface = Depends(get_jwt_service),
    user_service: UserService = Depends(get_user_service),
    audit_logger: IAuditLogger = Depends(get_audit_logger)
):
    """Login endpoint that issues JWT tokens."""
    user = await user_service.authenticate_user(credentials.username, credentials.password)
    
    if not user:
        await audit_logger.log_security_event(
            "login_failed",
            {"username": credentials.username, "reason": "invalid_credentials"}
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
    
    # Generate tokens
    access_token = await jwt_service.create_access_token(data={"sub": user.id})
    refresh_token = await jwt_service.create_refresh_token(data={"sub": user.id})
    
    await audit_logger.log_security_event(
        "login_successful",
        {"user_id": user.id}
    )
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }
```

### Logout Process

```python
@router.post("/logout")
async def logout(
    token: str = Depends(get_token_from_authorization_header),
    jwt_service: JWTServiceInterface = Depends(get_jwt_service),
    audit_logger: IAuditLogger = Depends(get_audit_logger)
):
    """
    Logout endpoint that blacklists the current token.
    
    This ensures the token cannot be used again, effectively
    logging the user out of the current session.
    """
    try:
        # Add current token to blacklist
        await jwt_service.blacklist_token(token)
        
        return {"message": "Successfully logged out"}
        
    except JWTError as e:
        await audit_logger.log_security_event(
            "logout_failed",
            {"reason": str(e)}
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
```

## HIPAA Compliance Considerations

The Token Blacklist Repository is critical for HIPAA compliance:

1. **Session Management**: HIPAA requires automatic session termination after periods of inactivity
2. **Access Controls**: Immediate revocation of access when authorization changes
3. **Audit Logging**: All token blacklisting events are logged for audit trails
4. **Emergency Access**: Ability to immediately terminate all active sessions in case of a security incident

## Performance Considerations

For high-traffic applications, token blacklisting can become a performance bottleneck:

1. **High-Speed Store**: Using Redis provides sub-millisecond lookup times
2. **Sharding**: For very large deployments, consider sharding the blacklist by token ID
3. **Cleanup Jobs**: Redis handles TTL expiration automatically, but other implementations may need periodic cleanup
4. **Rate Limiting**: Protect blacklist operations with rate limiting to prevent DoS attacks

## Testing

To test the token blacklist functionality:

```python
import pytest
from datetime import timedelta

# Test fixture for the in-memory implementation
@pytest.fixture
def token_blacklist():
    return InMemoryTokenBlacklistRepository()

# Test adding and checking a blacklisted token
async def test_blacklist_token(token_blacklist):
    test_token_id = "test-token-123"
    await token_blacklist.add_to_blacklist(test_token_id, timedelta(minutes=15))
    
    # Token should be blacklisted
    assert await token_blacklist.is_blacklisted(test_token_id) is True
    
    # Unknown token should not be blacklisted
    assert await token_blacklist.is_blacklisted("unknown-token") is False

# Test token expiration
async def test_token_expiration(token_blacklist):
    test_token_id = "expires-quickly"
    # Set a very short expiration
    await token_blacklist.add_to_blacklist(test_token_id, timedelta(microseconds=1))
    
    # Wait for expiration
    await asyncio.sleep(0.01)
    
    # Token should no longer be blacklisted
    assert await token_blacklist.is_blacklisted(test_token_id) is False
```

## Migration Strategy

To implement the Token Blacklist Repository:

1. Define the interface in the core layer
2. Implement the Redis version in the infrastructure layer
3. Update the JWT service to use the blacklist
4. Implement endpoints for token revocation (logout)
5. Add audit logging for all blacklist operations

## Security Implications

The token blacklist is a critical security component with several implications:

1. **Blacklist Persistence**: Loss of the blacklist could allow revoked tokens to be reused
2. **Denial of Service**: Attackers might attempt to overload the blacklist
3. **Clock Synchronization**: Server time discrepancies could affect token validation
4. **Storage Growth**: Without proper expiration, the blacklist can grow indefinitely

## Conclusion

The Token Blacklist Repository interface is an essential security component for the Clarity AI psychiatric digital twin platform. It provides the foundation for secure session management, complies with HIPAA requirements for healthcare applications, and integrates seamlessly with the JWT authentication system. By implementing this interface according to clean architecture principles, the system maintains a high level of security, testability, and maintainability.
