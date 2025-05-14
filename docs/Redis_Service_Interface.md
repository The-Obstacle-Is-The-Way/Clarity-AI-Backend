# Redis Service Interface

## Overview

The Redis Service Interface is a crucial architectural component that provides a clean abstraction for Redis operations throughout the Clarity AI Backend. This document explains the design, implementation, and usage of the Redis service according to clean architecture principles.

## Architectural Significance

In a clean architecture, direct access to external systems (like Redis) should be abstracted behind interfaces that:

1. **Protect Domain Logic**: Keep business rules independent of external implementations
2. **Enable Testability**: Allow for mocking during tests
3. **Facilitate Changes**: Make it possible to change implementation details without affecting consumers
4. **Support Security**: Enforce consistent security practices (especially for HIPAA compliance)

The Redis Service embodies these principles by providing a standardized interface for all Redis operations across the system.

## Interface Definition

The `IRedisService` interface is defined in the core layer and serves as a contract for Redis operations:

```python
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Union, TypeVar, Generic, Set
from datetime import timedelta

T = TypeVar('T')

class IRedisService(ABC, Generic[T]):
    """Interface for Redis operations, providing a clean abstraction for Redis functionality."""
    
    @abstractmethod
    async def get(self, key: str) -> Optional[T]:
        """Retrieve a value by key."""
        pass
    
    @abstractmethod
    async def set(self, key: str, value: T, expiration: Optional[timedelta] = None) -> bool:
        """Set a key-value pair with optional expiration."""
        pass
    
    @abstractmethod
    async def delete(self, key: str) -> bool:
        """Delete a key-value pair."""
        pass
    
    @abstractmethod
    async def exists(self, key: str) -> bool:
        """Check if a key exists."""
        pass
    
    @abstractmethod
    async def expire(self, key: str, expiration: timedelta) -> bool:
        """Set expiration on a key."""
        pass
    
    @abstractmethod
    async def incr(self, key: str, amount: int = 1) -> int:
        """Increment a key's value."""
        pass
    
    @abstractmethod
    async def decr(self, key: str, amount: int = 1) -> int:
        """Decrement a key's value."""
        pass
    
    @abstractmethod
    async def lpush(self, key: str, *values: T) -> int:
        """Add values to the left of a list."""
        pass
    
    @abstractmethod
    async def rpush(self, key: str, *values: T) -> int:
        """Add values to the right of a list."""
        pass
    
    @abstractmethod
    async def lrange(self, key: str, start: int, end: int) -> List[T]:
        """Get a range of values from a list."""
        pass
    
    @abstractmethod
    async def hset(self, key: str, field: str, value: T) -> bool:
        """Set a field in a hash."""
        pass
    
    @abstractmethod
    async def hget(self, key: str, field: str) -> Optional[T]:
        """Get a field from a hash."""
        pass
    
    @abstractmethod
    async def hmset(self, key: str, mapping: Dict[str, T]) -> bool:
        """Set multiple fields in a hash."""
        pass
    
    @abstractmethod
    async def hmget(self, key: str, fields: List[str]) -> Dict[str, Optional[T]]:
        """Get multiple fields from a hash."""
        pass
    
    @abstractmethod
    async def hgetall(self, key: str) -> Dict[str, T]:
        """Get all fields from a hash."""
        pass
    
    @abstractmethod
    async def hdel(self, key: str, *fields: str) -> int:
        """Delete fields from a hash."""
        pass
    
    @abstractmethod
    async def sadd(self, key: str, *members: T) -> int:
        """Add members to a set."""
        pass
    
    @abstractmethod
    async def smembers(self, key: str) -> Set[T]:
        """Get all members of a set."""
        pass
    
    @abstractmethod
    async def sismember(self, key: str, member: T) -> bool:
        """Check if a member exists in a set."""
        pass
    
    @abstractmethod
    async def srem(self, key: str, *members: T) -> int:
        """Remove members from a set."""
        pass
    
    @abstractmethod
    async def pipeline(self) -> "IRedisPipeline":
        """Get a pipeline for batch operations."""
        pass
```

## Implementation Classes

### Redis Service Implementation

The concrete implementation of `IRedisService` is defined in the infrastructure layer:

```python
class RedisService(IRedisService[T]):
    """
    Concrete implementation of IRedisService using Redis.
    
    This class wraps redis.asyncio.Redis to provide a clean interface 
    for Redis operations according to our application needs.
    """
    
    def __init__(self, redis_client: Redis):
        """
        Initialize the Redis service with a Redis client.
        
        Args:
            redis_client: Initialized Redis client
        """
        self._redis = redis_client
    
    # Implementation of all interface methods...
```

### Test Mock Implementation

For testing purposes, an in-memory implementation is provided:

```python
class InMemoryRedisService(IRedisService[T]):
    """
    In-memory implementation of IRedisService for testing.
    """
    
    def __init__(self):
        """Initialize the in-memory Redis service."""
        self._data = {}
        self._expirations = {}
        self._lists = {}
        self._hashes = {}
        self._sets = {}
    
    # Mock implementations of all interface methods...
```

## Dependency Injection

The Redis service is provided through FastAPI's dependency injection system:

```python
from fastapi import Depends, Request
from app.core.interfaces.services.redis_service_interface import IRedisService

async def get_redis_service(request: Request) -> IRedisService:
    """
    Dependency provider for Redis service.
    
    Args:
        request: FastAPI Request object
    
    Returns:
        IRedisService implementation
    """
    # Access the Redis client from app state
    redis_client = request.app.state.redis
    return RedisService(redis_client)
```

## Usage Examples

### General Usage

```python
from fastapi import Depends, APIRouter
from app.core.interfaces.services.redis_service_interface import IRedisService
from app.presentation.dependencies.redis import get_redis_service

router = APIRouter()

@router.get("/cache/{key}")
async def get_cached_data(
    key: str,
    redis_service: IRedisService = Depends(get_redis_service)
):
    """Get data from Redis cache."""
    data = await redis_service.get(key)
    return {"data": data}
```

### Token Blacklisting

```python
class TokenBlacklistRepository(ITokenBlacklistRepository):
    """
    Redis-based implementation of token blacklist repository.
    """
    
    def __init__(self, redis_service: IRedisService):
        self._redis = redis_service
        self._prefix = "blacklist:"
    
    async def add_to_blacklist(self, token_id: str, expiration: timedelta) -> None:
        """Add a token to the blacklist with expiration."""
        key = f"{self._prefix}{token_id}"
        await self._redis.set(key, "1", expiration)
    
    async def is_blacklisted(self, token_id: str) -> bool:
        """Check if a token is blacklisted."""
        key = f"{self._prefix}{token_id}"
        return await self._redis.exists(key)
```

### Rate Limiting

```python
class RedisRateLimiter(IRateLimiter):
    """
    Redis-based rate limiter implementation.
    """
    
    def __init__(self, redis_service: IRedisService):
        self._redis = redis_service
        self._prefix = "ratelimit:"
    
    async def increment(self, key: str, window: timedelta) -> int:
        """
        Increment the counter for a rate limit key.
        
        Args:
            key: Rate limit key (e.g., IP address or user ID)
            window: Time window for rate limiting
        
        Returns:
            Current count within the window
        """
        redis_key = f"{self._prefix}{key}"
        count = await self._redis.incr(redis_key)
        
        # Set expiration on first increment
        if count == 1:
            await self._redis.expire(redis_key, window)
        
        return count
```

## Health Check Implementation

The Redis service supports health checks to verify Redis availability:

```python
class HealthCheckService:
    """Service for checking system health."""
    
    def __init__(
        self,
        redis_service: IRedisService,
        # Other dependencies...
    ):
        self._redis = redis_service
        # Initialize other services...
    
    async def check_redis(self) -> Dict[str, Any]:
        """Check Redis connectivity."""
        try:
            # Set and retrieve a test value
            await self._redis.set("health_check", "ok", timedelta(seconds=5))
            result = await self._redis.get("health_check")
            
            return {
                "status": "healthy" if result == "ok" else "degraded",
                "latency_ms": self._redis.get_latency_ms(),  # Requires instrumentation
                "details": "Redis connection successful"
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e),
                "details": "Redis connection failed"
            }
```

## HIPAA Compliance Considerations

The Redis service interface enforces HIPAA compliance by:

1. **No PHI in Keys**: Redis keys should never contain PHI
2. **Encrypted Values**: PHI stored in Redis values must be encrypted
3. **Automatic Expiration**: Sensible TTLs for all cached PHI data
4. **Audit Logging**: All PHI access operations are logged
5. **Secure Connection**: Redis connections use TLS when available

## Migration Strategy

To migrate from direct Redis usage to the new interface:

1. Create the interface definition in the core layer
2. Implement a concrete Redis service in the infrastructure layer
3. Create a dependency provider for FastAPI
4. Refactor existing code to use the new interface via dependency injection
5. Update tests to use the in-memory implementation

## Performance Considerations

- **Connection Pooling**: The Redis service uses connection pooling for efficiency
- **Pipelining**: Batch operations via the pipeline method
- **Serialization**: Consistent serialization/deserialization of data

## Testing

To test code that depends on Redis:

```python
# In a test file
@pytest.fixture
def mock_redis_service():
    """Provide a mock Redis service for testing."""
    return InMemoryRedisService()

@pytest.fixture
def app_instance(mock_redis_service):
    """Create test application with mock Redis service."""
    app = create_application(settings_override=test_settings)
    
    # Override Redis service dependency
    app.dependency_overrides[get_redis_service] = lambda: mock_redis_service
    
    return app
```

## Conclusion

The Redis Service Interface is a critical architectural component that ensures clean separation of concerns, consistent error handling, and HIPAA compliance throughout the Clarity AI Backend. By following this interface definition, all Redis operations within the system maintain a high standard of security, testability, and maintainability.
