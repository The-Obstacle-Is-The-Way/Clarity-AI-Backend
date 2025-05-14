# Rate Limiting Middleware

## Overview

The Rate Limiting Middleware is a critical security component of the Clarity AI Backend that prevents abuse, protects against brute force attacks, and ensures equitable API access. This document outlines the design, implementation, and configuration of rate limiting within the clean architecture framework.

## Architectural Significance

For a psychiatric digital twin platform processing sensitive PHI, rate limiting serves multiple critical functions:

1. **Security Protection**: Prevents credential brute-forcing and enumeration attacks
2. **Resource Management**: Prevents API abuse that could impact system performance
3. **DoS Mitigation**: Reduces vulnerability to denial of service attacks
4. **HIPAA Compliance**: Contributes to security safeguards required under §164.308(a)(1)(ii)(B)

## Core Components

The rate limiting system consists of several distinct components, each with well-defined responsibilities:

### 1. Rate Limiter Interface

```python
# app/core/interfaces/services/rate_limiting/rate_limiter_interface.py
from abc import ABC, abstractmethod
from datetime import timedelta
from typing import Tuple, Optional

class IRateLimiter(ABC):
    """
    Interface defining rate limiting operations.
    
    This interface provides methods to track and enforce rate limits
    across various dimensions (IP, user, endpoint, etc.).
    """
    
    @abstractmethod
    async def is_rate_limited(
        self,
        key: str,
        max_requests: int,
        window: timedelta
    ) -> Tuple[bool, int, Optional[timedelta]]:
        """
        Check if a request should be rate limited.
        
        Args:
            key: Unique identifier for the rate limit (e.g., "ip:{ip}" or "user:{id}")
            max_requests: Maximum number of requests allowed in the time window
            window: Time period for the rate limit
            
        Returns:
            Tuple containing:
              - Boolean indicating if request should be limited
              - Current count of requests in the window
              - Optional time remaining until limit reset
        """
        pass
    
    @abstractmethod
    async def increment(
        self,
        key: str,
        window: timedelta
    ) -> int:
        """
        Increment the counter for a rate limit key.
        
        Args:
            key: Rate limit key
            window: Time window for rate limiting
            
        Returns:
            Current count within the window
        """
        pass
```

### 2. Rate Limiter Service

The service implementation in the application layer uses Strategy pattern:

```python
# app/core/services/rate_limiting/service.py
from datetime import timedelta
from typing import Dict, Optional, Tuple

from app.core.config import Settings
from app.core.interfaces.services.rate_limiting.rate_limiter_interface import IRateLimiter

class RateLimiterService:
    """
    Service for enforcing rate limits across different dimensions.
    
    This service uses an IRateLimiter implementation and provides
    policy-based rate limiting with different limits for different
    request types and user roles.
    """
    
    def __init__(
        self,
        rate_limiter: IRateLimiter,
        settings: Settings
    ):
        """
        Initialize the rate limiter service.
        
        Args:
            rate_limiter: Concrete rate limiter implementation
            settings: Application settings containing rate limit configurations
        """
        self._limiter = rate_limiter
        self._settings = settings
        
        # Default rate limit policies
        self._default_limits = {
            "global": (settings.RATE_LIMIT_DEFAULT_REQUESTS, timedelta(minutes=1)),
            "login": (settings.RATE_LIMIT_LOGIN_REQUESTS, timedelta(minutes=5)),
            "patient_lookup": (settings.RATE_LIMIT_PATIENT_REQUESTS, timedelta(minutes=1)),
            "write_operations": (settings.RATE_LIMIT_WRITE_REQUESTS, timedelta(minutes=1))
        }
        
        # Role-based multipliers (e.g., admins get higher limits)
        self._role_multipliers = {
            "admin": 5.0,
            "clinician": 2.0,
            "researcher": 3.0,
            "patient": 1.0
        }
    
    async def check_rate_limit(
        self,
        dimension: str,
        key: str,
        policy_name: str = "global",
        role: Optional[str] = None
    ) -> Tuple[bool, int, Optional[timedelta]]:
        """
        Check if a request should be rate limited.
        
        Args:
            dimension: The dimension to rate limit (e.g., "ip", "user", "endpoint")
            key: Specific key within that dimension (e.g., the IP address or user ID)
            policy_name: Name of the rate limiting policy to apply
            role: User role for role-based rate limiting
            
        Returns:
            Tuple containing:
              - Boolean indicating if request should be limited
              - Current count of requests in the window
              - Optional time remaining until limit reset
        """
        # Construct the full rate limit key
        full_key = f"{dimension}:{key}:{policy_name}"
        
        # Get the base limits for this policy
        max_requests, window = self._default_limits.get(
            policy_name, self._default_limits["global"]
        )
        
        # Apply role multiplier if a role is provided
        if role and role in self._role_multipliers:
            max_requests = int(max_requests * self._role_multipliers[role])
        
        # Check if rate limited
        return await self._limiter.is_rate_limited(full_key, max_requests, window)
```

### 3. Redis Rate Limiter Implementation

The infrastructure layer provides concrete implementations:

```python
# app/infrastructure/rate_limiting/redis_rate_limiter.py
import time
from datetime import timedelta
from typing import Optional, Tuple

from app.core.interfaces.services.rate_limiting.rate_limiter_interface import IRateLimiter
from app.core.interfaces.services.redis_service_interface import IRedisService

class RedisRateLimiter(IRateLimiter):
    """
    Redis-based implementation of rate limiter.
    
    Uses Redis for distributed rate limiting with precise time windows
    using the sliding window algorithm.
    """
    
    def __init__(self, redis_service: IRedisService):
        """
        Initialize the Redis rate limiter.
        
        Args:
            redis_service: Redis service for storage
        """
        self._redis = redis_service
        self._prefix = "ratelimit:"
    
    async def is_rate_limited(
        self,
        key: str,
        max_requests: int,
        window: timedelta
    ) -> Tuple[bool, int, Optional[timedelta]]:
        """
        Check if a request should be rate limited.
        
        Args:
            key: Rate limit key
            max_requests: Maximum number of requests allowed
            window: Time window for the rate limit
            
        Returns:
            Tuple containing:
              - Boolean indicating if request should be limited
              - Current count of requests in the window
              - Optional time remaining until limit reset
        """
        # Get the current count
        count = await self.increment(key, window)
        
        # Check if over limit
        if count > max_requests:
            # Get TTL to determine time until reset
            redis_key = f"{self._prefix}{key}"
            ttl = await self._redis.get_ttl(redis_key)
            remaining = timedelta(seconds=ttl) if ttl > 0 else None
            
            # Rate limited
            return (True, count, remaining)
        
        # Not rate limited
        return (False, count, None)
    
    async def increment(
        self,
        key: str,
        window: timedelta
    ) -> int:
        """
        Increment the counter for a rate limit key.
        
        Uses Redis sorted sets with timestamp scores for a sliding window.
        
        Args:
            key: Rate limit key
            window: Time window for rate limiting
            
        Returns:
            Current count within the window
        """
        now = time.time()
        window_seconds = window.total_seconds()
        cutoff = now - window_seconds
        
        # Full Redis key
        redis_key = f"{self._prefix}{key}"
        
        # Pipeline operations for atomicity
        async with self._redis.pipeline() as pipe:
            # Remove expired items (sliding window)
            await pipe.zremrangebyscore(redis_key, 0, cutoff)
            
            # Add current timestamp
            await pipe.zadd(redis_key, {str(now): now})
            
            # Get current count
            await pipe.zcard(redis_key)
            
            # Set expiration on the key
            await pipe.expire(redis_key, int(window_seconds * 1.5))
            
            # Execute pipeline
            results = await pipe.execute()
        
        # Return the count (third command result)
        return results[2]
```

### 4. In-Memory Rate Limiter (for Testing)

```python
# app/infrastructure/rate_limiting/in_memory_rate_limiter.py
import time
from collections import defaultdict
from datetime import timedelta
from typing import Dict, List, Optional, Tuple

from app.core.interfaces.services.rate_limiting.rate_limiter_interface import IRateLimiter

class InMemoryRateLimiter(IRateLimiter):
    """
    In-memory implementation of rate limiter for testing.
    
    Maintains rate limit state in memory using a sliding window algorithm.
    Not suitable for production in distributed environments.
    """
    
    def __init__(self):
        """Initialize the in-memory rate limiter."""
        # Dict of key -> list of request timestamps
        self._requests: Dict[str, List[float]] = defaultdict(list)
    
    async def is_rate_limited(
        self,
        key: str,
        max_requests: int,
        window: timedelta
    ) -> Tuple[bool, int, Optional[timedelta]]:
        """Check if a request should be rate limited."""
        # Clean up expired entries
        now = time.time()
        cutoff = now - window.total_seconds()
        
        # Keep only non-expired timestamps
        self._requests[key] = [t for t in self._requests[key] if t > cutoff]
        
        # Get current count
        count = len(self._requests[key])
        
        # Check if over limit
        if count >= max_requests:
            # Calculate time until oldest request expires
            if self._requests[key]:
                oldest = min(self._requests[key])
                reset_in = oldest + window.total_seconds() - now
                remaining = timedelta(seconds=max(0, reset_in))
            else:
                remaining = None
                
            return (True, count, remaining)
        
        # Not rate limited
        return (False, count, None)
    
    async def increment(
        self,
        key: str,
        window: timedelta
    ) -> int:
        """Increment the counter for a rate limit key."""
        # Clean up expired entries first
        now = time.time()
        cutoff = now - window.total_seconds()
        
        # Keep only non-expired timestamps
        self._requests[key] = [t for t in self._requests[key] if t > cutoff]
        
        # Add current timestamp
        self._requests[key].append(now)
        
        # Return current count
        return len(self._requests[key])
```

### 5. Rate Limiting Middleware

```python
# app/core/security/rate_limiting/middleware.py
from fastapi import Request, Response
from starlette.status import HTTP_429_TOO_MANY_REQUESTS
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.core.services.rate_limiting.service import RateLimiterService

class RateLimitingMiddleware(BaseHTTPMiddleware):
    """
    Middleware for enforcing rate limits on API requests.
    
    This middleware checks rate limits based on various dimensions:
    - IP address for anonymous requests
    - User ID for authenticated requests
    - Endpoint path for endpoint-specific limits
    
    Rate limit headers are added to responses, and requests exceeding
    limits receive a 429 Too Many Requests response.
    """
    
    def __init__(
        self,
        app,
        service: RateLimiterService
    ):
        """
        Initialize the rate limiting middleware.
        
        Args:
            app: The FastAPI application
            service: Rate limiter service for enforcing limits
        """
        super().__init__(app)
        self._service = service
    
    async def dispatch(
        self,
        request: Request,
        call_next
    ) -> Response:
        """
        Process the request with rate limiting.
        
        Args:
            request: The incoming request
            call_next: The next middleware or route handler
            
        Returns:
            The response, potentially a 429 if rate limited
        """
        # Get client IP
        client_ip = request.client.host if request.client else "unknown"
        
        # Determine rate limit policy based on path
        policy = self._get_policy_for_path(request.url.path, request.method)
        
        # Check IP-based rate limit for all requests
        is_limited, count, reset_in = await self._service.check_rate_limit(
            dimension="ip",
            key=client_ip,
            policy_name=policy
        )
        
        if is_limited:
            return self._create_rate_limit_response(count, reset_in)
        
        # For authenticated requests, also check user-based rate limit
        user = getattr(request.state, "user", None)
        if user:
            user_id = getattr(user, "id", None)
            role = getattr(user, "role", None)
            
            if user_id:
                is_limited, count, reset_in = await self._service.check_rate_limit(
                    dimension="user",
                    key=str(user_id),
                    policy_name=policy,
                    role=role
                )
                
                if is_limited:
                    return self._create_rate_limit_response(count, reset_in)
        
        # Process the request if not rate limited
        response = await call_next(request)
        
        # Add rate limit headers to the response
        response.headers["X-RateLimit-Limit"] = str(self._get_limit_for_policy(policy))
        response.headers["X-RateLimit-Remaining"] = str(max(0, self._get_limit_for_policy(policy) - count))
        if reset_in:
            response.headers["X-RateLimit-Reset"] = str(int(reset_in.total_seconds()))
        
        return response
    
    def _get_policy_for_path(self, path: str, method: str) -> str:
        """Determine which rate limit policy to apply based on the request path."""
        if "/auth/login" in path:
            return "login"
        elif "/patients" in path:
            return "patient_lookup"
        elif method in {"POST", "PUT", "PATCH", "DELETE"}:
            return "write_operations"
        else:
            return "global"
    
    def _get_limit_for_policy(self, policy: str) -> int:
        """Get the max requests for a policy (simplified - should use service)."""
        # This is a simplified version - should get from service
        policy_limits = {
            "global": 100,
            "login": 5,
            "patient_lookup": 60,
            "write_operations": 30
        }
        return policy_limits.get(policy, 100)
    
    def _create_rate_limit_response(self, count: int, reset_in) -> Response:
        """Create a 429 Too Many Requests response with appropriate headers."""
        headers = {
            "X-RateLimit-Limit": str(count),
            "X-RateLimit-Remaining": "0"
        }
        
        if reset_in:
            headers["X-RateLimit-Reset"] = str(int(reset_in.total_seconds()))
            retry_after = max(1, int(reset_in.total_seconds()))
            headers["Retry-After"] = str(retry_after)
        
        return JSONResponse(
            status_code=HTTP_429_TOO_MANY_REQUESTS,
            content={"detail": "Rate limit exceeded. Please try again later."},
            headers=headers
        )
```

## Dependency Injection

The Rate Limiter is provided through FastAPI's dependency injection system:

```python
# app/core/security/rate_limiting/service.py (continued)
from fastapi import Depends
from app.core.config import get_settings, Settings
from app.core.interfaces.services.redis_service_interface import IRedisService
from app.infrastructure.rate_limiting.redis_rate_limiter import RedisRateLimiter
from app.presentation.dependencies.redis import get_redis_service

def get_rate_limiter_service(
    redis_service: IRedisService = Depends(get_redis_service),
    settings: Settings = Depends(get_settings)
) -> RateLimiterService:
    """
    Dependency provider for Rate Limiter Service.
    
    Args:
        redis_service: Redis service for storage
        settings: Application settings
    
    Returns:
        RateLimiterService implementation
    """
    limiter = RedisRateLimiter(redis_service)
    return RateLimiterService(limiter, settings)
```

## Integration in Application Factory

The Rate Limiting Middleware is registered in the application factory:

```python
# app/app_factory.py (excerpt)
def create_application(...) -> FastAPI:
    # ... (initial application setup)
    
    # Configure middleware
    app.add_middleware(RequestIdMiddleware)
    # ... other middleware
    
    # Add rate limiting middleware
    rate_limiter_service = get_rate_limiter_service(app.state.redis_service, app.state.settings)
    app.add_middleware(
        RateLimitingMiddleware,
        service=rate_limiter_service
    )
    
    # ... (remaining application setup)
```

## HIPAA Compliance Considerations

The Rate Limiting Middleware contributes to HIPAA compliance:

1. **Access Control**: Prevents brute force attacks on authentication endpoints
2. **Security Management**: Protects against DoS attacks per §164.308(a)(1)(ii)(B)
3. **Audit Controls**: Rate limit events can be logged for compliance review
4. **Emergency Access**: Administrative endpoints can be exempted from limits when needed

## Configuration

Rate limits are configured through application settings:

```python
# app/core/config/settings.py (excerpt)
class Settings(BaseSettings):
    # ... other settings
    
    # Rate limiting settings
    RATE_LIMIT_DEFAULT_REQUESTS: int = 100
    RATE_LIMIT_LOGIN_REQUESTS: int = 5
    RATE_LIMIT_PATIENT_REQUESTS: int = 60
    RATE_LIMIT_WRITE_REQUESTS: int = 30
    
    # ... other settings
```

## Testing Considerations

When testing with the Rate Limiting Middleware:

1. **Isolation**: Use the in-memory implementation for unit tests
2. **Time Sensitivity**: Tests involving rate limits may need time manipulation
3. **Response Headers**: Verify rate limit headers are correctly added
4. **Rate Limit Response**: Ensure 429 responses match the expected format

Example test:

```python
async def test_rate_limiting(test_client):
    """Test that rate limiting works as expected."""
    # Configure a very low limit for testing
    limiter_service = InMemoryRateLimiterService(max_requests=3)
    app.dependency_overrides[get_rate_limiter_service] = lambda: limiter_service
    
    # Make requests up to the limit
    for _ in range(3):
        response = await test_client.get("/api/v1/patients")
        assert response.status_code == 200
        assert "X-RateLimit-Remaining" in response.headers
    
    # Next request should be rate limited
    response = await test_client.get("/api/v1/patients")
    assert response.status_code == 429
    assert "Retry-After" in response.headers
```

## Implementation Challenges

Common challenges when implementing rate limiting:

1. **Distributed Systems**: Ensuring consistent rate limiting across multiple instances
2. **Clock Synchronization**: Time-based algorithms rely on synchronized clocks
3. **Performance Impact**: Minimizing the overhead of rate limit checks
4. **Bypassing Detection**: Identifying and mitigating attempts to circumvent limits

## Optimization Techniques

For high-traffic applications, several optimizations can be applied:

1. **Layered Approach**: Simple global checks first, specific checks only when needed
2. **Caching Decisions**: Short-term caching of rate limit decisions for repeat clients
3. **Sampling**: Applying rate limiting to a percentage of requests during high load
4. **Client Fingerprinting**: Using multiple attributes to identify clients beyond IP

## Conclusion

The Rate Limiting Middleware is a critical security component of the Clarity AI Backend. When properly implemented, it protects the system against various attack vectors, prevents abuse, and ensures fair resource allocation for all users. The clean architecture approach with an interface-based design enables flexible implementation, testing, and scaling as requirements evolve.
