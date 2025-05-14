# Domain Service Interfaces in Clarity AI Backend

## Overview

Domain Service Interfaces form the mathematical backbone of the Clarity AI Backend's revolutionary psychiatric digital twin platform. These interfaces define pure abstractions that encapsulate complex domain operations while maintaining perfect conceptual integrity across architectural boundaries. This document provides a comprehensive guide to the system's core domain service interfaces, their implementation patterns, and architectural significance.

## Foundational Principles

Domain Service Interfaces in the Clarity AI Backend adhere to these fundamental principles:

1. **Pure Abstraction**: Interfaces define behavior without implementation details
2. **Domain Focus**: Each interface represents a cohesive set of domain operations
3. **Implementation Independence**: Interfaces have no dependencies on infrastructure concerns
4. **Complete Contracts**: Interfaces fully specify their behavioral contracts
5. **Architectural Boundary**: Interfaces enable dependency inversion across layers

## Core Domain Service Interfaces

### Authentication & Security Interfaces

#### `IPasswordHandler`

Abstracts password hashing and verification operations:

```python
from abc import ABC, abstractmethod

class IPasswordHandler(ABC):
    @abstractmethod
    def hash_password(self, plain_text_password: str) -> str:
        """Hash a plain text password securely.
        
        Args:
            plain_text_password: The plain text password to hash.
            
        Returns:
            A secure hash of the password with salt.
        """
        raise NotImplementedError
    
    @abstractmethod
    def verify(self, plain_text_password: str, hashed_password: str) -> bool:
        """Verify if a plain text password matches a hashed password.
        
        Args:
            plain_text_password: The plain text password to verify.
            hashed_password: The hashed password to compare against.
            
        Returns:
            True if the password matches, False otherwise.
        """
        raise NotImplementedError
```

**Current Implementation Status**: 
- Interface defined in `app/core/interfaces/security/password_handler_interface.py`
- Primary implementation: `PasswordHandler` in `app/infrastructure/security/password_handler.py`
- Uses Passlib with bcrypt for secure password handling

**Architectural Violations**:
- Some services bypass the interface and use the concrete implementation directly
- Dependency injection inconsistently applied in security-related endpoints

#### `IAuditLogger`

Defines contract for HIPAA-compliant security audit logging:

```python
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, Optional
from uuid import UUID

class IAuditLogger(ABC):
    @abstractmethod
    async def log_security_event(
        self,
        event_type: str,
        user_id: Optional[UUID],
        resource_type: str,
        resource_id: Optional[str],
        action: str,
        status: str,
        details: Optional[Dict[str, Any]] = None,
        timestamp: Optional[datetime] = None
    ) -> None:
        """Log a security-related event for audit purposes.
        
        Args:
            event_type: Type of security event (auth, access, etc.)
            user_id: ID of user performing the action, if available
            resource_type: Type of resource being accessed
            resource_id: ID of the resource being accessed, if applicable
            action: Action being performed (create, read, update, delete)
            status: Outcome status (success, failure, etc.)
            details: Additional details about the event
            timestamp: Event timestamp, defaults to current time if None
        """
        raise NotImplementedError
    
    @abstractmethod
    async def log_phi_access(
        self,
        user_id: UUID,
        patient_id: UUID,
        access_reason: str,
        data_elements: Dict[str, Any],
        timestamp: Optional[datetime] = None
    ) -> None:
        """Log access to Protected Health Information (PHI).
        
        Args:
            user_id: ID of user accessing the PHI
            patient_id: ID of patient whose PHI is being accessed
            access_reason: Clinical or administrative reason for access
            data_elements: PHI elements being accessed
            timestamp: Access timestamp, defaults to current time if None
        """
        raise NotImplementedError
```

**Current Implementation Status**:
- Interface defined in `app/core/interfaces/services/audit_logger_interface.py`
- Primary implementation: `AuditLogger` in `app/infrastructure/logging/audit_logger.py`
- Used by authentication, PHI access services, and API endpoints

**Architectural Violations**:
- JWTService directly imports concrete AuditLogger rather than depending on interface
- Inconsistent logging of PHI access across the codebase

#### `ITokenBlacklistRepository`

Manages blacklisted authentication tokens:

```python
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Optional

class ITokenBlacklistRepository(ABC):
    @abstractmethod
    async def add_to_blacklist(self, token: str, expires_at: datetime) -> None:
        """Add a token to the blacklist.
        
        Args:
            token: Token to blacklist
            expires_at: When the token would have expired
        """
        raise NotImplementedError
    
    @abstractmethod
    async def is_blacklisted(self, token: str) -> bool:
        """Check if a token is blacklisted.
        
        Args:
            token: Token to check
            
        Returns:
            True if the token is blacklisted, False otherwise
        """
        raise NotImplementedError
    
    @abstractmethod
    async def clear_expired(self, before: Optional[datetime] = None) -> int:
        """Remove expired tokens from the blacklist.
        
        Args:
            before: Optional timestamp, remove tokens expiring before this time
                   If None, use current time
                   
        Returns:
            Number of tokens removed
        """
        raise NotImplementedError
```

**Current Implementation Status**:
- Interface missing, required for JWTService implementation
- Referenced but commented out in `app/application/security/jwt_service.py`
- Primary implementation needs to be created in infrastructure layer

**Architectural Violations**:
- Interface definition missing from core/interfaces
- Implementation missing from infrastructure layer
- JWT service has commented-out blacklisting logic due to missing component

### Data Access Interfaces

#### `ITokenRepository`

Manages authentication tokens:

```python
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Optional
from uuid import UUID

class ITokenRepository(ABC):
    @abstractmethod
    async def create_refresh_token(self, user_id: UUID, expires_at: datetime) -> str:
        """Create and store a new refresh token.
        
        Args:
            user_id: User ID associated with the token
            expires_at: Token expiration timestamp
            
        Returns:
            Created refresh token string
        """
        raise NotImplementedError
    
    @abstractmethod
    async def validate_refresh_token(self, token: str) -> Optional[UUID]:
        """Validate a refresh token and return the associated user ID.
        
        Args:
            token: Refresh token to validate
            
        Returns:
            User ID if token is valid, None otherwise
        """
        raise NotImplementedError
    
    @abstractmethod
    async def revoke_refresh_token(self, token: str) -> bool:
        """Revoke a refresh token.
        
        Args:
            token: Refresh token to revoke
            
        Returns:
            True if token was found and revoked, False otherwise
        """
        raise NotImplementedError
    
    @abstractmethod
    async def revoke_all_user_tokens(self, user_id: UUID) -> int:
        """Revoke all refresh tokens for a user.
        
        Args:
            user_id: User ID to revoke tokens for
            
        Returns:
            Number of tokens revoked
        """
        raise NotImplementedError
```

**Current Implementation Status**:
- Interface defined in `app/domain/interfaces/token_repository.py`
- Should be moved to `app/core/interfaces/repositories/token_repository_interface.py`
- Primary implementation: `SQLAlchemyTokenRepository`

**Architectural Violations**:
- Interface defined in incorrect layer (domain instead of core)
- Implementation may have direct dependencies on infrastructure

#### `IUserRepository`

Manages user entity persistence:

```python
from abc import ABC, abstractmethod
from typing import List, Optional
from uuid import UUID

from app.core.domain.entities.user import User

class IUserRepository(ABC):
    @abstractmethod
    async def get_by_id(self, user_id: str | UUID) -> Optional[User]:
        """Retrieve a user by ID.
        
        Args:
            user_id: User ID to retrieve
            
        Returns:
            User if found, None otherwise
        """
        raise NotImplementedError
    
    @abstractmethod
    async def get_by_email(self, email: str) -> Optional[User]:
        """Retrieve a user by email address.
        
        Args:
            email: Email address to search for
            
        Returns:
            User if found, None otherwise
        """
        raise NotImplementedError
    
    @abstractmethod
    async def get_by_username(self, username: str) -> Optional[User]:
        """Retrieve a user by username.
        
        Args:
            username: Username to search for
            
        Returns:
            User if found, None otherwise
        """
        raise NotImplementedError
    
    @abstractmethod
    async def create(self, user: User) -> User:
        """Create a new user.
        
        Args:
            user: User entity to create
            
        Returns:
            Created user with generated ID
        """
        raise NotImplementedError
    
    @abstractmethod
    async def update(self, user: User) -> Optional[User]:
        """Update an existing user.
        
        Args:
            user: User entity with updated properties
            
        Returns:
            Updated user if found, None otherwise
        """
        raise NotImplementedError
    
    @abstractmethod
    async def delete(self, user_id: str | UUID) -> bool:
        """Delete a user by ID.
        
        Args:
            user_id: User ID to delete
            
        Returns:
            True if user was found and deleted, False otherwise
        """
        raise NotImplementedError
    
    @abstractmethod
    async def list_users(self, skip: int = 0, limit: int = 100) -> List[User]:
        """List users with pagination.
        
        Args:
            skip: Number of users to skip
            limit: Maximum number of users to return
            
        Returns:
            List of users
        """
        raise NotImplementedError
```

**Current Implementation Status**:
- Duplicated in `app/core/interfaces/repositories/user_repository_interface.py` and `app/core/interfaces/repositories/user_repository.py`
- Primary implementation: `SQLAlchemyUserRepository`

**Architectural Violations**:
- Duplicate interface definitions causing import confusion
- Inconsistent method signatures between interface and implementation

### External Integration Interfaces

#### `IRedisService`

Abstracts Redis caching and data storage operations:

```python
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Set, Union
from datetime import timedelta

class IRedisService(ABC):
    @abstractmethod
    async def get(self, key: str) -> Optional[bytes]:
        """Get a value from Redis by key.
        
        Args:
            key: Redis key to retrieve
            
        Returns:
            Value as bytes if found, None otherwise
        """
        raise NotImplementedError
    
    @abstractmethod
    async def set(self, key: str, value: Union[str, bytes, int, float], 
                 expiration: Optional[timedelta] = None) -> bool:
        """Set a value in Redis with optional expiration.
        
        Args:
            key: Redis key to set
            value: Value to store
            expiration: Optional expiration time
            
        Returns:
            True if successful, False otherwise
        """
        raise NotImplementedError
    
    @abstractmethod
    async def delete(self, key: str) -> int:
        """Delete a key from Redis.
        
        Args:
            key: Redis key to delete
            
        Returns:
            Number of keys deleted (0 or 1)
        """
        raise NotImplementedError
    
    @abstractmethod
    async def exists(self, key: str) -> bool:
        """Check if a key exists in Redis.
        
        Args:
            key: Redis key to check
            
        Returns:
            True if key exists, False otherwise
        """
        raise NotImplementedError
    
    @abstractmethod
    async def increment(self, key: str, amount: int = 1) -> int:
        """Increment a numeric value in Redis.
        
        Args:
            key: Redis key to increment
            amount: Amount to increment by
            
        Returns:
            New value after increment
        """
        raise NotImplementedError
    
    @abstractmethod
    async def hset(self, key: str, field: str, value: Union[str, bytes, int, float]) -> int:
        """Set a field in a Redis hash.
        
        Args:
            key: Redis hash key
            field: Hash field name
            value: Value to store
            
        Returns:
            1 if field is new, 0 if field existed and was updated
        """
        raise NotImplementedError
    
    @abstractmethod
    async def hget(self, key: str, field: str) -> Optional[bytes]:
        """Get a field from a Redis hash.
        
        Args:
            key: Redis hash key
            field: Hash field name
            
        Returns:
            Field value as bytes if found, None otherwise
        """
        raise NotImplementedError
    
    @abstractmethod
    async def hgetall(self, key: str) -> Dict[bytes, bytes]:
        """Get all fields and values from a Redis hash.
        
        Args:
            key: Redis hash key
            
        Returns:
            Dictionary of field names and values
        """
        raise NotImplementedError
```

**Current Implementation Status**:
- Interface defined in `app/core/interfaces/services/redis_service_interface.py`
- Primary implementation: `RedisService` in infrastructure layer
- Redis client stored directly in app state rather than through interface

**Architectural Violations**:
- Direct access to `app.state.redis` throughout codebase rather than through interface
- Missing dependency injection in services that use Redis

### Machine Learning Interfaces

#### `IModelService`

Abstracts ML model operations for psychiatric analysis:

```python
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from uuid import UUID

from app.core.domain.entities.ml_model import ModelInfo, InferenceResult

class IModelService(ABC):
    @abstractmethod
    async def get_model_info(self, model_id: str) -> ModelInfo:
        """Get information about a specific model.
        
        Args:
            model_id: Unique identifier for the model
            
        Returns:
            Model metadata information
            
        Raises:
            ModelNotFoundError: If model doesn't exist
        """
        raise NotImplementedError
    
    @abstractmethod
    async def list_available_models(self) -> List[ModelInfo]:
        """List all available models.
        
        Returns:
            List of available model information
        """
        raise NotImplementedError
    
    @abstractmethod
    async def run_inference(
        self, 
        model_id: str, 
        input_data: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> InferenceResult:
        """Run inference using the specified model.
        
        Args:
            model_id: Unique identifier for the model
            input_data: Model input data
            context: Optional contextual information
            
        Returns:
            Inference result from the model
            
        Raises:
            ModelNotFoundError: If model doesn't exist
            InferenceError: If inference fails
        """
        raise NotImplementedError
    
    @abstractmethod
    async def get_feature_importance(
        self,
        model_id: str,
        inference_id: UUID
    ) -> Dict[str, float]:
        """Get feature importance for a specific inference result.
        
        Args:
            model_id: Unique identifier for the model
            inference_id: ID of the inference result
            
        Returns:
            Dictionary mapping feature names to importance scores
            
        Raises:
            ModelNotFoundError: If model doesn't exist
            InferenceNotFoundError: If inference result doesn't exist
        """
        raise NotImplementedError
```

**Current Implementation Status**:
- Interface missing, needs to be defined in core layer
- `InferenceResult` entity missing from domain layer
- `ModelInfo` defined in infrastructure instead of domain layer

**Architectural Violations**:
- `ModelInfo` defined in wrong layer (infrastructure)
- `InferenceResult` entity missing
- Direct use of infrastructure model implementations without interfaces

#### `IPAT` (Pretrained Actigraphy Transformer)

Abstracts actigraphy analysis for sleep and activity pattern analysis:

```python
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from datetime import datetime
from uuid import UUID

from app.core.domain.entities.actigraphy import ActigraphyData
from app.core.domain.entities.ml_model import ModelInfo, InferenceResult

class IPAT(ABC):
    @abstractmethod
    async def get_model_info(self) -> ModelInfo:
        """Get information about the PAT model.
        
        Returns:
            Model metadata information
        """
        raise NotImplementedError
    
    @abstractmethod
    async def analyze_actigraphy(
        self,
        actigraphy_data: ActigraphyData,
        patient_id: UUID,
        **kwargs
    ) -> InferenceResult:
        """Analyze actigraphy data for sleep and activity patterns.
        
        Args:
            actigraphy_data: Preprocessed actigraphy data
            patient_id: Patient identifier
            **kwargs: Additional analysis parameters
            
        Returns:
            Analysis results
            
        Raises:
            AnalysisError: If analysis fails
        """
        raise NotImplementedError
    
    @abstractmethod
    async def detect_anomalies(
        self,
        actigraphy_data: ActigraphyData,
        patient_id: UUID,
        **kwargs
    ) -> List[Dict[str, Any]]:
        """Detect anomalies in actigraphy data.
        
        Args:
            actigraphy_data: Preprocessed actigraphy data
            patient_id: Patient identifier
            **kwargs: Additional detection parameters
            
        Returns:
            List of detected anomalies with timestamps and confidence scores
            
        Raises:
            AnalysisError: If analysis fails
        """
        raise NotImplementedError
    
    @abstractmethod
    async def get_sleep_metrics(
        self,
        actigraphy_data: ActigraphyData,
        patient_id: UUID,
        **kwargs
    ) -> Dict[str, Any]:
        """Extract sleep metrics from actigraphy data.
        
        Args:
            actigraphy_data: Preprocessed actigraphy data
            patient_id: Patient identifier
            **kwargs: Additional analysis parameters
            
        Returns:
            Dictionary of sleep metrics
            
        Raises:
            AnalysisError: If analysis fails
        """
        raise NotImplementedError
```

**Current Implementation Status**:
- Interface defined but refactoring required
- Primary implementations: `BedrockPAT`, other PAT variants
- Tests partially implemented and passing

**Architectural Violations**:
- Inconsistent parameter naming across implementations
- Domain entities misplaced in infrastructure layer

### Rate Limiting Interfaces

#### `IRateLimiter`

Abstracts rate limiting operations for API security:

```python
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Optional, Tuple

class IRateLimiter(ABC):
    @abstractmethod
    async def is_allowed(
        self, 
        key: str, 
        max_requests: int, 
        time_window_seconds: int
    ) -> Tuple[bool, int]:
        """Check if a request is allowed under rate limiting rules.
        
        Args:
            key: Unique identifier for the client/endpoint
            max_requests: Maximum number of requests allowed
            time_window_seconds: Time window in seconds
            
        Returns:
            Tuple with (is_allowed, remaining_requests)
        """
        raise NotImplementedError
    
    @abstractmethod
    async def reset(self, key: str) -> bool:
        """Reset rate limiting counters for a key.
        
        Args:
            key: Unique identifier to reset
            
        Returns:
            True if reset was successful, False otherwise
        """
        raise NotImplementedError
    
    @abstractmethod
    async def get_remaining(self, key: str) -> Optional[int]:
        """Get remaining request count for a key.
        
        Args:
            key: Unique identifier to check
            
        Returns:
            Remaining requests if key exists, None otherwise
        """
        raise NotImplementedError
```

**Current Implementation Status**:
- Interface missing from core layer
- Implementation exists as `InMemoryRateLimiter`
- Middleware referencing missing method

**Architectural Violations**:
- Interface missing or incorrect
- Middleware error: `AttributeError: 'InMemoryRateLimiter' object has no attribute 'process_request'`

## Implementation Strategies

Domain Service Interfaces in the Clarity AI Backend follow these implementation patterns:

### 1. Interface Definition

Interfaces are defined using Python's ABC (Abstract Base Class):

```python
from abc import ABC, abstractmethod

class ISomeService(ABC):
    @abstractmethod
    def some_method(self, param: str) -> bool:
        raise NotImplementedError
```

### 2. Implementation in Infrastructure

Concrete implementations are provided in the infrastructure layer:

```python
class ConcreteService(ISomeService):
    def __init__(self, dependencies):
        self._dependencies = dependencies
        
    def some_method(self, param: str) -> bool:
        # Implementation details
        return True
```

### 3. Dependency Injection

Services are injected through FastAPI's dependency system:

```python
def get_service(db: Database = Depends(get_db)) -> ISomeService:
    return ConcreteService(db)

@router.get("/resource/{id}")
async def get_resource(
    id: str,
    service: ISomeService = Depends(get_service)
):
    # Use service through its interface
    result = await service.some_method(id)
    return {"result": result}
```

## Architectural Gaps and Remediation Plan

The Clarity AI Backend exhibits several architectural gaps related to Domain Service Interfaces:

### 1. Missing Interfaces

Several critical interfaces are missing entirely:

- `IPasswordHandler` (referenced but missing)
- `ITokenBlacklistRepository` (referenced but missing)
- `IRateLimiter` (missing correct methods)

**Remediation:**
- Define all missing interfaces in `app/core/interfaces/`
- Follow consistent naming conventions
- Add comprehensive docstrings

### 2. Misplaced Interfaces

Some interfaces are defined in incorrect architectural layers:

- `ITokenRepository` in domain instead of core layer
- `IUserRepository` duplicated across multiple locations

**Remediation:**
- Move interfaces to correct locations
- Remove duplicate definitions
- Update import references throughout codebase

### 3. Inconsistent Implementation

Some concrete implementations don't fully satisfy their interfaces:

- `InMemoryRateLimiter` missing `process_request` method
- Some repository implementations with additional methods not in interface

**Remediation:**
- Align implementations with interface contracts
- Add missing methods to implementations
- Ensure full type compatibility

### 4. Direct Dependency Violations

Some services directly depend on concrete implementations:

- `JWTService` directly imports `AuditLogger`
- Redis client used directly via `app.state.redis`

**Remediation:**
- Replace direct dependencies with interface dependencies
- Implement proper dependency injection
- Update tests to use interface mocks

## Interface Standardization Plan

To standardize Domain Service Interfaces across the Clarity AI Backend:

1. **Naming Conventions**
   - Interfaces prefixed with "I" (e.g., `IUserRepository`)
   - Interface files suffixed with "_interface.py"
   - Group interfaces by domain area in core layer

2. **Documentation Standards**
   - Complete docstrings with Args, Returns, Raises sections
   - Type hints for all parameters and return values
   - Examples for complex interfaces

3. **Method Signatures**
   - Consistent async/sync patterns within each interface
   - Consistent parameter naming and ordering
   - Explicit exception types in docstrings

## Conclusion

Domain Service Interfaces form the mathematical backbone of the Clarity AI Backend's revolutionary psychiatric digital twin platform. While several architectural inconsistencies exist, these interfaces provide the foundation for a clean, maintainable, and extensible system that transcends conventional psychiatric diagnostic approaches.

The strategic refinement of these interfaces according to the remediation plan will enhance the system's architectural integrity, allowing it to evolve while maintaining perfect conceptual clarity. By strictly adhering to interface-based design, the Clarity AI Backend achieves a level of decoupling and extensibility that enables the revolutionary advances in psychiatric care it aims to deliver.
