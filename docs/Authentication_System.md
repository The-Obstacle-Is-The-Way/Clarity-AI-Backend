# Authentication System

## Overview

The Authentication System is a foundational security component of the Clarity AI Backend, providing secure identity management and access control for the psychiatric digital twin platform. It implements robust token-based authentication with refresh capabilities while adhering to HIPAA security requirements for protected health information (PHI).

## Implementation Status

> ⚠️ **IMPORTANT**: There are several discrepancies between this documentation and the actual implementation in the codebase:

| Component | Documentation Status | Implementation Status | Notes |
|-----------|---------------------|----------------------|-------|
| AuthServiceInterface | ✅ Documented | ✅ Implemented | Located in app/core/interfaces/services/auth_service_interface.py |
| JWT Service | ✅ Documented | ⚠️ Partially Implemented | Implementation exists in app/application/security/jwt_service.py but with commented-out blacklisting functionality |
| Token Blacklist | ✅ Documented | ❌ Not Implemented | Interface exists but implementation is missing; token blacklisting functionality is commented out |
| Password Handler | ✅ Documented | ✅ Implemented | Located in app/infrastructure/security/password/password_handler.py |
| Multi-Factor Authentication | ✅ Documented | ❌ Not Implemented | Documented but not implemented in the codebase |

### Current Security Gaps

1. **Token Revocation**: Without token blacklisting, tokens cannot be revoked before expiration, creating a security vulnerability when users log out
2. **HIPAA Compliance Issues**: Session termination and immediate access revocation are not fully implemented as required by HIPAA
3. **Audit Trail**: While the audit logging interface exists, it may not be capturing all required authentication events

## Clean Architecture Context

The Authentication System exemplifies clean architecture principles through:

1. **Interface Segregation**: Authentication functionality is defined through clear interface contracts
2. **Dependency Inversion**: High-level modules depend on abstractions, not concrete implementations
3. **Single Responsibility**: Each component handles one aspect of authentication (tokens, password management, etc.)
4. **Domain Independence**: Core authentication logic remains independent of delivery mechanisms

## System Components

### Authentication Service Interface

The `AuthServiceInterface` defines the contract for authentication operations:

```python
class AuthServiceInterface(ABC):
    """
    Abstract interface for authentication services.
    
    This interface defines the contract for authentication operations,
    allowing for different implementations (e.g., JWT, OAuth) while
    maintaining consistent usage throughout the application.
    """
    
    @abstractmethod
    async def authenticate_user(self, username_or_email: str, password: str) -> User | None:
        """
        Authenticate a user with username/email and password.
        """
        
    @abstractmethod
    async def login(self, username: str, password: str, remember_me: bool) -> TokenResponseSchema:
        """
        Authenticate a user and return access and refresh tokens.
        """
        
    @abstractmethod
    async def logout(self, response: Response) -> None:
        """
        Log out the current user, potentially invalidating tokens or clearing cookies.
        """
        
    @abstractmethod
    async def refresh_access_token(self, refresh_token_str: str) -> TokenResponseSchema:
        """
        Refresh an access token using a valid refresh token.
        """
        
    @abstractmethod
    async def register_user(self, email: str, password: str, full_name: str | None) -> UserRegistrationResponseSchema:
        """
        Register a new user.
        """
        
    @abstractmethod
    async def get_current_session_info(self) -> SessionInfoResponseSchema:
        """
        Get information about the current user's session.
        """
```

### JWT Service Implementation

The actual JWTService implementation in the codebase (app/application/security/jwt_service.py) differs from the documented interface:

```python
class JWTService:
    """
    Service for JWT token generation, validation, and management.
    
    This service adheres to HIPAA security requirements for authentication
    and authorization, including:
    - Secure token generation with appropriate expiration
    - Token validation and verification
    - Token blacklisting to enforce logout (INCOMPLETE)
    - Audit logging of token-related activities
    """

    def __init__(
        self,
        token_repo: ITokenRepository,
        # blacklist_repo: ITokenBlacklistRepository, # TODO: Add back when defined and injected
        audit_logger: IAuditLogger
    ):
        """Initialize the JWT service."""
        self.token_repo = token_repo
        # self.blacklist_repo = blacklist_repo # TODO: Add back when defined and injected
        self.audit_logger = audit_logger
        self.algorithm = "HS256"  # HMAC with SHA-256
        
    def create_access_token(
        self, 
        user_id: str,
        email: str,
        role: str,
        permissions: list[str],
        session_id: str
    ) -> tuple[str, int]:
        """Create a new access token for a user."""
        # ... implementation details ...
    
    def validate_token(self, token: str, token_type: str = "access") -> dict[str, Any]:
        """Validate a JWT token and return its payload."""
        try:
            # Check if token is blacklisted - COMMENTED OUT IN ACTUAL CODE
            # if self.token_blacklist_repository.is_blacklisted(token):
            #     self.audit_logger.log_security_event(...)
            #     raise TokenBlacklistedException("Token has been revoked")
            
            # Decode token
            payload = jwt.decode(...)
            
            # ... other validation logic ...
```

### Token Blacklist Repository Status

The `ITokenBlacklistRepository` interface is defined but no implementation exists in the codebase. The JWT service contains commented-out code that should use this repository, indicating the token blacklisting functionality is incomplete.

Comments in the JWT service file confirm this issue:
```python
# from app.domain.interfaces.repositories.token_blacklist_repository import (
#     ITokenBlacklistRepository, # TODO: Define this interface in core
#     ITokenRepository,
# )
```

### Password Handler Implementation

The `PasswordHandler` class is implemented and functional, providing secure password operations:

```python
class PasswordHandler:
    """
    Implementation of the password handler interface.
    
    Handles password hashing, verification, and security requirement checking
    using industry-standard algorithms and HIPAA-compliant security practices.
    """
    
    def hash_password(self, password: str) -> str:
        """Hash a password using bcrypt."""
        return pwd_context.hash(password)
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash."""
        return pwd_context.verify(plain_password, hashed_password)
    
    def check_password_requirements(self, password: str) -> Tuple[bool, Optional[str]]:
        """Check if a password meets security requirements."""
        # ... implementation details ...
```

## Authentication Flow

The intended authentication flow is:

1. **User Registration**:
   - User submits registration credentials
   - System validates credentials and password strength
   - Password is securely hashed
   - User account is created with initial status

2. **User Login**:
   - User submits credentials
   - System verifies credentials against stored values
   - If verified, access and refresh tokens are generated
   - Tokens are returned to client for subsequent requests

3. **Authenticated Requests**:
   - Client includes access token in Authorization header
   - System validates token signature and expiration
   - ⚠️ Blacklist status check is NOT implemented
   - If valid, request is processed with user context
   - If invalid, 401 Unauthorized response is returned

4. **Token Refresh**:
   - When access token expires, client uses refresh token
   - System validates refresh token
   - If valid, new access token is generated
   - New token is returned to client

5. **User Logout**:
   - ⚠️ While endpoint exists, token blacklisting is NOT implemented
   - Tokens are NOT added to blacklist
   - Client must destroy local token copies, but server-side revocation is missing

## API Routes

The Authentication API routes are defined in `app/presentation/api/v1/routes/auth.py`:

### Login

```python
@router.post("/login", response_model=TokenResponseSchema)
async def login(
    login_data: LoginRequestSchema,
    auth_service: AuthServiceInterface = Depends(get_auth_service)
) -> TokenResponseSchema:
    """
    Authenticate a user and return access and refresh tokens.
    """
```

### Token Refresh

```python
@router.post("/refresh", response_model=TokenResponseSchema)
async def refresh_token(
    refresh_data: RefreshTokenRequestSchema,
    auth_service: AuthServiceInterface = Depends(get_auth_service)
) -> TokenResponseSchema:
    """
    Refresh an access token using a valid refresh token.
    """
```

### User Registration

```python
@router.post("/register", response_model=UserRegistrationResponseSchema, status_code=status.HTTP_201_CREATED)
async def register(
    registration_data: UserRegistrationRequestSchema,
    auth_service: AuthServiceInterface = Depends(get_auth_service)
) -> UserRegistrationResponseSchema:
    """
    Register a new user account.
    """
```

### Logout

```python
@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    response: Response,
    auth_service: AuthServiceInterface = Depends(get_auth_service)
) -> None:
    """
    Logs out the current user by invalidating tokens/session.
    
    ⚠️ WARNING: Due to missing token blacklisting implementation,
    this endpoint does not actually invalidate tokens!
    """
```

## Security Considerations

### HIPAA Compliance

The Authentication System has several gaps in HIPAA compliance:

1. **Password Security**:
   - ✅ Passwords are hashed using strong algorithms
   - ✅ Password requirements enforce complexity
   - ❌ Password rotation policies not implemented

2. **Token Security**:
   - ✅ Access tokens are short-lived
   - ❌ Refresh tokens cannot be revoked (blacklisting not implemented)
   - ✅ Token validation prevents tampering and ensures integrity

3. **Session Management**:
   - ❌ Sessions cannot be forcibly terminated (blacklisting not implemented)
   - ❌ Inactivity timeouts not fully implemented
   - ⚠️ Session tracking exists but revocation is limited

4. **Audit Trail**:
   - ✅ Interface for audit logging exists
   - ⚠️ Not all authentication events may be properly logged
   - ⚠️ Failed authentication monitoring needs validation

### Multi-Factor Authentication

Despite being documented, multi-factor authentication is not implemented:

1. **TOTP Implementation**: ❌ Not implemented
2. **MFA Enrollment**: ❌ Not implemented 
3. **Risk-Based Authentication**: ❌ Not implemented

## Implementation Roadmap

To address the authentication system gaps, the following changes are needed:

1. **Token Blacklisting**:
   - Implement `RedisTokenBlacklistRepository` class
   - Uncomment and complete token blacklisting in JWT service
   - Update logout endpoint to use blacklisting

2. **HIPAA Compliance**:
   - Implement session timeout mechanisms
   - Ensure comprehensive audit logging
   - Add password rotation policies

3. **Multi-Factor Authentication**:
   - Implement TOTP validation for MFA
   - Create MFA enrollment endpoints
   - Add MFA verification to login flow

## Data Models

### Authentication Request Models

- **LoginRequestSchema**: Credentials for authentication
- **RefreshTokenRequestSchema**: Refresh token for obtaining new access token
- **UserRegistrationRequestSchema**: New user registration details

### Authentication Response Models

- **TokenResponseSchema**: Access and refresh tokens with metadata
- **UserRegistrationResponseSchema**: Created user information
- **SessionInfoResponseSchema**: Information about current session

## Related Components

- **User Repository**: Stores and retrieves user credentials and profile information
- **Audit Logger**: Records authentication events for compliance and security analysis
- **Rate Limiter**: Prevents brute force attacks on authentication endpoints
- **Redis Service**: Supports token blacklisting and session management
