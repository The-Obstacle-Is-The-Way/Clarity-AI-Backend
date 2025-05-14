# Authentication System

## Overview

The Authentication System is a foundational security component of the Clarity AI Backend, providing secure identity management and access control for the psychiatric digital twin platform. It implements robust token-based authentication with refresh capabilities while adhering to HIPAA security requirements for protected health information (PHI).

## Current Implementation Status

The Authentication System currently implements these key components:

| Component | Status | Location | Notes |
|-----------|--------|----------|-------|
| AuthServiceInterface | ✅ Implemented | app/core/interfaces/services/auth_service_interface.py | Defines the contract for authentication operations |
| JWT Service | ✅ Implemented | app/application/security/jwt_service.py | Handles token generation, validation, and blacklisting |
| Token Blacklist | ✅ Implemented | Via ITokenBlacklistRepository | Used by JWT service to invalidate tokens |
| Password Handler | ✅ Implemented | app/infrastructure/security/password/password_handler.py | Handles password hashing and verification |
| Audit Logging | ✅ Implemented | Via IAuditLogger | Logs all authentication-related events |

## Clean Architecture Implementation

The Authentication System exemplifies clean architecture principles through:

1. **Interface Segregation**: Authentication functionality is defined through clear, cohesive interface contracts
2. **Dependency Inversion**: High-level authentication policies are defined independently of low-level mechanisms
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
        Log out the current user, invalidating tokens or clearing cookies.
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

The `JWTService` class implements token handling with HIPAA-compliant security features:

```python
class JWTService:
    """
    Service for JWT token generation, validation, and management.
    
    This service adheres to HIPAA security requirements for authentication
    and authorization, including:
    - Secure token generation with appropriate expiration
    - Token validation and verification
    - Token blacklisting to enforce logout
    - Audit logging of token-related activities
    """

    def __init__(
        self,
        token_repo: ITokenRepository,
        blacklist_repo: ITokenBlacklistRepository,
        audit_logger: IAuditLogger
    ):
        """Initialize the JWT service."""
        self.token_repo = token_repo
        self.blacklist_repo = blacklist_repo
        self.audit_logger = audit_logger
        self.algorithm = "HS256"  # HMAC with SHA-256
```

The service provides the following key methods:

1. `create_access_token`: Generates a short-lived access token with user context
2. `create_refresh_token`: Generates a longer-lived refresh token
3. `validate_token`: Verifies token integrity, expiration, and blacklist status
4. `blacklist_token`: Invalidates tokens during logout for immediate access revocation
5. `blacklist_session_tokens`: Invalidates all tokens for a user session

### Token Security Features

The JWT implementation includes several security features:

1. **Short Expiration Times**: Access tokens expire quickly to limit exposure
2. **Token Blacklisting**: Invalidates tokens before their natural expiration
3. **JTI (JWT ID) Tracking**: Unique identifier for each token enabling revocation
4. **Session Binding**: Tokens are bound to specific user sessions
5. **Comprehensive Auditing**: All token operations are logged for compliance

### Password Handler Implementation

The `PasswordHandler` class implements secure password operations using bcrypt:

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
    
    def check_password_requirements(self, password: str) -> tuple[bool, str | None]:
        """Check if a password meets security requirements."""
        # Requirements implementation
```

## Authentication Flow

The authentication flow follows these steps:

1. **User Registration**:
   - User submits registration credentials
   - System validates credentials and password strength
   - Password is securely hashed using bcrypt
   - User account is created with initial status

2. **User Login**:
   - User submits credentials (username/email and password)
   - System verifies credentials against stored values
   - If verified, access and refresh tokens are generated
   - Comprehensive login event is recorded in audit log
   - Tokens are returned to client for subsequent requests

3. **Authenticated Requests**:
   - Client includes access token in Authorization header
   - System validates token signature and expiration
   - System verifies token is not blacklisted
   - If valid, request is processed with user context
   - If invalid, 401 Unauthorized response is returned

4. **Token Refresh**:
   - When access token expires, client uses refresh token
   - System validates refresh token
   - If valid, new access token is generated
   - New token is returned to client
   - Refresh event is recorded in audit log

5. **User Logout**:
   - Client sends logout request
   - System blacklists current token
   - System can optionally blacklist all session tokens
   - Logout event is recorded in audit log
   - Client destroys local token copies

## HIPAA Compliance Features

The Authentication System implements these HIPAA security requirements:

1. **Access Controls**: Role-based access with fine-grained permissions
2. **Automatic Session Timeouts**: Short-lived tokens enforce session expiration
3. **Emergency Access**: Administrative override capabilities for emergency situations
4. **Audit Controls**: Comprehensive logging of authentication events
5. **Automatic Logoff**: Token expiration and blacklisting mechanisms
6. **Unique User Identification**: Each user has unique credentials and identifiers
7. **Encryption and Decryption**: All tokens are cryptographically secured

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
    Register a new user.
    """
```

### Logout

```python
@router.post("/logout")
async def logout(
    auth_service: AuthServiceInterface = Depends(get_auth_service),
    response: Response = None
) -> dict[str, str]:
    """
    Log out the current user by blacklisting the current token.
    """
```

## Security Recommendations

Current security recommendations for the Authentication System:

1. **Multi-Factor Authentication**: Implement MFA for higher security levels
2. **Rate Limiting**: Add specific rate limiting for authentication endpoints
3. **Account Lockout**: Implement temporary lockout after failed login attempts
4. **Continuous Token Validation**: Consider implementing periodic token revalidation for long-running sessions
