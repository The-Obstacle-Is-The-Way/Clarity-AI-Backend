# Authentication System

## Overview

The Authentication System is a foundational security component of the Clarity AI Backend, providing secure identity management and access control for the psychiatric digital twin platform. It implements robust token-based authentication with refresh capabilities while adhering to HIPAA security requirements for protected health information (PHI).

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

### JWT Service Interface

The `IJwtService` handles token generation, validation, and blacklisting:

```python
class IJwtService(ABC):
    """
    Interface for JWT (JSON Web Token) service operations.
    
    This interface encapsulates the functionality required for:
    - Creating access and refresh tokens
    - Verifying and decoding tokens
    - Managing token blacklisting
    - Token identity operations
    """
    
    @abstractmethod
    async def create_access_token(self, user_id: Union[str, UUID], additional_data: Optional[Dict] = None) -> str:
        """
        Create a short-lived access token.
        """
        
    @abstractmethod
    async def create_refresh_token(self, user_id: Union[str, UUID]) -> str:
        """
        Create a long-lived refresh token.
        """
        
    @abstractmethod
    async def decode_token(self, token: str) -> Dict[str, Any]:
        """
        Decode and validate a token.
        """
        
    @abstractmethod
    async def blacklist_token(self, token: str, reason: Optional[str] = None) -> None:
        """
        Add a token to the blacklist to prevent its future use.
        """
        
    @abstractmethod
    async def is_token_blacklisted(self, token: str) -> bool:
        """
        Check if a token is in the blacklist.
        """
```

### Token Blacklist Repository Interface

The `ITokenBlacklistRepository` manages the storage and retrieval of blacklisted tokens:

```python
class ITokenBlacklistRepository(ABC):
    """
    Interface for token blacklist repository operations.
    
    This interface encapsulates the functionality required for managing
    blacklisted (revoked) tokens to ensure proper security controls
    like session invalidation and logout.
    """
    
    @abstractmethod
    async def add_to_blacklist(self, token: str, jti: str, expires_at: datetime, reason: Optional[str] = None) -> None:
        """
        Add a token to the blacklist.
        """
        
    @abstractmethod
    async def is_blacklisted(self, token: str) -> bool:
        """
        Check if a token is blacklisted.
        """
        
    @abstractmethod
    async def is_jti_blacklisted(self, jti: str) -> bool:
        """
        Check if a token with specific JWT ID is blacklisted.
        """
```

### Password Handler Interface

The `IPasswordHandler` provides secure password operations:

```python
class IPasswordHandler(ABC):
    """
    Interface for password handling operations.
    
    This interface encapsulates the functionality required for secure
    password operations including hashing, verification, and validation
    according to HIPAA security requirements.
    """
    
    @abstractmethod
    async def hash_password(self, password: str) -> str:
        """
        Hash a password securely.
        """
        
    @abstractmethod
    async def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """
        Verify a password against its hash.
        """
        
    @abstractmethod
    async def check_password_requirements(self, password: str) -> Tuple[bool, Optional[str]]:
        """
        Check if a password meets security requirements.
        """
```

## Authentication Flow

The authentication system implements token-based authentication with the following flow:

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
   - System validates token signature, expiration, and blacklist status
   - If valid, request is processed with user context
   - If invalid, 401 Unauthorized response is returned

4. **Token Refresh**:
   - When access token expires, client uses refresh token
   - System validates refresh token
   - If valid, new access token is generated
   - New token is returned to client

5. **User Logout**:
   - Client submits logout request with tokens
   - Tokens are added to blacklist
   - Client destroys local token copies

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

This endpoint authenticates a user with username/email and password, returning JWT tokens on successful authentication.

**Request Body**: `LoginRequestSchema` containing credentials  
**Response**: `TokenResponseSchema` with access_token, refresh_token, and token_type  
**Errors**:

- 401: Invalid credentials or disabled account
- 500: Internal server error during authentication

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

This endpoint issues a new access token when provided with a valid refresh token.

**Request Body**: `RefreshTokenRequestSchema` containing refresh_token  
**Response**: `TokenResponseSchema` with new access_token  
**Errors**:

- 401: Invalid or expired refresh token
- 500: Internal server error during token refresh

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

This endpoint registers a new user in the system after validating their information.

**Request Body**: `UserRegistrationRequestSchema` with user details  
**Response**: `UserRegistrationResponseSchema` with created user information  
**Errors**:

- 409: User already exists with provided email
- 400: Invalid registration data (e.g., weak password)
- 500: Internal server error during registration

### Logout

```python
@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    response: Response,
    auth_service: AuthServiceInterface = Depends(get_auth_service)
) -> None:
    """
    Logs out the current user by invalidating tokens/session.
    """
```

This endpoint invalidates the user's current tokens, effectively logging them out.

**Response**: 204 No Content on successful logout  
**Errors**:

- 500: Error during logout operation

### Session Information

```python
@router.get("/session-info", response_model=SessionInfoResponseSchema)
async def get_session_info(
    auth_service: AuthServiceInterface = Depends(get_auth_service)
) -> SessionInfoResponseSchema:
    """
    Provides information about the current user's session.
    """
```

This endpoint returns information about the current user's authenticated session.

**Response**: `SessionInfoResponseSchema` with session details  
**Errors**:

- 500: Error retrieving session information

## Security Considerations

### HIPAA Compliance

The Authentication System implements multiple security measures to ensure HIPAA compliance:

1. **Password Security**:
   - Passwords are hashed using strong algorithms (bcrypt/Argon2)
   - Password requirements enforce complexity and prevent common passwords
   - Regular password rotation can be enforced through expiry policies

2. **Token Security**:
   - Access tokens are short-lived (typically 15-60 minutes)
   - Refresh tokens are secured and can be revoked
   - Token validation prevents tampering and ensures integrity

3. **Session Management**:
   - Sessions can be forcibly terminated for security incidents
   - Inactivity timeouts automatically end idle sessions
   - Session metadata is tracked for audit purposes

4. **Audit Trail**:
   - All authentication events are logged with timestamps
   - Failed authentication attempts are monitored for potential attacks
   - Session creation and termination events are recorded

### Multi-Factor Authentication

The system supports multi-factor authentication as an additional security layer:

1. **TOTP Implementation**:
   - Time-based One-Time Password generation and validation
   - Compatible with standard authenticator apps (Google Authenticator, etc.)
   - Fallback mechanisms for device loss

2. **MFA Enrollment**:
   - Self-service MFA enrollment process
   - QR code generation for easy setup
   - Recovery codes for emergency access

3. **Risk-Based Authentication**:
   - Optional escalation to MFA based on risk factors
   - Unusual access patterns can trigger additional verification
   - Administrative policies can enforce MFA for sensitive operations

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
