"""
Authentication service module.

This service handles user authentication operations including:
- User login with credentials verification
- Token generation and validation
- Session management
- HIPAA-compliant authorization
"""

import logging
from datetime import datetime, timedelta
from uuid import UUID

from app.application.dtos.auth_dtos import LoginResponseDTO, TokenPairDTO, UserSessionDTO
from app.core.config.settings import Settings
from app.domain.entities.user import User
from app.domain.exceptions import (
    AuthenticationError,
    InvalidCredentialsError,
    InvalidTokenError,
    MissingTokenError,
    PermissionDeniedError,
    TokenExpiredError,
    UserNotFoundError,
)
from app.domain.interfaces.user_repository import UserRepositoryInterface
from app.infrastructure.logging.audit_logger import AuditLogger
from app.infrastructure.security.jwt.jwt_service import JWTService
from app.infrastructure.security.password.password_service import PasswordService


class AuthenticationService:
    """
    Service for handling user authentication and authorization.
    
    Implements HIPAA-compliant authentication flows with secure token management
    and comprehensive audit logging.
    """
    
    def __init__(
        self,
        user_repository: UserRepositoryInterface,
        jwt_service: JWTService,
        password_service: PasswordService,
        audit_logger: AuditLogger,
        settings: Settings
    ):
        """
        Initialize the authentication service with required dependencies.
        
        Args:
            user_repository: Repository for user data access
            jwt_service: Service for JWT token operations
            password_service: Service for password hashing/verification
            audit_logger: Logger for security audit events
            settings: Application settings
        """
        self.user_repository = user_repository
        self.jwt_service = jwt_service
        self.password_service = password_service
        self.audit_logger = audit_logger
        self.settings = settings
        self.session_timeout = settings.SESSION_TIMEOUT_MINUTES
        
        # Initialize session storage
        # In production, this should use Redis or similar distributed cache
        self._active_sessions: dict[str, UserSessionDTO] = {}
        
    async def login(self, email: str, password: str, ip_address: str, user_agent: str) -> LoginResponseDTO:
        """
        Authenticate a user with email and password credentials.
        
        Args:
            email: User's email address
            password: User's password
            ip_address: Client IP address for audit logging
            user_agent: Client user agent for audit logging
            
        Returns:
            Login response with tokens and user info
            
        Raises:
            InvalidCredentialsError: If credentials are invalid
            AuthenticationError: For other authentication failures
        """
        try:
            # Fetch user by email
            user = await self.user_repository.get_by_email(email)
            
            if not user:
                # Log failed attempt but don't reveal user existence
                self.audit_logger.log_failed_login(
                    email=email,
                    reason="user_not_found",
                    ip_address=ip_address,
                    user_agent=user_agent
                )
                raise InvalidCredentialsError("Invalid email or password")
                
            # Check if user is active
            if not user.is_active:
                self.audit_logger.log_failed_login(
                    email=email,
                    user_id=str(user.id),
                    reason="account_inactive",
                    ip_address=ip_address,
                    user_agent=user_agent
                )
                raise AuthenticationError("Account is inactive")
                
            # Verify password
            is_valid = await self.password_service.verify_password(
                plain_password=password,
                hashed_password=user.hashed_password
            )
            
            if not is_valid:
                self.audit_logger.log_failed_login(
                    email=email,
                    user_id=str(user.id),
                    reason="invalid_password",
                    ip_address=ip_address,
                    user_agent=user_agent
                )
                raise InvalidCredentialsError("Invalid email or password")
                
            # Generate session ID
            session_id = self._generate_session_id()
            
            # Create token pair
            tokens = await self._create_token_pair(user, session_id)
            
            # Create session record
            session = UserSessionDTO(
                session_id=session_id,
                user_id=str(user.id),
                email=user.email,
                ip_address=ip_address,
                user_agent=user_agent,
                created_at=datetime.now(datetime.UTC),
                expires_at=datetime.now(datetime.UTC) + timedelta(minutes=self.session_timeout)
            )
            
            # Store session
            self._active_sessions[session_id] = session
            
            # Log successful login
            self.audit_logger.log_successful_login(
                user_id=str(user.id),
                email=user.email,
                session_id=session_id,
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            # Create sanitized user data (no password or sensitive info)
            user_data = {
                "id": str(user.id),
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "roles": user.roles,
                "permissions": user.permissions
            }
            
            # Return login response
            return LoginResponseDTO(
                access_token=tokens.access_token,
                refresh_token=tokens.refresh_token,
                token_type="bearer",
                expires_in=self.settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
                user=user_data
            )
            
        except (UserNotFoundError, InvalidCredentialsError):
            # Standardize error for security (don't leak user existence)
            raise InvalidCredentialsError("Invalid email or password")
            
        except Exception as e:
            logging.error(f"Login error: {e!s}", exc_info=True)
            self.audit_logger.log_failed_login(
                email=email,
                reason=f"error: {type(e).__name__}",
                ip_address=ip_address,
                user_agent=user_agent
            )
            raise AuthenticationError(f"Authentication failed: {e!s}")
            
    async def logout(self, user_id: str, session_id: str, all_sessions: bool = False) -> bool:
        """
        Log out a user by invalidating their session and/or tokens.
        
        Args:
            user_id: User ID
            session_id: Session ID to invalidate
            all_sessions: If True, invalidate all user sessions
            
        Returns:
            True if logout was successful
        """
        try:
            if all_sessions:
                # Invalidate all sessions for this user
                sessions_to_remove = [
                    s_id for s_id, session in self._active_sessions.items()
                    if session.user_id == user_id
                ]
                
                for s_id in sessions_to_remove:
                    if s_id in self._active_sessions:
                        del self._active_sessions[s_id]
                        
                self.audit_logger.log_logout(
                    user_id=user_id,
                    session_id="all_sessions",
                    logout_type="all_sessions"
                )
            else:
                # Invalidate specific session
                if session_id in self._active_sessions:
                    # Verify user owns this session
                    session = self._active_sessions[session_id]
                    if session.user_id != user_id:
                        self.audit_logger.log_security_event(
                            event_type="unauthorized_logout_attempt",
                            user_id=user_id,
                            session_id=session_id,
                            details="Attempted to logout from another user's session"
                        )
                        raise PermissionDeniedError("Not authorized to end this session")
                        
                    # Remove session
                    del self._active_sessions[session_id]
                    
                    self.audit_logger.log_logout(
                        user_id=user_id,
                        session_id=session_id,
                        logout_type="user_initiated"
                    )
                    
            return True
            
        except Exception as e:
            logging.error(f"Logout error: {e!s}", exc_info=True)
            raise AuthenticationError(f"Logout failed: {e!s}")
            
    async def refresh_token(self, refresh_token: str, ip_address: str, user_agent: str) -> TokenPairDTO:
        """
        Issue a new access token using a valid refresh token.
        
        Args:
            refresh_token: Valid refresh token
            ip_address: Client IP address for audit logging
            user_agent: Client user agent for audit logging
            
        Returns:
            New token pair with refreshed access token
            
        Raises:
            InvalidTokenError: If refresh token is invalid
            TokenExpiredError: If refresh token has expired
        """
        try:
            # Verify refresh token
            payload = self.jwt_service.verify_token(refresh_token)
            
            # Ensure it's a refresh token
            if payload.get("type") != "refresh":
                self.audit_logger.log_security_event(
                    event_type="invalid_token_type",
                    details="Attempted to use non-refresh token for refresh",
                    ip_address=ip_address,
                    user_agent=user_agent
                )
                raise InvalidTokenError("Not a refresh token")
                
            # Extract user and session info
            user_id = payload.get("sub")
            session_id = payload.get("session_id")
            
            if not user_id:
                raise InvalidTokenError("Token missing user ID")
                
            # Verify session exists and is valid
            if session_id and session_id in self._active_sessions:
                session = self._active_sessions[session_id]
                
                # Check if session belongs to user
                if session.user_id != user_id:
                    self.audit_logger.log_security_event(
                        event_type="session_user_mismatch",
                        details="Token user ID doesn't match session user ID",
                        ip_address=ip_address,
                        user_agent=user_agent
                    )
                    raise InvalidTokenError("Invalid session")
                    
                # Check if session has expired
                if session.expires_at < datetime.now(datetime.UTC):
                    # Remove expired session
                    del self._active_sessions[session_id]
                    
                    self.audit_logger.log_security_event(
                        event_type="expired_session",
                        user_id=user_id,
                        session_id=session_id,
                        ip_address=ip_address,
                        user_agent=user_agent
                    )
                    raise TokenExpiredError("Session has expired")
            else:
                # Session not found - could be after server restart
                # Fetch user to verify they exist and are active
                user = await self.user_repository.get_by_id(user_id)
                
                if not user or not user.is_active:
                    self.audit_logger.log_security_event(
                        event_type="refresh_for_invalid_user",
                        user_id=user_id,
                        ip_address=ip_address,
                        user_agent=user_agent
                    )
                    raise InvalidTokenError("Invalid user")
                    
                # Create new session
                session_id = self._generate_session_id()
                session = UserSessionDTO(
                    session_id=session_id,
                    user_id=str(user.id),
                    email=user.email,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    created_at=datetime.now(datetime.UTC),
                    expires_at=datetime.now(datetime.UTC) + timedelta(minutes=self.session_timeout)
                )
                self._active_sessions[session_id] = session
            
            # Get full user data for tokens
            user = await self.user_repository.get_by_id(user_id)
            
            # Create new token pair
            tokens = await self._create_token_pair(user, session_id)
            
            # Revoke old refresh token
            self.jwt_service.revoke_token(refresh_token)
            
            # Log token refresh
            self.audit_logger.log_security_event(
                event_type="token_refresh",
                user_id=user_id,
                session_id=session_id,
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            return tokens
            
        except (InvalidTokenError, TokenExpiredError) as e:
            # Log but re-raise for proper handling
            self.audit_logger.log_security_event(
                event_type="token_refresh_failed",
                details=str(e),
                ip_address=ip_address,
                user_agent=user_agent
            )
            raise
            
        except Exception as e:
            logging.error(f"Token refresh error: {e!s}", exc_info=True)
            raise AuthenticationError(f"Token refresh failed: {e!s}")
            
    async def validate_token(self, token: str) -> User:
        """
        Validate an access token and return the associated user.
        
        Args:
            token: Access token to validate
            
        Returns:
            User object for the authenticated user
            
        Raises:
            MissingTokenError: If token is empty
            InvalidTokenError: If token is invalid
            TokenExpiredError: If token has expired
        """
        if not token:
            raise MissingTokenError("Token is required")
            
        try:
            # Verify token
            payload = self.jwt_service.verify_token(token)
            
            # Ensure it's an access token
            if payload.get("type") != "access":
                raise InvalidTokenError("Not an access token")
                
            # Extract user ID
            user_id = payload.get("sub")
            if not user_id:
                raise InvalidTokenError("Token missing user ID")
                
            # Get user from repository
            user = await self.user_repository.get_by_id(user_id)
            
            if not user:
                raise InvalidTokenError("User not found")
                
            if not user.is_active:
                raise InvalidTokenError("User account is inactive")
                
            return user
            
        except (InvalidTokenError, TokenExpiredError):
            # Re-raise these exceptions for specific handling
            raise
            
        except Exception as e:
            logging.error(f"Token validation error: {e!s}", exc_info=True)
            raise InvalidTokenError(f"Token validation failed: {e!s}")
            
    async def check_permission(self, user: User, required_permission: str) -> bool:
        """
        Check if a user has a specific permission.
        
        Args:
            user: User to check permissions for
            required_permission: Permission to check
            
        Returns:
            True if user has the permission, False otherwise
        """
        # Super admin role has all permissions
        if "admin" in user.roles:
            return True
            
        # Check user's permissions
        if user.permissions and required_permission in user.permissions:
            return True
            
        return False
        
    async def _create_token_pair(self, user: User, session_id: str) -> TokenPairDTO:
        """
        Create a pair of access and refresh tokens for a user.
        
        Args:
            user: User to create tokens for
            session_id: Session ID to associate with tokens
            
        Returns:
            TokenPairDTO with access and refresh tokens
        """
        # Prepare user data for token
        user_data = {
            "first_name": user.first_name,
            "last_name": user.last_name,
            "email": user.email,
            "roles": user.roles,
            "session_id": session_id
        }
        
        # Create access token
        access_token = self.jwt_service.create_access_token(
            user_id=str(user.id),
            permissions=user.permissions,
            additional_data=user_data
        )
        
        # Create refresh token
        refresh_token = self.jwt_service.create_refresh_token(
            user_id=str(user.id)
        )
        
        return TokenPairDTO(
            access_token=access_token,
            refresh_token=refresh_token
        )
        
    def _generate_session_id(self) -> str:
        """
        Generate a unique session ID.
        
        Returns:
            Unique session ID string
        """
        return str(UUID.uuid4()) 