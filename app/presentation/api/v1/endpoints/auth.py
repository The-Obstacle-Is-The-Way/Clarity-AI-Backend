"""
Authentication endpoints for the Novamind API.

These endpoints handle user authentication and token management
with HIPAA-compliant security measures.
"""

from typing import Any

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, EmailStr, Field

from app.core.config.settings import get_settings
from app.core.domain.entities.user import User
from app.core.utils.logging import get_logger
from app.infrastructure.security.auth.authentication_service import AuthenticationService
from app.presentation.api.dependencies.auth import (  
    get_current_user,
    get_optional_user,
)
from app.presentation.api.dependencies.auth_service import get_auth_service
from app.application.dtos.auth_dtos import RefreshTokenRequestDTO as TokenRefreshRequest, LoginRequestDTO as UserLoginRequest

# Initialize router
router = APIRouter()
settings = get_settings()
logger = get_logger(__name__)

# --- Pydantic Models for Request/Response ---

class TokenResponse(BaseModel):
    """Token response model for login and refresh endpoints."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = Field(..., description="Token expiration time in seconds")


class LoginRequest(BaseModel):
    """Login request model for credentials."""
    username: str = Field(..., description="Username or email")
    password: str = Field(..., description="User password")
    remember_me: bool = Field(False, description="Whether to extend token lifetime")


class RefreshRequest(BaseModel):
    """Refresh token request model."""
    refresh_token: str = Field(..., description="Refresh token")


class UserResponse(BaseModel):
    """User data response model with no sensitive information."""
    id: str
    email: EmailStr
    first_name: str | None = None
    last_name: str | None = None
    roles: list[str] = []
    is_active: bool = True


class SessionInfoResponse(BaseModel):
    """Session information response model."""
    authenticated: bool
    session_active: bool
    roles: list[str] = []
    user_id: str | None = None
    exp: int | None = None
    permissions: list[str] = []


# --- Auth Endpoints ---

@router.post(
    "/login", 
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Authenticate user and get tokens",
    description="Log in a user with username/email and password, return access and refresh tokens",
    response_description="JWT tokens for authentication"
) 
async def login(
    request: Request,
    login_data: LoginRequest,
    response: Response,
    auth_service: AuthenticationService = Depends(get_auth_service)
) -> TokenResponse:
    """
    Authenticate a user and return JWT tokens.
    
    Args:
        request: FastAPI request
        login_data: Login credentials
        response: FastAPI response for cookie setting
        auth_service: Authentication service
        
    Returns:
        TokenResponse with access and refresh tokens
        
    Raises:
        HTTPException: If authentication fails
    """
    try:
        # Authenticate user
        user = await auth_service.authenticate_user(login_data.username, login_data.password)
        
        if not user:
            # Don't provide specific error details for security
            logger.warning(f"Failed login attempt for username: {login_data.username}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials",
                headers={"WWW-Authenticate": "Bearer"}
            ) from None
            
        if not user.is_active:
            logger.warning(f"Login attempt on inactive account: {login_data.username}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Account is inactive",
                headers={"WWW-Authenticate": "Bearer"}
            ) from None
            
        # Generate tokens
        tokens = await auth_service.create_token_pair(user)
        
        # Set secure cookie with access token
        response.set_cookie(
            key="access_token",
            value=tokens["access_token"],
            httponly=True,
            secure=settings.ENVIRONMENT != "development", 
            samesite="lax",
            max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60, 
            path="/",
        )
        
        # Set refresh token cookie with longer expiration if remember_me is true
        refresh_max_age = settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60
        if login_data.remember_me:
            # Double the expiration time for remember_me
            refresh_max_age *= 2
            
        response.set_cookie(
            key="refresh_token",
            value=tokens["refresh_token"],
            httponly=True,
            secure=settings.ENVIRONMENT != "development",
            samesite="lax",
            max_age=refresh_max_age,
            path="/api/v1/auth/refresh",  
        )
        
        # Log successful login
        logger.info(f"User logged in successfully: {login_data.username}")
        
        # Return tokens and expiration
        return TokenResponse(
            access_token=tokens["access_token"],
            refresh_token=tokens["refresh_token"],
            token_type="bearer",
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        )
    except HTTPException as http_exc:
        # Re-throw HTTP exceptions
        raise http_exc from http_exc
    except Exception as e:
        # Log the error but don't expose details to client
        logger.error(f"Login error: {e!s}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication failed",
            headers={"WWW-Authenticate": "Bearer"}
        ) from e


@router.post(
    "/refresh", 
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Refresh access token",
    description="Get a new access token using a valid refresh token",
    response_description="New JWT tokens"
) 
async def refresh_token(
    request: Request,
    response: Response,
    refresh_data: RefreshRequest | None = None,
    refresh_token: str | None = Cookie(None, alias="refresh_token"),
    auth_service: AuthenticationService = Depends(get_auth_service)
) -> TokenResponse:
    """
    Refresh access token using a valid refresh token.
    
    Args:
        request: FastAPI request
        response: FastAPI response
        refresh_data: Refresh token from request body (optional)
        refresh_token: Refresh token from cookie (optional)
        auth_service: Authentication service
        
    Returns:
        TokenResponse with new access and refresh tokens
        
    Raises:
        HTTPException: If refresh token is invalid or expired
    """
    # Get refresh token from either request body or cookie
    token_to_use = None
    if refresh_data and refresh_data.refresh_token:
        token_to_use = refresh_data.refresh_token
    elif refresh_token:
        token_to_use = refresh_token
        
    if not token_to_use:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token required",
            headers={"WWW-Authenticate": "Bearer"}
        ) from None
        
    try:
        # Refresh tokens and get new pair
        tokens = await auth_service.refresh_token(token_to_use)
        
        # Set cookies with new tokens
        response.set_cookie(
            key="access_token",
            value=tokens["access_token"],
            httponly=True,
            secure=settings.ENVIRONMENT != "development",
            samesite="lax",
            max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            path="/",
        )
        
        response.set_cookie(
            key="refresh_token",
            value=tokens["refresh_token"],
            httponly=True,
            secure=settings.ENVIRONMENT != "development",
            samesite="lax",
            max_age=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
            path="/api/v1/auth/refresh",
        )
        
        logger.info("Token refreshed successfully")
        
        # Return new tokens
        return TokenResponse(
            access_token=tokens["access_token"],
            refresh_token=tokens["refresh_token"],
            token_type="bearer",
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        )
    except HTTPException as http_exc:
        # Re-throw HTTP exceptions
        raise http_exc from http_exc
    except Exception as e:
        logger.warning(f"Token refresh failed: {e!s}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
            headers={"WWW-Authenticate": "Bearer"}
        ) from e


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Log out user",
    description="Revoke current tokens and clear auth cookies",
    response_model=None  # Explicitly set to None to avoid response validation issues
) 
async def logout(
    request: Request,
    response: Response,
    access_token: str | None = Depends(get_current_user),
    refresh_token: str | None = Cookie(None, alias="refresh_token"),
    auth_service: AuthenticationService = Depends(get_auth_service)
) -> None:
    """
    Log out the current user by revoking their tokens.
    
    Args:
        request: FastAPI request
        response: FastAPI response
        access_token: Current access token 
        refresh_token: Current refresh token from cookie
        auth_service: Authentication service
    """
    # Revoke tokens if they exist
    tokens_to_revoke = []
    
    if access_token:
        tokens_to_revoke.append(access_token)
    
    if refresh_token:
        tokens_to_revoke.append(refresh_token)
        
    if tokens_to_revoke:
        try:
            await auth_service.logout(tokens_to_revoke)
        except Exception as e:
            logger.warning(f"Error during token revocation: {e!s}")
    
    # Clear auth cookies regardless of revocation success
    response.delete_cookie(key="access_token", path="/")
    response.delete_cookie(key="refresh_token", path="/api/v1/auth/refresh")
    
    # No content response for successful logout
    return None


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current user profile",
    description="Return the current user information based on the token",
    response_description="Current user data"
) 
async def get_current_user_profile(
    current_user: User = Depends(get_current_user),
) -> UserResponse:
    """
    Get the current authenticated user's profile.
    
    Args:
        current_user: The authenticated User object from the dependency.
        
    Returns:
        UserResponse with user information
        
    Raises:
        HTTPException: If user is not found (should be handled by dependency).
    """
    try:
        # The get_current_user dependency should already handle authentication
        # and raise HTTPException if the user is not valid or not found.
        # We can directly use the provided current_user object.

        # Directly return data from the User object provided by the dependency
        return UserResponse(
            id=str(current_user.id),
            email=current_user.email,
            first_name=current_user.first_name,
            last_name=current_user.last_name,
            roles=[str(role) for role in current_user.roles],
            is_active=current_user.is_active
        )
    except HTTPException as http_exc:
        # Re-throw HTTP exceptions
        raise http_exc from http_exc
    except Exception as e:
        # Log unexpected errors
        logger.error(f"Error retrieving user profile for user ID {current_user.id if current_user else 'UNKNOWN'}: {e!s}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve user profile"
        ) from e


@router.get(
    "/session-info",
    response_model=SessionInfoResponse,
    summary="Get session information",
    description="Return information about the current authentication session",
    response_description="Session information"
) 
async def get_session_info(
    user_data: dict[str, Any] | None = Depends(get_optional_user),
) -> SessionInfoResponse:
    """
    Get information about the current session.
    
    Args:
        user_data: Optional user data from token
        
    Returns:
        Dictionary with session information
    """
    if not user_data:
        return SessionInfoResponse(
            authenticated=False,
            session_active=False
        )
        
    return SessionInfoResponse(
        authenticated=True,
        session_active=True,
        roles=user_data.get("roles", []),
        user_id=user_data.get("sub") or user_data.get("user_id"),
        exp=user_data.get("exp"),
        permissions=user_data.get("permissions", [])
    )
