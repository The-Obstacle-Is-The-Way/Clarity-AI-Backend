"""
Authentication routes module.

This module provides API endpoints for user authentication, including
login, token refresh, and registration functionality.
"""

from fastapi import APIRouter, Depends, HTTPException, status, Response
from typing import Any, Optional

# Import concrete implementations instead of interfaces for FastAPI compatibility
from app.infrastructure.security.auth.authentication_service import AuthenticationService
from app.presentation.api.dependencies.auth_service import get_auth_service
from app.presentation.api.schemas.auth import (
    LoginRequestSchema,
    TokenResponseSchema,
    RefreshTokenRequestSchema,
    SessionInfoResponseSchema,
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    LogoutResponseSchema
)
from app.domain.exceptions.auth_exceptions import (
    InvalidCredentialsException,
    AccountDisabledException,
    InvalidTokenException,
    UserAlreadyExistsException,
    TokenExpiredException
)

# Create router (prefix removed as it's handled by the including router)
router = APIRouter(
    tags=["authentication"],
)

@router.post("/login", response_model=TokenResponseSchema, status_code=status.HTTP_200_OK)
async def login(
    login_data: LoginRequestSchema,
    response: Response,
    auth_service: AuthenticationService = Depends(get_auth_service)
) -> dict[str, Any]:
    """
    Authenticate a user and return access and refresh tokens.
    
    Returns:
        Dictionary with access_token, refresh_token, and token_type
    """
    try:
        # Call authentication service login method
        token_data = await auth_service.login(
            username=str(login_data.username),  # Convert EmailStr to str
            password=login_data.password,
            remember_me=login_data.remember_me
        )
        
        # Extract expiration time from token data or use default
        expires_in = token_data.get("expires_in", 3600)  # Default to 3600 seconds if not present
        
        # Extract user_id and roles from token data
        user_id = token_data.get("user_id", None)
        roles = token_data.get("roles", None)
        
        # Return token data with required fields for TokenResponseSchema
        return {
            "access_token": token_data["access_token"],
            "refresh_token": token_data["refresh_token"],
            "token_type": token_data.get("token_type", "bearer"),
            "expires_in": expires_in,
            "user_id": user_id,  # Include user_id from token data
            "roles": roles  # Include roles from token data
        }

    except InvalidCredentialsException as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail=str(e)
        ) from e
    except AccountDisabledException as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail=str(e)
        ) from e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
            detail="An internal error occurred during login."
        ) from e

@router.post("/refresh", response_model=TokenResponseSchema)
async def refresh_token(
    refresh_data: RefreshTokenRequestSchema,
    auth_service: AuthenticationService = Depends(get_auth_service)
) -> TokenResponseSchema:
    """
    Refresh an access token using a valid refresh token.
    
    Returns:
        Dictionary with new access_token and unchanged token_type
    """
    try:
        token_data = await auth_service.refresh_access_token(refresh_token_str=refresh_data.refresh_token)
        return TokenResponseSchema(**token_data.model_dump()) if hasattr(token_data, 'model_dump') else TokenResponseSchema(**token_data)
    except (InvalidTokenException, TokenExpiredException) as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An internal error occurred during token refresh.")

@router.post("/register", response_model=UserRegistrationResponseSchema, status_code=status.HTTP_201_CREATED)
async def register(
    registration_data: UserRegistrationRequestSchema,
    auth_service: AuthenticationService = Depends(get_auth_service)
) -> UserRegistrationResponseSchema:
    """
    Register a new user account.
    
    Returns:
        Dictionary with user information
    """
    try:
        user = await auth_service.register_user(
            email=registration_data.email,
            password=registration_data.password,
            full_name=registration_data.full_name
        )
        return UserRegistrationResponseSchema(**user.model_dump()) if hasattr(user, 'model_dump') else UserRegistrationResponseSchema(**user)
    except UserAlreadyExistsException as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An internal error occurred during registration.")

@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    response: Response, # To manage cookies
    auth_service: AuthenticationService = Depends(get_auth_service)
) -> None:
    """
    Logs out the current user by invalidating tokens/session.
    """
    try:
        # Actual service might need current token from headers/cookies to invalidate it
        # For now, assuming it handles context or client-side will clear tokens
        await auth_service.logout(response=response) # Pass response to clear cookies
        return None # HTTP 204 returns no content
    except Exception as e:
        # Log error
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An error occurred during logout.")

@router.get("/session-info", response_model=SessionInfoResponseSchema)
async def get_session_info(
    auth_service: AuthenticationService = Depends(get_auth_service) 
    # current_user: User = Depends(get_current_active_user) # Or use a dependency that provides current user or None
) -> SessionInfoResponseSchema:
    """
    Provides information about the current user's session.
    """
    try:
        # This method would typically inspect the request (e.g., JWT in headers)
        # and return session details. The auth_service should encapsulate this.
        session_data = await auth_service.get_current_session_info()
        return SessionInfoResponseSchema(**session_data.model_dump()) if hasattr(session_data, 'model_dump') else SessionInfoResponseSchema(**session_data)
    except Exception as e:
        # Log error
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error retrieving session information.")

# Placeholder for the dependency provider - this needs to exist in app.presentation.api.dependencies.auth
# Example of what get_auth_service might look like:
# from app.application.services.auth_service import AuthService
# from app.core.interfaces.services.auth_service_interface import AuthServiceInterface
# from app.infrastructure.persistence.sqlalchemy.repositories.user_repository import UserRepositoryImpl
# from app.infrastructure.security.jwt_service import JWTServiceImpl # Assuming you have this
# from .database import get_db_session # Your DB session dependency
# from sqlalchemy.ext.asyncio import AsyncSession
# 
# def get_auth_service(
#     db_session: AsyncSession = Depends(get_db_session),
#     jwt_service: JWTService = Depends(get_jwt_service) # Assuming get_jwt_service exists
# ) -> AuthServiceInterface:
#     user_repo = UserRepositoryImpl(db_session)
#     return AuthService(user_repository=user_repo, jwt_service=jwt_service)
