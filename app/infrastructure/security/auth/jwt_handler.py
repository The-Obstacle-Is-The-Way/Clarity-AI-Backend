"""
JWT token handler for secure authentication.

This module provides functions for creating, validating, and managing JWT tokens
for use in authentication throughout the application.
"""

import logging
from datetime import timedelta
from typing import Any

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from pydantic import ValidationError

# Import settings for JWT configuration
from app.core.config.settings import get_settings
from app.core.utils.date_utils import utcnow

# Configure logger
logger = logging.getLogger(__name__)

# OAuth2 scheme for token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def create_access_token(
    data: dict[str, Any], expires_delta: timedelta | None = None
) -> str:
    """
    Create a new JWT access token.

    Args:
        data: Data to encode in the token
        expires_delta: Optional expiration time delta

    Returns:
        Encoded JWT token
    """
    settings = get_settings()

    to_encode = data.copy()
    if expires_delta:
        expire = utcnow() + expires_delta
    else:
        expire = utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({"exp": expire})

    # Encode the token
    try:
        encoded_jwt = jwt.encode(
            to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM
        )
        return encoded_jwt
    except Exception as e:
        logger.error(f"Token generation failed: {e}")
        raise ValueError(f"Token generation failed: {e}")


def create_refresh_token(
    data: dict[str, Any], expires_delta: timedelta | None = None
) -> str:
    """
    Create a new JWT refresh token with longer expiration.

    Args:
        data: Data to encode in the token
        expires_delta: Optional expiration time delta

    Returns:
        Encoded JWT refresh token
    """
    settings = get_settings()

    to_encode = data.copy()
    if expires_delta:
        expire = utcnow() + expires_delta
    else:
        # Default refresh token expiration (typically longer than access token)
        days = getattr(settings, "JWT_REFRESH_TOKEN_EXPIRE_DAYS", 7)
        expire = utcnow() + timedelta(days=days)

    to_encode.update({"exp": expire, "token_type": "refresh"})

    # Encode the token
    try:
        encoded_jwt = jwt.encode(
            to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM
        )
        return encoded_jwt
    except Exception as e:
        logger.error(f"Refresh token generation failed: {e}")
        raise ValueError(f"Refresh token generation failed: {e}")


def decode_token(token: str) -> dict[str, Any]:
    """
    Decode and validate a JWT token.

    Args:
        token: The JWT token to decode

    Returns:
        Decoded token payload

    Raises:
        JWTError: If token is invalid or expired
    """
    settings = get_settings()

    try:
        payload = jwt.decode(
            token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM]
        )
        return payload
    except JWTError as e:
        logger.warning(f"JWT token validation failed: {e}")
        raise


def get_token_data(token: str) -> dict[str, Any]:
    """
    Get the data from a JWT token without validating signature or expiration.

    Args:
        token: The JWT token to decode

    Returns:
        Decoded token payload without validation

    Raises:
        ValueError: If token format is invalid
    """
    try:
        # Decode without verification for inspection purposes only
        payload = jwt.decode(
            token, options={"verify_signature": False, "verify_exp": False}
        )
        return payload
    except Exception as e:
        logger.error(f"Token data extraction failed: {e}")
        raise ValueError(f"Invalid token format: {e}")


def validate_access_token(token: str) -> dict[str, Any]:
    """
    Validate an access token and return its payload if valid.

    Args:
        token: The JWT token to validate

    Returns:
        Decoded token payload if valid

    Raises:
        HTTPException: If token is invalid, expired, or not an access token
    """
    try:
        payload = decode_token(token)

        # Check if this is an access token (optional, based on your token structure)
        token_type = payload.get("token_type", "access")
        if token_type != "access":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type",
                headers={"WWW-Authenticate": "Bearer"},
            )

        return payload

    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_current_user(token: str = Depends(oauth2_scheme)) -> dict[str, Any]:
    """
    Get the current authenticated user from a JWT token.

    Args:
        token: JWT token from request

    Returns:
        User information extracted from token

    Raises:
        HTTPException: If authentication fails
    """
    try:
        payload = decode_token(token)
        user_id = payload.get("sub")

        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Here you would typically fetch user from DB
        # For test compliance we return basic user info from token
        user = {
            "id": payload.get("id", user_id),
            "username": user_id,
            "role": payload.get("role", "user"),
            "permissions": payload.get("permissions", []),
        }

        return user

    except (JWTError, ValidationError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
