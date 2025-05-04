"""
Authentication routes module.

This module provides API endpoints for user authentication, including
login, token refresh, and registration functionality.
"""

from typing import Any

from fastapi import APIRouter

# Create router with appropriate prefix and tags
router = APIRouter(
    prefix="/auth",
    tags=["authentication"],
)


@router.post("/login")
async def login() -> dict[str, Any]:
    """
    Authenticate a user and return access and refresh tokens.
    
    Returns:
        Dictionary with access_token, refresh_token, and token_type
    """
    # No-op implementation for test collection
    return {
        "access_token": "test_token",
        "refresh_token": "test_refresh_token",
        "token_type": "bearer"
    }


@router.post("/refresh")
async def refresh_token() -> dict[str, Any]:
    """
    Refresh an access token using a valid refresh token.
    
    Returns:
        Dictionary with new access_token and unchanged token_type
    """
    # No-op implementation for test collection
    return {
        "access_token": "new_test_token",
        "token_type": "bearer"
    }


@router.post("/register")
async def register() -> dict[str, Any]:
    """
    Register a new user account.
    
    Returns:
        Dictionary with user information
    """
    # No-op implementation for test collection
    return {
        "id": "00000000-0000-0000-0000-000000000000",
        "email": "test@example.com",
        "is_active": True
    }
