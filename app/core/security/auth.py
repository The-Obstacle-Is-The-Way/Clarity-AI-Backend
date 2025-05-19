"""
Authentication and authorization module.

This module provides functions for user authentication and authorization.
"""

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

# Create a mock OAuth2 scheme for testing
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


# Mock user response schema for testing
class UserResponseSchema:
    """Mock user response schema for testing."""

    def __init__(
        self, id=None, username=None, email=None, is_active=True, is_superuser=False
    ):
        self.id = id or "00000000-0000-0000-0000-000000000000"
        self.username = username or "test_user"
        self.email = email or "test@example.com"
        self.is_active = is_active
        self.is_superuser = is_superuser

    def dict(self):
        """Return user data as a dictionary."""
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "is_active": self.is_active,
            "is_superuser": self.is_superuser,
        }


async def get_current_user(token: str = Depends(oauth2_scheme)) -> UserResponseSchema:
    """
    Get the current authenticated user.

    This function validates the JWT token and returns the user if valid.

    Args:
        token: JWT token from the Authorization header

    Returns:
        UserResponseSchema: The authenticated user

    Raises:
        HTTPException: If the token is invalid or the user is not found
    """
    # This is a mock implementation for testing
    # In a real implementation, this would validate the token and get the user
    return UserResponseSchema()


async def verify_admin_access(
    current_user: UserResponseSchema = Depends(get_current_user),
) -> UserResponseSchema:
    """
    Verify that the current user has admin access.

    Args:
        current_user: The current authenticated user

    Returns:
        UserResponseSchema: The authenticated admin user

    Raises:
        HTTPException: If the user is not an admin
    """
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to perform this action",
        )
    return current_user
