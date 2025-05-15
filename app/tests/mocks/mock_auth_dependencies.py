"""
Mock authentication dependencies for testing.

This module provides mock authentication dependencies that
can be used to override FastAPI dependency injections for testing.
"""

from typing import Callable, Dict, Any, Optional, Union
import uuid
from fastapi import Depends, HTTPException, status
from pydantic import BaseModel

from app.core.dto.auth.token import TokenPayload
from app.core.dto.user.user import UserBase
from app.domain.entities.user import User
from app.domain.enums.role import Role
from app.tests.utils.jwt_helpers import create_test_token


# Mock user for testing
MOCK_USER_ID = str(uuid.uuid4())
MOCK_TEST_USER = User(
    id=MOCK_USER_ID,
    username="testuser",
    email="test@example.com",
    role=Role.ADMIN,
    is_active=True,
    is_superuser=True,
)


class MockCurrentUser:
    """
    Mock current user dependency for testing.
    
    This class provides a callable that returns a mock user
    for testing authentication-protected endpoints.
    """
    
    def __init__(self, user: Optional[User] = None, raise_error: bool = False):
        """
        Initialize with optional user override and error flag.
        
        Args:
            user: Optional user to return instead of the default
            raise_error: Whether to raise an authentication error
        """
        self.user = user or MOCK_TEST_USER
        self.raise_error = raise_error
        
    async def __call__(self) -> User:
        """
        Return the mock user or raise an authentication error.
        
        Returns:
            User: The mock user
            
        Raises:
            HTTPException: If raise_error is True
        """
        if self.raise_error:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return self.user


def get_mock_current_user(user: Optional[User] = None, raise_error: bool = False) -> Callable:
    """
    Get a mock current user dependency.
    
    Args:
        user: Optional user to return
        raise_error: Whether to raise an authentication error
        
    Returns:
        Callable: A callable that returns the mock user
    """
    return MockCurrentUser(user=user, raise_error=raise_error)


def get_mock_current_active_user(user: Optional[User] = None, raise_error: bool = False) -> Callable:
    """
    Get a mock current active user dependency.
    
    Args:
        user: Optional user to return
        raise_error: Whether to raise an authentication error
        
    Returns:
        Callable: A callable that returns the mock user
    """
    if user and not user.is_active:
        async def mock_inactive_user():
            raise HTTPException(status_code=400, detail="Inactive user")
        return mock_inactive_user
    
    return MockCurrentUser(user=user, raise_error=raise_error)


def get_mock_current_admin_user(user: Optional[User] = None, raise_error: bool = False) -> Callable:
    """
    Get a mock current admin user dependency.
    
    Args:
        user: Optional user to return
        raise_error: Whether to raise an authentication error
        
    Returns:
        Callable: A callable that returns the mock user
    """
    user_obj = user or MOCK_TEST_USER
    
    if not user_obj.is_superuser and user_obj.role != Role.ADMIN:
        async def mock_non_admin_user():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not enough permissions"
            )
        return mock_non_admin_user
    
    return MockCurrentUser(user=user_obj, raise_error=raise_error)


def create_mock_token_payload(subject: str = MOCK_USER_ID, token_type: str = "access") -> TokenPayload:
    """
    Create a mock token payload for testing.
    
    Args:
        subject: Subject of the token
        token_type: Type of token (access or refresh)
        
    Returns:
        TokenPayload: Mock token payload
    """
    from app.domain.enums.token_type import TokenType
    
    # Create a dict with the token payload
    payload_dict = {
        "sub": subject,
        "jti": str(uuid.uuid4()),
        "type": TokenType.ACCESS if token_type == "access" else TokenType.REFRESH,
        "exp": 1704110400 + (30 * 60),  # Fixed timestamp for testing
        "iat": 1704110400,
        "nbf": 1704110400,
        "iss": "clarity-tests",
        "aud": "test-audience"
    }
    
    # Add refresh-specific fields
    if token_type == "refresh":
        payload_dict["refresh"] = True
        payload_dict["family_id"] = str(uuid.uuid4())
    
    # Convert to TokenPayload
    return TokenPayload(**payload_dict) 