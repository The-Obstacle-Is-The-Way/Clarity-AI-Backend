# -*- coding: utf-8 -*-
"""
Interface definition for JWT Service.

Defines the contract for creating and validating JSON Web Tokens.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from datetime import timedelta

# Attempt to import User, handle potential circular dependency or missing file gracefully
try:
    from app.domain.entities.user import User
except ImportError:
    User = Any # Fallback if User cannot be imported

# Import AuthenticationError - adjust path if necessary
from app.domain.exceptions import AuthenticationError


class IJwtService(ABC):
    """Abstract base class for JWT operations."""

    @abstractmethod
    async def create_access_token(
        self, 
        data: Dict[str, Any], 
        expires_delta: Optional[timedelta] = None,
        expires_delta_minutes: Optional[int] = None
    ) -> str:
        """Creates a new access token."""
        pass

    @abstractmethod
    async def create_refresh_token(
        self, 
        data: Dict[str, Any], 
        expires_delta: Optional[timedelta] = None,
        expires_delta_minutes: Optional[int] = None
    ) -> str:
        """Creates a new refresh token."""
        pass

    @abstractmethod
    async def decode_token(self, token: str) -> Dict[str, Any]:
        """
        Decodes a token and returns its payload.
        Raises AuthenticationError if the token is invalid or expired.
        """
        pass

    @abstractmethod
    async def get_user_from_token(self, token: str) -> Optional[User]:
        """
        Decodes a token and retrieves the corresponding user.
        Returns None if the user is not found or the token is invalid.
        Raises AuthenticationError for token issues.
        """
        pass

    @abstractmethod
    async def verify_refresh_token(self, refresh_token: str) -> Dict[str, Any]:
        """
        Verifies a refresh token and returns its payload.
        Raises AuthenticationError if invalid.
        """
        pass

    @abstractmethod
    def get_token_payload_subject(self, payload: Dict[str, Any]) -> Optional[str]:
        """Extracts the subject (user identifier) from the token payload."""
        pass 