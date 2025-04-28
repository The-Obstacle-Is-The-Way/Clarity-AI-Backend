"""
Token Repository Interface.

Defines the interface for token persistence and blacklisting operations
that must be implemented by concrete repositories.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import List, Optional


class ITokenRepository(ABC):
    """Interface for token repository operations."""

    @abstractmethod
    async def blacklist_token(self, token: str, expires_at: datetime) -> None:
        """
        Add a token to the blacklist.

        Args:
            token: The token to blacklist
            expires_at: When the token expires

        Raises:
            RepositoryException: If the operation fails
        """
        pass

    @abstractmethod
    async def is_blacklisted(self, token: str) -> bool:
        """
        Check if a token is blacklisted.

        Args:
            token: The token to check

        Returns:
            bool: True if blacklisted, False otherwise

        Raises:
            RepositoryException: If the operation fails
        """
        pass
    
    @abstractmethod
    async def blacklist_user_tokens(self, user_id: str) -> None:
        """
        Blacklist all tokens for a specific user.

        Args:
            user_id: The user identifier

        Raises:
            RepositoryException: If the operation fails
        """
        pass
    
    @abstractmethod
    async def blacklist_session_tokens(self, session_id: str) -> None:
        """
        Blacklist all tokens for a specific session.

        Args:
            session_id: The session identifier

        Raises:
            RepositoryException: If the operation fails
        """
        pass
    
    @abstractmethod
    async def cleanup_expired_tokens(self) -> int:
        """
        Remove expired tokens from the blacklist.

        Returns:
            int: Number of expired tokens removed

        Raises:
            RepositoryException: If the operation fails
        """
        pass
    
    @abstractmethod
    async def get_active_sessions(self, user_id: str) -> List[str]:
        """
        Get all active sessions for a user.

        Args:
            user_id: The user identifier

        Returns:
            List[str]: List of active session IDs

        Raises:
            RepositoryException: If the operation fails
        """
        pass 