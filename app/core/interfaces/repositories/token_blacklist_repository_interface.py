"""
Token Blacklist Repository Interface.

This module defines the interface for token blacklist repository operations,
supporting secure token revocation and logout functionality
while maintaining HIPAA compliance and clean architecture.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Optional


class ITokenBlacklistRepository(ABC):
    """
    Interface for token blacklist repository operations.
    
    This interface encapsulates the functionality required for managing
    blacklisted (revoked) tokens to ensure proper security controls
    like session invalidation and logout.
    """
    
    @abstractmethod
    async def add_to_blacklist(
        self,
        token: str,
        jti: str,
        expires_at: datetime,
        reason: Optional[str] = None
    ) -> None:
        """
        Add a token to the blacklist.
        
        Args:
            token: The token to blacklist (typically a hash of the token)
            jti: JWT ID - unique identifier for the token
            expires_at: When the token expires
            reason: Reason for blacklisting
            
        Raises:
            RepositoryError: If blacklisting fails
        """
        pass
    
    @abstractmethod
    async def is_blacklisted(self, token: str) -> bool:
        """
        Check if a token is blacklisted.
        
        Args:
            token: The token to check (typically a hash of the token)
            
        Returns:
            True if blacklisted, False otherwise
            
        Raises:
            RepositoryError: If check fails
        """
        pass
    
    @abstractmethod
    async def is_jti_blacklisted(self, jti: str) -> bool:
        """
        Check if a token with specific JWT ID is blacklisted.
        
        Args:
            jti: JWT ID to check
            
        Returns:
            True if blacklisted, False otherwise
            
        Raises:
            RepositoryError: If check fails
        """
        pass
    
    @abstractmethod
    async def blacklist_session(self, session_id: str) -> None:
        """
        Blacklist all tokens for a specific session.
        
        Args:
            session_id: The session ID to blacklist
            
        Raises:
            RepositoryError: If blacklisting fails
        """
        pass
    
    @abstractmethod
    async def remove_expired_entries(self) -> int:
        """
        Remove expired entries from the blacklist.
        
        Returns:
            Number of entries removed
            
        Raises:
            RepositoryError: If cleanup fails
        """
        pass