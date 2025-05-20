"""
Interface for Token Blacklist Repository.

This module defines the interface for a repository that manages blacklisted tokens
to enforce secure token invalidation for compliance with HIPAA security requirements.
"""

from abc import ABC, abstractmethod
from datetime import datetime


class ITokenBlacklistRepository(ABC):
    """
    Interface for a token blacklist repository.
    
    This interface defines the contract for repositories that handle the blacklisting
    of JWT tokens (e.g., after logout or token revocation) to prevent token reuse.
    Implementations should provide secure, persistent storage for blacklisted tokens.
    """
    
    @abstractmethod
    async def add_to_blacklist(self, token: str, jti: str, expires_at: datetime, reason: str | None = None) -> None:
        """
        Add a token to the blacklist.
        
        Args:
            token: The token value to blacklist
            jti: JWT ID - unique identifier for the token
            expires_at: When the token expires
            reason: Reason for blacklisting (optional)
        """
        pass
    
    @abstractmethod
    async def is_blacklisted(self, token: str) -> bool:
        """
        Check if a token is blacklisted.
        
        Args:
            token: The token value to check
            
        Returns:
            True if the token is blacklisted, False otherwise
        """
        pass
    
    @abstractmethod
    async def is_jti_blacklisted(self, token_id: str) -> bool:
        """
        Check if a token ID (JTI) is blacklisted.
        
        Args:
            token_id: The token ID (JTI) to check
            
        Returns:
            True if the token ID is blacklisted, False otherwise
        """
        pass
    
    @abstractmethod
    async def clear_expired_tokens(self) -> int:
        """
        Remove expired tokens from the blacklist.
        
        This should be called periodically to clean up the blacklist.
        
        Returns:
            The number of tokens removed from the blacklist
        """
        pass