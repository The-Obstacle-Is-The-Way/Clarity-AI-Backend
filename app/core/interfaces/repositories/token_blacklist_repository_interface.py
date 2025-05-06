"""
Token Blacklist Repository Interface.

This module defines the interface for token blacklist repositories used for JWT token revocation.
Following the Repository Pattern and Interface Segregation Principle from SOLID.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Optional


class ITokenBlacklistRepository(ABC):
    """Interface for token blacklist repository operations.
    
    This interface defines the contract that any token blacklist repository implementation
    must follow. It provides methods for blacklisting tokens, checking if tokens are
    blacklisted, and managing token expiration.
    """
    
    @abstractmethod
    async def add_to_blacklist(self, token_jti: str, expires_at: datetime) -> bool:
        """Add a token to the blacklist.
        
        Args:
            token_jti: The unique identifier (JTI) of the token to blacklist
            expires_at: When the token would naturally expire
            
        Returns:
            bool: True if successfully blacklisted, False otherwise
        """
        pass
    
    @abstractmethod
    async def is_blacklisted(self, token_jti: str) -> bool:
        """Check if a token is blacklisted.
        
        Args:
            token_jti: The unique identifier (JTI) of the token to check
            
        Returns:
            bool: True if token is blacklisted, False otherwise
        """
        pass
    
    @abstractmethod
    async def remove_expired(self, before_time: Optional[datetime] = None) -> int:
        """Remove expired tokens from the blacklist.
        
        Args:
            before_time: Optional time threshold, tokens that expired before this time
                         will be removed. If None, current time is used.
            
        Returns:
            int: Number of expired tokens removed
        """
        pass
    
    @abstractmethod
    async def clear_blacklist(self) -> bool:
        """Clear all tokens from the blacklist.
        
        This is primarily used for testing and maintenance purposes.
        
        Returns:
            bool: True if successful, False otherwise
        """
        pass
