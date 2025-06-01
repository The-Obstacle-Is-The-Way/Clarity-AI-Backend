"""
Token blacklist repository interface definition.

This module defines the interface for token blacklisting repositories, ensuring proper
abstraction between the application layer and concrete infrastructure implementations.
This is critical for secure JWT token management and HIPAA compliance.
"""
from abc import ABC, abstractmethod
from datetime import datetime
from typing import List, Optional
from uuid import UUID


class ITokenBlacklistRepository(ABC):
    """
    Interface for token blacklist repositories.
    
    All token blacklist repository implementations must adhere to this interface.
    This follows the Dependency Inversion Principle by allowing high-level modules
    to depend on this abstraction rather than concrete implementations.
    """
    
    @abstractmethod
    async def add_to_blacklist(
        self, 
        token_jti: str, 
        user_id: UUID, 
        expires_at: datetime,
        token_type: str = "access",
        reason: Optional[str] = None
    ) -> None:
        """
        Add a token to the blacklist.
        
        Args:
            token_jti: The JWT token ID (jti claim)
            user_id: The user ID associated with the token
            expires_at: When the token expires
            token_type: Type of token (e.g., "access", "refresh")
            reason: Optional reason for blacklisting (e.g., "logout", "password_change")
        """
        pass
    
    @abstractmethod
    async def is_blacklisted(self, token_jti: str) -> bool:
        """
        Check if a token is blacklisted.
        
        Args:
            token_jti: The JWT token ID (jti claim)
            
        Returns:
            True if the token is blacklisted, False otherwise
        """
        pass
    
    @abstractmethod
    async def get_blacklisted_tokens_for_user(self, user_id: UUID) -> List[dict]:
        """
        Get all blacklisted tokens for a specific user.
        
        Args:
            user_id: The user ID
            
        Returns:
            List of dictionaries containing blacklisted token information
        """
        pass
    
    @abstractmethod
    async def remove_expired_tokens(self) -> int:
        """
        Remove expired tokens from the blacklist.
        
        Returns:
            Number of tokens removed
        """
        pass
    
    @abstractmethod
    async def blacklist_all_for_user(
        self, 
        user_id: UUID, 
        reason: str = "security_measure"
    ) -> int:
        """
        Blacklist all active tokens for a specific user.
        
        This is particularly important for security events such as:
        - Password changes
        - Detected suspicious activity
        - Account lockouts
        - Force logout of all sessions
        
        Args:
            user_id: The user ID
            reason: Reason for blacklisting all tokens
            
        Returns:
            Number of tokens blacklisted
        """
        pass