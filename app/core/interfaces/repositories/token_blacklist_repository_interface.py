"""
Interface for token blacklist repository to maintain clean architecture boundaries and
provide a consistent contract for token invalidation operations.

Supports HIPAA compliance by ensuring secure session management and token revocation.
"""

from abc import ABC, abstractmethod
from typing import List, Optional
from uuid import UUID


class ITokenBlacklistRepository(ABC):
    """Interface for token blacklist repository operations.
    
    Defines contract for blacklisting JWT tokens to prevent their reuse,
    supporting secure session management and token invalidation according to
    HIPAA security requirements.
    """
    
    @abstractmethod
    async def add_to_blacklist(self, token_id: str, expires_at: Optional[int] = None) -> bool:
        """Add a token ID to the blacklist.
        
        Args:
            token_id: JWT token ID (jti) to blacklist
            expires_at: Optional Unix timestamp when token expires
            
        Returns:
            True if successfully added to the blacklist
        """
        pass
    
    @abstractmethod
    async def is_blacklisted(self, token: str) -> bool:
        """Check if a token is blacklisted by its full token string.
        
        Args:
            token: Full JWT token string
            
        Returns:
            True if token is blacklisted
        """
        pass
    
    @abstractmethod
    async def is_jti_blacklisted(self, jti: str) -> bool:
        """Check if a token ID is blacklisted.
        
        Args:
            jti: JWT token ID to check
            
        Returns:
            True if the token ID is blacklisted
        """
        pass
    
    @abstractmethod
    async def blacklist_session(self, session_id: str) -> bool:
        """Blacklist all tokens associated with a session.
        
        Args:
            session_id: Session identifier to blacklist
            
        Returns:
            True if session was successfully blacklisted
        """
        pass
    
    @abstractmethod
    async def blacklist_user_tokens(self, user_id: str) -> bool:
        """Blacklist all tokens for a specific user.
        
        Args:
            user_id: User identifier whose tokens should be blacklisted
            
        Returns:
            True if user tokens were successfully blacklisted
        """
        pass
    
    @abstractmethod
    async def clear_expired_tokens(self) -> int:
        """Remove expired tokens from the blacklist.
        
        Returns:
            Number of tokens removed from blacklist
        """
        pass