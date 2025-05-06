"""
Token Repository Interface.

This module defines the interface for token repository operations,
supporting authentication and authorization in the application
while maintaining HIPAA compliance and clean architecture.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID


class ITokenRepository(ABC):
    """
    Interface for token repository operations.
    
    This interface encapsulates the functionality required for storing,
    retrieving, and managing authentication tokens according to HIPAA
    requirements and security best practices.
    """
    
    @abstractmethod
    async def store_token(
        self,
        user_id: UUID,
        token_id: str,
        token_type: str,
        expires_at: datetime,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Store a token in the repository.
        
        Args:
            user_id: ID of the user the token belongs to
            token_id: Unique identifier for the token (JTI)
            token_type: Type of token (access, refresh)
            expires_at: Expiration timestamp
            metadata: Additional token metadata
            
        Raises:
            RepositoryError: If token storage fails
        """
        pass
    
    @abstractmethod
    async def get_user_tokens(
        self,
        user_id: UUID,
        token_type: Optional[str] = None,
        active_only: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Get all tokens for a specific user.
        
        Args:
            user_id: ID of the user
            token_type: Filter by token type (optional)
            active_only: If True, only return non-expired tokens
            
        Returns:
            List of token data dictionaries
            
        Raises:
            RepositoryError: If token retrieval fails
        """
        pass
    
    @abstractmethod
    async def invalidate_token(self, token_id: str) -> bool:
        """
        Invalidate a specific token.
        
        Args:
            token_id: Unique identifier for the token (JTI)
            
        Returns:
            True if token was invalidated, False if token not found
            
        Raises:
            RepositoryError: If token invalidation fails
        """
        pass
    
    @abstractmethod
    async def invalidate_user_tokens(
        self,
        user_id: UUID,
        token_type: Optional[str] = None,
        exclude_token_ids: Optional[List[str]] = None
    ) -> int:
        """
        Invalidate all tokens for a user.
        
        Args:
            user_id: ID of the user
            token_type: Only invalidate tokens of this type (optional)
            exclude_token_ids: List of token IDs to exclude from invalidation
            
        Returns:
            Number of tokens invalidated
            
        Raises:
            RepositoryError: If token invalidation fails
        """
        pass
    
    @abstractmethod
    async def clean_expired_tokens(self) -> int:
        """
        Remove expired tokens from the repository.
        
        Returns:
            Number of tokens removed
            
        Raises:
            RepositoryError: If token cleanup fails
        """
        pass