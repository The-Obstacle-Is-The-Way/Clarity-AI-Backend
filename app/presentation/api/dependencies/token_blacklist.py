"""
Token blacklist repository dependency provider.

This module provides the dependency injection for token blacklist repositories
used in the token revocation and session management flows.
"""

from typing import Annotated

from fastapi import Depends

from app.core.interfaces.repositories.token_blacklist_repository_interface import ITokenBlacklistRepository
from app.infrastructure.repositories.memory_token_blacklist_repository import MemoryTokenBlacklistRepository


def get_token_blacklist_repository():
    """
    Provides a token blacklist repository implementation.
    
    Returns an in-memory implementation for development and testing.
    In production, this should be replaced with a Redis-based implementation.
    
    Returns:
        An implementation of ITokenBlacklistRepository
    """
    # For development and testing, use the in-memory implementation
    # In production, this should be replaced with RedisTokenBlacklistRepository
    return MemoryTokenBlacklistRepository()


# Type annotation for dependency injection
# Use concrete implementation for FastAPI compatibility while preserving
# clean architecture inside the application
from app.infrastructure.repositories.memory_token_blacklist_repository import MemoryTokenBlacklistRepository
TokenBlacklistRepositoryDep = Annotated[MemoryTokenBlacklistRepository, Depends(get_token_blacklist_repository)]
