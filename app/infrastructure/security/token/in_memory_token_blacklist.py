"""
Factory for in-memory token blacklist repositories for testing.

This module provides factory functions for creating token blacklist repositories
that can be used for testing and development purposes.
"""

from app.infrastructure.security.token.in_memory_token_blacklist_repository import InMemoryTokenBlacklistRepository
from app.core.interfaces.repositories.token_blacklist_repository_interface import ITokenBlacklistRepository


def get_in_memory_token_blacklist_repository() -> ITokenBlacklistRepository:
    """
    Create and return an in-memory token blacklist repository.
    
    This factory function creates an InMemoryTokenBlacklistRepository instance
    suitable for testing and development environments.
    
    Returns:
        ITokenBlacklistRepository: An in-memory implementation of the token blacklist repository interface
    """
    return InMemoryTokenBlacklistRepository()


# Alternative name for fastapi Depends injection
async def get_token_blacklist_repository_for_testing() -> ITokenBlacklistRepository:
    """
    Async dependency function to get an in-memory token blacklist repository for testing.
    
    This function can be used with FastAPI's Depends for injecting a token blacklist
    repository in test environments.
    
    Returns:
        ITokenBlacklistRepository: An in-memory implementation of the token blacklist repository interface
    """
    return InMemoryTokenBlacklistRepository() 