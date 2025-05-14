from fastapi import Depends

from app.core.interfaces.repositories.token_blacklist_repository_interface import ITokenBlacklistRepository
from app.infrastructure.security.token.in_memory_token_blacklist_repository import InMemoryTokenBlacklistRepository


# In-memory instance for now
_blacklist_repository_instance = InMemoryTokenBlacklistRepository()


async def get_token_blacklist_repository(
    # No explicit dependencies for the in-memory version for now
) -> ITokenBlacklistRepository:
    """
    Dependency provider for Token Blacklist Repository.

    Returns:
        ITokenBlacklistRepository implementation (in-memory for now).
    """
    return _blacklist_repository_instance
