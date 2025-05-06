"""
Database Dependencies for FastAPI.

This module provides dependency functions for database sessions
to be injected into FastAPI endpoints.
"""

from collections.abc import AsyncGenerator, Callable
from typing import Any, TypeVar

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.config.settings import get_settings
from app.infrastructure.persistence.sqlalchemy.config.database import (
    get_db_session as get_session_from_config,
)

settings = get_settings()

from app.infrastructure.logging.logger import get_logger

logger = get_logger(__name__)

# Repository interfaces
from app.core.interfaces.repositories.user_repository_interface import IUserRepository

# Import biometric repository interfaces - these might need to be created if they don't exist
try:
    from app.core.interfaces.repositories.biometric_alert_repository import (
        IBiometricAlertRepository,
    )
    from app.core.interfaces.repositories.biometric_rule_repository import IBiometricRuleRepository
except ImportError:
    # If these interfaces don't exist yet, use placeholders for now
    # This allows the app to start while we implement these interfaces
    logger.warning("Biometric repository interfaces not found, using Any as placeholder")
    from typing import Any
    IBiometricAlertRepository = Any
    IBiometricRuleRepository = Any

# Import concrete repository implementations
# For biometric alert and rule repositories, we'll use Any as placeholder if they don't exist yet
from typing import Any

from app.infrastructure.repositories.user_repository import SqlAlchemyUserRepository

# Try to import concrete repository implementations, use placeholders if not found
try:
    from app.infrastructure.repositories.biometric_alert_repository import BiometricAlertRepository
except ImportError:
    logger.warning("BiometricAlertRepository not found, using placeholder")
    BiometricAlertRepository = Any  # type: ignore

try:
    from app.infrastructure.repositories.biometric_rule_repository import BiometricRuleRepository
except ImportError:
    logger.warning("BiometricRuleRepository not found, using placeholder")
    BiometricRuleRepository = Any  # type: ignore

T = TypeVar('T')

_repository_map: dict[type[T], type[T]] = {}

def register_repository(interface: type[T], implementation: type[T]) -> None:
    global _repository_map
    logger.debug(f"Registering repository: {interface.__name__} -> {implementation.__name__}")
    _repository_map[interface] = implementation

# --- Register Concrete Implementations ---

# Register the actual implementations for the application runtime
register_repository(IUserRepository, SqlAlchemyUserRepository)
register_repository(IBiometricRuleRepository, BiometricRuleRepository)
register_repository(IBiometricAlertRepository, BiometricAlertRepository)

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Provide an async database session for endpoints.
    Yields an AsyncSession from the configured session factory.
    """
    async for session in get_session_from_config():
        try:
            yield session
        except Exception as e:
             logger.error(f"Exception during DB session yield: {e}", exc_info=True)
             raise 
        # Session closing/rollback is handled by the context manager in get_session_from_config

def get_repository(repo_type: type[T]) -> Callable[[AsyncSession], T]:
    """
    Dependency factory for obtaining repository instances.
    Returns a function that expects an AsyncSession and returns the repository instance.
    The lookup of the implementation is deferred until the dependency is actually called.
    """
    # === DEBUG PRINT ===
    print(f"---> [DEBUG] Original get_repository called for repo_type: {repo_type.__name__}")
    # === END DEBUG PRINT ===

    # This inner function will be returned and called by FastAPI's dependency injection
    def _get_repo_instance_deferred_lookup(session: AsyncSession = Depends(get_db)) -> T:
        # === DEBUG PRINT ===
        print(f"------> [DEBUG] Inner _get_repo_instance_deferred_lookup executing for repo_type: {repo_type.__name__}")
        # === END DEBUG PRINT ===

        # Lookup happens here, when the dependency is resolved for a request
        def _lookup_implementation() -> type[T]:
            implementation = _repository_map.get(repo_type)
            if implementation is None:
                # === DEBUG PRINT ===
                print(f"---------> [DEBUG] FAILURE: No implementation found for {repo_type.__name__} in _repository_map: {_repository_map}")
                # === END DEBUG PRINT ===
                logger.error(f"Failed to find repository implementation for {repo_type.__name__}")
                # Log current map state for debugging
                logger.debug(f"Current repository map: {_repository_map}")
                raise NotImplementedError(
                    f"No repository implementation registered for {repo_type.__name__}"
                )
            return implementation

        implementation = _lookup_implementation()
        try:
            # Instantiate the concrete repository, passing the session
            instance = implementation(session=session)
            logger.debug(f"Successfully instantiated repository {implementation.__name__} for {repo_type.__name__}")
            return instance
        except Exception as e:
            logger.error(f"Error instantiating repository {implementation.__name__}: {e}", exc_info=True)
            raise  

    # Return the inner function which performs the deferred lookup and instantiation
    return _get_repo_instance_deferred_lookup