"""
Core Service Dependencies for the Presentation Layer.

This module provides FastAPI dependency functions for accessing core application
services and repositories within the API endpoints.
"""

from typing import Annotated, Any

from fastapi import Depends

# Correct service/factory imports
from app.core.interfaces.repositories.user_repository_interface import IUserRepository
from app.core.interfaces.services.ml.pat_interface import PATInterface
from app.core.services.ml.pat.factory import PATServiceFactory
from app.infrastructure.repositories.user_repository import (
    get_user_repository as infra_get_user_repo,
)

# --- Type Hinting for Dependencies --- #

PATServiceDep = Annotated[
    PATInterface, Depends(PATServiceFactory.create_pat_service)
]
UserRepoDep = Annotated[
    IUserRepository, Depends(infra_get_user_repo)
]  # Reusing from auth.py, but defining here for clarity

# --- Dependency Functions --- #

def get_pat_service(
    pat_service: PATInterface = Depends(PATServiceFactory.create_pat_service),
) -> PATInterface:
    """Provides an instance of the PAT Service created via its factory."""
    return pat_service

# Wrapper to inject AsyncSession into infrastructure-level factory
from app.core.dependencies.database import get_db_session
from sqlalchemy.ext.asyncio import AsyncSession

async def _user_repository_factory(
    db_session: AsyncSession = Depends(get_db_session),
) -> IUserRepository:
    """Factory that adapts infrastructure get_user_repository to FastAPI DI."""
    return infra_get_user_repo(db_session)

def get_user_repository(
    user_repo: IUserRepository = Depends(_user_repository_factory),
) -> IUserRepository:
    """Provides an instance of the User Repository via adapted factory."""
    return user_repo

def get_digital_twin_service() -> Any | None:
    """
    Provide a Digital Twin service implementation.
    
    Backward compatibility function - use app.api.dependencies instead in new code.
    
    Returns:
        Digital Twin service implementation
    """
    # Simple stub implementation to allow test collection
    return None

def get_xgboost_service() -> Any | None:
    """
    Provide an XGBoost service implementation.
    
    Backward compatibility function - use app.api.dependencies instead in new code.
    
    Returns:
        XGBoost service implementation
    """
    # Delegate to the clean architecture implementation
    from app.api.routes.xgboost import get_xgboost_service as new_get_xgboost_service
    return new_get_xgboost_service()
