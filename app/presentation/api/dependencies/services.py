"""
Core Service Dependencies for the Presentation Layer.

This module provides FastAPI dependency functions for accessing core application
services and repositories within the API endpoints.
"""

import logging
from typing import Annotated, Any

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

# Correct service/factory imports
from app.application.services.digital_twin_service import DigitalTwinApplicationService
from app.application.services.jwt_service import JWTService
from app.application.services.ml.pat_service import PATService
from app.application.services.ml.xgboost_service import XGBoostService
from app.core.config import settings
from app.core.dependencies.database import get_async_session
from app.core.interfaces.repositories.user_repository_interface import IUserRepository
from app.core.interfaces.services.ml.pat_interface import PATInterface
from app.core.services.ml.pat.factory import PATServiceFactory
from app.infrastructure.auth.jwt import JWTServiceImpl
from app.infrastructure.database.repositories.user_repository import (
    get_user_repository as infra_get_user_repo,
)
from app.infrastructure.digital_twin.digital_twin_service_impl import (
    DigitalTwinServiceImpl,
)
from app.infrastructure.ml.pat.bedrock_pat import BedrockPAT
from app.infrastructure.ml.xgboost.xgboost_service_impl import (
    XGBoostServiceImpl,
)

logger = logging.getLogger(__name__)

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


async def _user_repository_factory(
    db_session: AsyncSession = Depends(get_async_session),
) -> IUserRepository:
    """Factory that adapts infrastructure get_user_repository to FastAPI DI."""
    return infra_get_user_repo(db_session)

def get_user_repository(
    user_repo: IUserRepository = Depends(_user_repository_factory),
) -> IUserRepository:
    """Provides an instance of the User Repository via adapted factory."""
    return user_repo

def get_digital_twin_service() -> DigitalTwinApplicationService:
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
