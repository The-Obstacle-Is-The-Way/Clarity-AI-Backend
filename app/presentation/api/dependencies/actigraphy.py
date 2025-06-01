"""
Actigraphy Service Dependency Provider Module.

This module provides dependency injection for Actigraphy services
in the FastAPI application, following Clean Architecture principles.
"""

import logging
from typing import Annotated, cast

from fastapi import Depends
from sqlalchemy.orm import Session

from app.core.interfaces.services.actigraphy_service_interface import ActigraphyServiceInterface
from app.infrastructure.services.actigraphy_service import ActigraphyService
from app.presentation.api.dependencies.database import get_db

# Configure logger
logger = logging.getLogger(__name__)


async def get_actigraphy_service(db: Session = Depends(get_db)) -> ActigraphyServiceInterface:
    """
    Provide an instance of ActigraphyServiceInterface for dependency injection.
    
    This function creates and returns an ActigraphyService instance that
    implements the ActigraphyServiceInterface, allowing for proper dependency
    injection and adherence to the Dependency Inversion Principle.
    
    Args:
        db: Database session dependency
        
    Returns:
        An instance of a class implementing ActigraphyServiceInterface
    """
    logger.debug("Creating Actigraphy service instance for dependency injection")
    
    # Create concrete implementation of the interface
    service = ActigraphyService(db)
    
    # Cast to the interface type to ensure proper typing
    return cast(ActigraphyServiceInterface, service)


# Type alias for cleaner dependency usage in endpoints
ActigraphyServiceDep = Annotated[ActigraphyServiceInterface, Depends(get_actigraphy_service)]
