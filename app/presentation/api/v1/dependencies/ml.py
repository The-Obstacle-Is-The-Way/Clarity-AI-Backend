"""
ML Service Dependency Provider Module.

This module provides dependency injection for ML services
in the FastAPI application, following Clean Architecture principles.
"""

import logging
from typing import Annotated, cast

from fastapi import Depends
from sqlalchemy.orm import Session

from app.core.interfaces.services.ml_service_interface import MLServiceInterface
from app.infrastructure.services.ml_service import MLService
from app.presentation.api.dependencies.database import get_db

# Configure logger
logger = logging.getLogger(__name__)


async def get_ml_service(db: Session = Depends(get_db)) -> MLServiceInterface:
    """
    Provide an instance of MLServiceInterface for dependency injection.
    
    This function creates and returns an MLService instance that
    implements the MLServiceInterface, allowing for proper dependency
    injection and adherence to the Dependency Inversion Principle.
    
    Args:
        db: Database session dependency
        
    Returns:
        An instance of a class implementing MLServiceInterface
    """
    logger.debug("Creating ML service instance for dependency injection")
    
    # Create concrete implementation of the interface
    service = MLService(db)
    
    # Cast to the interface type to ensure proper typing
    return cast(MLServiceInterface, service)


# Type alias for cleaner dependency usage in endpoints
MLServiceDep = Annotated[MLServiceInterface, Depends(get_ml_service)]
