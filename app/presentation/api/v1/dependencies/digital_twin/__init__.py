"""
Digital Twin Dependencies Module.

This module provides dependency injection for Digital Twin services
in the FastAPI application, following Clean Architecture principles.
"""

import logging
from typing import Annotated, cast

from fastapi import Depends
from sqlalchemy.orm import Session

from app.core.interfaces.services.digital_twin_interface import DigitalTwinInterface
from app.core.services.ml.interface import MentaLLaMAInterface
from app.infrastructure.services.digital_twin_service import DigitalTwinService
from app.infrastructure.services.mentallama_service import MentaLLaMAService
from app.presentation.api.dependencies.database import get_db

# Configure logger
logger = logging.getLogger(__name__)


async def get_digital_twin_service(db: Session = Depends(get_db)) -> DigitalTwinInterface:
    """
    Provide an instance of DigitalTwinInterface for dependency injection.
    
    This function creates and returns a DigitalTwinService instance that
    implements the DigitalTwinInterface, allowing for proper dependency
    injection and adherence to the Dependency Inversion Principle.
    
    Args:
        db: Database session dependency
        
    Returns:
        An instance of a class implementing DigitalTwinInterface
    """
    logger.debug("Creating Digital Twin service instance for dependency injection")
    
    # Create concrete implementation of the interface
    service = DigitalTwinService(db)
    
    # Cast to the interface type to ensure proper typing
    return cast(DigitalTwinInterface, service)


async def get_mentallama_service(db: Session = Depends(get_db)) -> MentaLLaMAInterface:
    """
    Provide an instance of MentaLLaMAInterface for dependency injection.
    
    This function creates and returns a MentaLLaMAService instance that
    implements the MentaLLaMAInterface, allowing for proper dependency
    injection and adherence to the Dependency Inversion Principle.
    
    Args:
        db: Database session dependency
        
    Returns:
        An instance of a class implementing MentaLLaMAInterface
    """
    logger.debug("Creating MentaLLaMA service instance for dependency injection")
    
    # Create concrete implementation of the interface
    service = MentaLLaMAService(db)
    
    # Cast to the interface type to ensure proper typing
    return cast(MentaLLaMAInterface, service)


# Type aliases for cleaner dependency usage in endpoints
DigitalTwinServiceDep = Annotated[DigitalTwinInterface, Depends(get_digital_twin_service)]
MentaLLaMAServiceDep = Annotated[MentaLLaMAInterface, Depends(get_mentallama_service)]
