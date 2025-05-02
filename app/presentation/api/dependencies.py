"""
API dependency injection.

This module provides dependency injection functions for the API layer,
making services and other dependencies available to API endpoints.
"""

import logging
from typing import Annotated

from fastapi import Depends

from app.application.services.digital_twin_service import DigitalTwinService
from app.infrastructure.persistence.repositories.digital_twin_repository import DigitalTwinRepository
from app.core.dependencies.database import get_db_session


logger = logging.getLogger(__name__)


def get_digital_twin_repository(session=Depends(get_db_session)):
    """
    Get a digital twin repository instance.
    
    Args:
        session: Database session
        
    Returns:
        DigitalTwinRepository instance
    """
    return DigitalTwinRepository(session)


def get_digital_twin_service(repository=Depends(get_digital_twin_repository)):
    """
    Get a digital twin service instance.
    
    Args:
        repository: Digital twin repository
        
    Returns:
        DigitalTwinService instance
    """
    return DigitalTwinService(repository)


# Type aliases for common dependencies
DigitalTwinServiceDep = Annotated[DigitalTwinService, Depends(get_digital_twin_service)]