"""
Digital Twin service dependencies for v1 API endpoints.

This module provides dependency injection functions for the Digital Twin
service required by the v1 API endpoints, following clean architecture principles.
"""

import logging
from typing import Annotated

from fastapi import Depends

from app.core.interfaces.services.digital_twin_service_interface import DigitalTwinServiceInterface
from app.infrastructure.di.provider import get_service_instance
from app.core.interfaces.services.mentallama_service_interface import MentaLLaMAInterface

logger = logging.getLogger(__name__)


def get_digital_twin_service() -> DigitalTwinServiceInterface:
    """
    Dependency for injecting the digital twin service.
    
    Returns:
        DigitalTwinServiceInterface: Instance of the digital twin service.
    """
    return get_service_instance(DigitalTwinServiceInterface)


# Type alias for cleaner dependency annotations
DigitalTwinServiceDep = Annotated[DigitalTwinServiceInterface, Depends(get_digital_twin_service)]

# Add this function to provide the MentaLLaMA service
def get_mentallama_service() -> MentaLLaMAInterface:
    """
    Provides the MentaLLaMA service instance for API endpoints.
    
    This function creates or returns an existing instance of the
    MentaLLaMA service for use in the API layer.
    
    Returns:
        A MentaLLaMAInterface implementation instance
    """
    from app.infrastructure.ml.mentallama.service import MockMentaLLaMAService
    
    try:
        service = MockMentaLLaMAService()
        if not service.is_healthy():
            service.initialize({})
        return service
    except Exception as e:
        logger.error(f"Failed to initialize MentaLLaMA service: {e}")
        # Return a basic service that will indicate it's unhealthy
        return MockMentaLLaMAService()