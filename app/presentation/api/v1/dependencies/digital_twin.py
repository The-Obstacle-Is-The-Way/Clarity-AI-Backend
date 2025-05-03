"""
Digital Twin service dependencies for v1 API endpoints.

This module provides dependency injection functions for the Digital Twin
service required by the v1 API endpoints, following clean architecture principles.
"""

from typing import Annotated

from fastapi import Depends

from app.core.interfaces.services.digital_twin_service_interface import DigitalTwinServiceInterface
from app.infrastructure.di.provider import get_service_instance


def get_digital_twin_service() -> DigitalTwinServiceInterface:
    """
    Dependency for injecting the digital twin service.
    
    Returns:
        DigitalTwinServiceInterface: Instance of the digital twin service.
    """
    return get_service_instance(DigitalTwinServiceInterface)


# Type alias for cleaner dependency annotations
DigitalTwinServiceDep = Annotated[DigitalTwinServiceInterface, Depends(get_digital_twin_service)]