"""
Digital Twin service dependencies for v1 API endpoints.

This module provides dependency injection functions for the Digital Twin
service required by the v1 API endpoints, following clean architecture principles.
"""

# Standard libs
import logging
from typing import Annotated, Protocol, TypeVar, cast

# Third-party
from fastapi import Depends

# Project
from app.core.interfaces.services.digital_twin_service_interface import (
    DigitalTwinServiceInterface,
)
from app.core.services.ml.interface import MentaLLaMAInterface
from app.infrastructure.di.container import get_container

logger = logging.getLogger(__name__)

T = TypeVar("T")


class _SupportsGet(Protocol):
    """Minimal protocol exposing ``get`` used by the DI container."""

    def get(self, interface: type[T]) -> T: ...


def get_digital_twin_service() -> DigitalTwinServiceInterface:
    """Return a concrete implementation of the `DigitalTwinServiceInterface`."""

    container: _SupportsGet = get_container()
    return container.get(DigitalTwinServiceInterface)


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
        return cast(MentaLLaMAInterface, service)
    except Exception as exc:  # pragma: no cover - log then fallback
        logger.error("Failed to initialize MentaLLaMA service: %s", exc)
        return cast(MentaLLaMAInterface, MockMentaLLaMAService())
