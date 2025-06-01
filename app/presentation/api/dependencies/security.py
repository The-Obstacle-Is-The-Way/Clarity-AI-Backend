"""
Security-related dependency providers for the Presentation Layer.

This module centralizes the creation and provision of security components
(like password handlers and JWT services) required by API endpoints and authentication services.
"""

import logging
from typing import Annotated

from fastapi import Depends

# Import interfaces from the core layer
from app.core.interfaces.security.jwt_service_interface import IJwtService
from app.core.interfaces.security.password_handler_interface import IPasswordHandler

# Import concrete implementations from the infrastructure layer
from app.infrastructure.security.jwt.jwt_service import get_jwt_service as infra_get_jwt_service
from app.infrastructure.security.password.password_handler import PasswordHandler

logger = logging.getLogger(__name__)


def get_password_handler() -> IPasswordHandler:
    """Dependency provider for the Password Handler.

    Returns an implementation of IPasswordHandler interface, following
    the Dependency Inversion Principle from SOLID.
    """
    logger.debug("Providing Password Handler dependency")
    # Return concrete implementation as interface type
    return PasswordHandler()


def get_jwt_service() -> IJwtService:
    """Dependency provider for the JWT Service.
    
    Returns an implementation of IJwtService interface, following
    the Dependency Inversion Principle from SOLID.
    
    This uses the existing JWT service factory in the infrastructure layer
    but exposes it through the interface type to ensure proper dependency inversion.
    """
    logger.debug("Providing JWT Service dependency")
    # Return concrete implementation as interface type
    return infra_get_jwt_service()

# Type hints for dependency injection using interfaces
PasswordHandlerDep = Annotated[IPasswordHandler, Depends(get_password_handler)]
JwtServiceDep = Annotated[IJwtService, Depends(get_jwt_service)]

__all__ = [
    "get_jwt_service",
    "get_password_handler",
    "JwtServiceDep",
    "PasswordHandlerDep",
]
