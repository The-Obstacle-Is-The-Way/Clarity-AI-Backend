"""
Security-related dependency providers for the Presentation Layer.

This module centralizes the creation and provision of security components
(like password handlers) required by API endpoints and authentication services.
"""

import logging
from typing import Annotated

from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt

# Import the concrete implementation from the infrastructure layer
from app.infrastructure.security.password.password_handler import PasswordHandler

# from app.config.settings import get_settings # Legacy import
from app.core.config.settings import get_settings # Corrected import
from app.domain.entities.user import User
from app.domain.exceptions import AuthenticationError

logger = logging.getLogger(__name__)

# TODO: Define IPasswordHandler in core.interfaces and use it here for Clean Architecture.
# from app.core.interfaces.security.password_handler_interface import IPasswordHandler

# Temporarily hinting with concrete class due to missing interface
def get_password_handler() -> PasswordHandler:
    """Dependency provider for the Password Handler."""
    logger.debug("Providing Password Handler dependency")
    # Simply return an instance of the concrete implementation
    return PasswordHandler()

# Type hint for dependency injection
# Temporarily hinting with concrete class
PasswordHandlerDep = Annotated[PasswordHandler, Depends(get_password_handler)]

__all__ = [
    "get_password_handler",
    "PasswordHandlerDep",
]
