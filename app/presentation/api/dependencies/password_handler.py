"""
Password handler dependency provider.

This module provides the dependency injection for password handling services
used throughout the application for secure authentication and HIPAA compliance.
"""

from typing import Annotated

from fastapi import Depends

from app.core.interfaces.security.password_handler_interface import IPasswordHandler
from app.infrastructure.security.password.password_handler import PasswordHandler


def get_password_handler() -> IPasswordHandler:
    """
    Provides a password handler implementation.

    Returns an instance of the password handler that implements the IPasswordHandler
    interface for secure password operations.

    Returns:
        An implementation of the IPasswordHandler interface
    """
    return PasswordHandler()


# Type annotation for dependency injection
# Use the interface type for dependency injection to ensure proper
# dependency inversion principle according to Clean Architecture
PasswordHandlerDep = Annotated[IPasswordHandler, Depends(get_password_handler)]


__all__ = [
    "PasswordHandlerDep",
    "get_password_handler",
]
