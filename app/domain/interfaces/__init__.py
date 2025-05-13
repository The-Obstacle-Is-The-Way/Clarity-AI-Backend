"""
Domain interfaces package.

This package contains interfaces that define contracts that various
implementations must adhere to, following the Dependency Inversion Principle.
"""

from app.domain.interfaces.token_repository import ITokenRepository
from app.domain.interfaces.token_service import ITokenService
from app.domain.interfaces.pat_service import PATService

__all__ = [
    "ITokenRepository",
    "ITokenService",
    "PATService"
]

"""Interfaces for domain services.""" 