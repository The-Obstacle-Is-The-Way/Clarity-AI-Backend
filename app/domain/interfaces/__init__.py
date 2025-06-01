"""
Domain interfaces package.

This package contains interfaces that define contracts that various
implementations must adhere to, following the Dependency Inversion Principle.
"""

# Import from core layer instead of domain layer
from app.core.interfaces.repositories.token_repository_interface import ITokenRepository
from app.domain.interfaces.pat_service import PATService
from app.domain.interfaces.token_service import ITokenService
from app.domain.interfaces.user_repository import UserRepositoryInterface

# Re-export frequently-used interfaces for convenience/compat.
__all__ = [
    "ITokenRepository",
    "ITokenService",
    "PATService",
    "UserRepositoryInterface",
]

"""Interfaces for domain services."""
