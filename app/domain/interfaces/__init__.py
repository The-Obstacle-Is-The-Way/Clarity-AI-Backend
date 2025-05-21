"""
Domain interfaces package.

This package contains interfaces that define contracts that various
implementations must adhere to, following the Dependency Inversion Principle.
"""

from app.domain.interfaces.pat_service import PATService
# Import from core layer instead of domain layer
from app.core.interfaces.repositories.token_repository_interface import ITokenRepository
from app.domain.interfaces.token_service import ITokenService

__all__ = ["ITokenRepository", "ITokenService", "PATService"]

"""Interfaces for domain services."""
