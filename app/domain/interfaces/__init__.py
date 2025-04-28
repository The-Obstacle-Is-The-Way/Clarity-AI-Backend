"""
Domain interfaces package.

This package contains interfaces that define contracts that various
implementations must adhere to, following the Dependency Inversion Principle.
"""

from app.domain.interfaces.token_service import ITokenService
from app.domain.interfaces.token_repository import ITokenRepository

__all__ = [
    "ITokenService",
    "ITokenRepository"
] 