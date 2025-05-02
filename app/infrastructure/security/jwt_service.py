"""
JWT service facade.

This module provides a clean facade for JWT token generation and validation
following SOLID principles and GOF patterns for clean architecture.
"""

from functools import lru_cache

from fastapi import Depends

from app.core.config.settings import Settings, get_settings
from app.infrastructure.security.jwt.jwt_service import JWTService

@lru_cache
def get_jwt_service(
    settings: Settings = Depends(get_settings)
) -> JWTService:
    """
    Get an instance of the JWT service with proper configuration.
    
    This factory function creates a JWT service with
    the necessary settings for secure token handling,
    following clean architecture principles.
    
    Args:
        settings: Application settings
        
    Returns:
        An initialized JWT service
    """
    return JWTService(settings)
