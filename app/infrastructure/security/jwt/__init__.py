# app.infrastructure.security.jwt

"""
JWT authentication components for the Novamind Digital Twin Backend.

This module provides JWT token handling, validation, and management.
"""

# Only export the service implementation, not the dependency getter
from .jwt_service import JWTService

__all__ = [
    "JWTService",
    # "get_jwt_service" # <-- REMOVED
]

# Remove import from non-existent module
# from app.infrastructure.security.jwt.token_handler import TokenHandler 
# Remove import from non-existent module
# from app.infrastructure.security.jwt.jwt_auth import JWTAuth
# Remove incorrect import of functions; they are methods of JWTService
# from app.infrastructure.security.jwt.jwt_service import (
#     create_access_token,
#     create_refresh_token,
#     verify_token,
#     get_current_user # Assuming get_current_user is also in jwt_service
# )
