"""
Authentication components for the Novamind Digital Twin Backend.

This module provides authentication services, middleware, and handlers
for user authentication, MFA, and session management.
"""

from app.infrastructure.security.auth.auth_service import AuthenticationService as AuthService
from app.infrastructure.security.auth.auth_service import (
    get_auth_service,
)
from app.infrastructure.security.auth.authentication_service import (
    AuthenticationService,
)
from app.infrastructure.security.auth.jwt_handler import (
    create_access_token,
    create_refresh_token,
    decode_token,
    get_token_data,
    validate_access_token,
)
from app.infrastructure.security.auth.mfa_service import MFAService

__all__ = [
    "AuthService",
    "AuthenticationService",
    "MFAService",
    "create_access_token",
    "create_refresh_token",
    "decode_token",
    "get_auth_service",
    "get_token_data",
    "validate_access_token",
]
