"""
Authentication components for the Novamind Digital Twin Backend.

This module provides authentication services, middleware, and handlers
for user authentication, MFA, and session management.
"""

# Remove incorrect import from non-existent module
# from app.infrastructure.security.auth.auth import TokenAuthorizationError, PermissionType, RolePermission, AuthorizationScope
# Remove incorrect import of middleware from presentation layer
# from app.infrastructure.security.auth.auth_middleware import JWTAuthMiddleware
from app.infrastructure.security.auth.mfa_service import MFAService 