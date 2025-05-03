"""
Authentication dependencies compatibility module.

This module provides backward compatibility for tests and code
that still references the old app.presentation.api.dependencies.auth module.

DO NOT USE THIS IN NEW CODE - use app.api.dependencies instead.
"""

# Re-export from the new location
from app.api.dependencies import get_current_user, get_authentication_service, get_jwt_service
