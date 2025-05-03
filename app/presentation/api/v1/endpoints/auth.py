"""
Authentication endpoints compatibility module.

This module provides backward compatibility for tests and code
that still references the old app.presentation.api.v1.endpoints.auth module.

DO NOT USE THIS IN NEW CODE - use app.api.routes.auth instead.
"""

# Re-export from the new location 
from app.api.routes.auth import router
