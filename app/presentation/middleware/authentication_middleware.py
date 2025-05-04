"""
Authentication middleware compatibility module.

This module provides backward compatibility for tests and code
that still references the old app.presentation.middleware.authentication_middleware module.

DO NOT USE THIS IN NEW CODE - use app.core.security.middleware instead.
"""

# Re-export from the new location
