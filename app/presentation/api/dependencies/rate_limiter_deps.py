"""
Rate limiter dependencies compatibility module.

This module provides backward compatibility for tests and code
that still references the old app.presentation.api.dependencies.rate_limiter_deps module.

DO NOT USE THIS IN NEW CODE - use app.core.security.rate_limiting instead.
"""

# Re-export from the new location
