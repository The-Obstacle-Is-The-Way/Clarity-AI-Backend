"""
Rate limiting middleware compatibility module.

This module provides backward compatibility for tests and code
that still references the old app.presentation.middleware.rate_limiting_middleware module.

DO NOT USE THIS IN NEW CODE - use app.core.security.rate_limiting instead.
"""

# Re-export from the new location
from app.core.security.rate_limiting import RateLimitingMiddleware
