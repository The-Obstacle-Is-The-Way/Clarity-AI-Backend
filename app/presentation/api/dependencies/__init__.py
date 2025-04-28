"""
Package for application‑level dependency helpers.

This package contains FastAPI dependency modules (database, services,
authentication, rate limiting, etc.) under their own files. Sub‑modules
can be imported directly:

    from app.presentation.api.dependencies.rate_limiter import RateLimitDependency
    from app.presentation.api.dependencies.auth import get_current_user
"""
# No legacy backward‑compat shims here – sub‑modules live under this package.


