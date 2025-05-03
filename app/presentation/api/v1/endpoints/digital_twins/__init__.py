"""
Digital Twins endpoints compatibility module.

This module provides backward compatibility for tests and code
that still references the old app.presentation.api.v1.endpoints.digital_twins module.

DO NOT USE THIS IN NEW CODE - use app.api.routes.v1.endpoints.digital_twins instead.
"""

# Re-export from the new location
from app.api.routes.v1.endpoints.digital_twins.router import router
