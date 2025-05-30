"""
Dependencies specific to the v1 API endpoints.

This module re-exports dependency functions required by
v1 API endpoints for improved code organization.
"""

# flake8: noqa: F401 - Allow unused imports for re-export

# Standard library imports (none)

# Third-party imports (none)

# First-party imports (sorted alphabetically by module path)
from app.presentation.api.dependencies.auth import (
    get_current_active_user,
    get_current_user,
    get_optional_user,
)
from app.presentation.api.dependencies.database import get_db, get_repository
from app.presentation.api.dependencies.rate_limiter import (
    RateLimitConfig,
    RateLimitScope,
    rate_limit,
)
from app.presentation.api.v1.dependencies.biometric import (
    get_alert_service,
    get_biometric_service,
)
from app.presentation.api.v1.dependencies.biometric_alert import (
    get_template_repository,  # Added import for the stub
)
from app.presentation.api.v1.dependencies.biometric_alert import (
    get_alert_repository,
    get_biometric_repository,
    get_rule_repository,
)
from app.presentation.api.v1.dependencies.digital_twin import get_digital_twin_service
from app.presentation.api.v1.dependencies.processing import get_event_processor

# Explicitly declare the public API of this module (sorted alphabetically)
__all__ = [
    "RateLimitConfig",
    "RateLimitScope",
    "get_alert_repository",
    "get_alert_service",
    "get_biometric_repository",
    "get_biometric_service",
    "get_current_active_user",
    "get_current_user",
    "get_db",
    "get_digital_twin_service",
    "get_event_processor",
    "get_optional_user",
    "get_repository",
    "get_rule_repository",
    "get_template_repository",  # Added export for the stub
    "rate_limit",
]
