"""
Dependencies specific to the v1 API endpoints.

This module re-exports dependency functions required by 
v1 API endpoints for improved code organization.
"""

from app.presentation.api.dependencies.auth import (
    get_current_user, 
    get_current_active_user,
    get_optional_user
)

from app.presentation.api.dependencies.database import (
    get_db,
    get_repository
)

from app.presentation.api.dependencies.rate_limiter import (
    rate_limit,
    RateLimitConfig,
    RateLimitScope
)

from app.presentation.api.v1.dependencies.biometric import (
    get_biometric_service,
    get_alert_service
)

# Import alert repository from correct module
from app.presentation.api.v1.dependencies.biometric_alert import get_alert_repository

from app.presentation.api.v1.dependencies.digital_twin import (
    get_digital_twin_service
)