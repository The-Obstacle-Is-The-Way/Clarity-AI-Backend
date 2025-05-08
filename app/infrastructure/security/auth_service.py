"""
DEPRECATED: This module is maintained for backward compatibility only.
Import from app.infrastructure.security.auth.auth_service instead.

This file will be removed in a future version. Update your imports to use the new path.
"""

import warnings

warnings.warn(
    "Importing from app.infrastructure.security.auth_service is deprecated. "
    "Please import from app.infrastructure.security.auth.auth_service instead.",
    DeprecationWarning,
    stacklevel=2
)

from app.infrastructure.security.auth.auth_service import (
    AuthenticationService,
    get_auth_service
)

# Re-export for backward compatibility
__all__ = ["AuthenticationService", "get_auth_service"]