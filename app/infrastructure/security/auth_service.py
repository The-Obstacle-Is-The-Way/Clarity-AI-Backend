"""
DEPRECATED: For backward compatibility only. 
Import from app.infrastructure.security.auth.auth_service instead.
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