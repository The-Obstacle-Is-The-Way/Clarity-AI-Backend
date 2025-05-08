"""
DEPRECATED: This module is maintained for backward compatibility only.
Import from app.infrastructure.security.password.password_handler instead.

This file will be removed in a future version. Update your imports to use the new path.
"""

import warnings

warnings.warn(
    "Importing from app.infrastructure.security.password_handler is deprecated. "
    "Please import from app.infrastructure.security.password.password_handler instead.",
    DeprecationWarning,
    stacklevel=2
)

from app.infrastructure.security.password.password_handler import (
    PasswordHandler,
    get_password_handler,
    get_password_hash,
    verify_password
)

# Re-export for backward compatibility
__all__ = ["PasswordHandler", "get_password_handler", "get_password_hash", "verify_password"]