"""
User entity for the Clarity Digital Twin Backend.

COMPATIBILITY LAYER: This module re-exports the User entity from app.core.domain.entities.user
to maintain backward compatibility while ensuring type consistency across the codebase.

All new code should import User directly from app.core.domain.entities.user.
"""
# Python 3.9 compatibility layer
from __future__ import annotations

import warnings

# Re-export the User entity from app.core.domain.entities.user
from app.core.domain.entities.user import User, UserRole, UserStatus

# Show a deprecation warning when this module is imported
warnings.warn(
    "Importing User from app.domain.entities.user is deprecated. "
    "Import from app.core.domain.entities.user instead.",
    DeprecationWarning,
    stacklevel=2,
)

# This compatibility layer ensures backward compatibility while maintaining type consistency
# All the functionality is now provided by the User class imported from app.core.domain.entities.user
