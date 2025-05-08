"""
DEPRECATED: For backward compatibility only. 
Import from app.infrastructure.security.encryption.encryption_service instead.
"""

import warnings

warnings.warn(
    "Importing from app.infrastructure.security.encryption_service is deprecated. "
    "Please import from app.infrastructure.security.encryption.encryption_service instead.",
    DeprecationWarning,
    stacklevel=2
)

from app.infrastructure.security.encryption.encryption_service import (
    EncryptionService
)

# Re-export for backward compatibility
__all__ = ["EncryptionService"]