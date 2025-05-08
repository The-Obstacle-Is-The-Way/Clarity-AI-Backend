"""
DEPRECATED: This module is maintained for backward compatibility only.
Import from app.infrastructure.security.encryption.encryption_service instead.

This file will be removed in a future version. Update your imports to use the new path.
"""

import warnings

warnings.warn(
    "Importing from app.infrastructure.security.encryption_service is deprecated. "
    "Please import from app.infrastructure.security.encryption.encryption_service instead.",
    DeprecationWarning,
    stacklevel=2
)

from app.infrastructure.security.encryption.encryption_service import (
    EncryptionService,
    encrypt_field,
    decrypt_field,
    encrypt_phi,
    decrypt_phi,
    get_encryption_key
)

# Re-export for backward compatibility
__all__ = ["EncryptionService", "encrypt_field", "decrypt_field", "encrypt_phi", "decrypt_phi", "get_encryption_key"]