"""
Encryption components for the Novamind Digital Twin Backend.

This module provides quantum-resistant encryption services for securing sensitive data,
including field-level encryption, key rotation, and HIPAA-compliant data protection.
"""

import base64
import json
import logging
import os
from typing import Any, Dict, Optional, Union

# Configure logger
logger = logging.getLogger(__name__)

# Default encryption key for testing - NEVER use in production
# In production, keys should be loaded from secure environment variables or key vaults
DEFAULT_TEST_KEY = "WnZr4u7x!A%D*G-KaPdSgVkYp3s6v9y$"


def get_settings():
    """
    Get application settings from settings module.

    Returns:
        Settings: Application settings object
    """
    try:
        from app.core.config.settings import get_settings as get_app_settings

        return get_app_settings()
    except ImportError:
        logger.warning("Could not import app settings, using defaults")
        from types import SimpleNamespace

        return SimpleNamespace(
            PHI_ENCRYPTION_KEY=DEFAULT_TEST_KEY,
            PHI_ENCRYPTION_PREVIOUS_KEY=None,
            DEBUG=False,
        )


def get_default_encryption_key() -> str:
    """
    Get the default encryption key from settings or environment.

    This function prioritizes settings over environment variables and
    provides a fallback for testing environments.

    Returns:
        str: Encryption key string
    """
    settings = get_settings()

    # Try to get the key from settings
    if hasattr(settings, "PHI_ENCRYPTION_KEY") and settings.PHI_ENCRYPTION_KEY:
        return settings.PHI_ENCRYPTION_KEY

    if hasattr(settings, "ENCRYPTION_KEY") and settings.ENCRYPTION_KEY:
        return settings.ENCRYPTION_KEY

    # Check environment variables
    env_key = os.environ.get("PHI_ENCRYPTION_KEY") or os.environ.get("ENCRYPTION_KEY")
    if env_key:
        return env_key

    # Fallback for testing - NEVER use in production
    logger.warning("No encryption key found, using default test key. DO NOT USE IN PRODUCTION!")
    return DEFAULT_TEST_KEY


def get_encryption_key() -> str:
    """Get the current primary encryption key from settings.

    Returns:
        str: Current encryption key
    """
    settings = get_settings()
    if not settings.PHI_ENCRYPTION_KEY:
        logger.warning("PHI_ENCRYPTION_KEY is not set in settings, using default key.")
        return DEFAULT_TEST_KEY
    return settings.PHI_ENCRYPTION_KEY


# Global encryption service instance for singleton access
encryption_service_instance = None


def get_encryption_service(
    direct_key: str | None = None,
    previous_key: str | None = None,
    reinitialize: bool = False,
) -> "BaseEncryptionService":
    """
    Get an instance of the encryption service.

    This implements the singleton pattern with thread safety considerations.

    Args:
        direct_key: Optional key to use directly (primarily for testing)
        previous_key: Optional previous key to support key rotation
        reinitialize: Force reinitialization of the encryption service

    Returns:
        BaseEncryptionService: The encryption service instance
    """
    global encryption_service_instance

    try:
        # Singleton initialization
        if encryption_service_instance is None or reinitialize:
            from app.infrastructure.security.encryption.base_encryption_service import (
                BaseEncryptionService,
            )

            # Use the provided key or get from settings
            if direct_key is None:
                key = get_encryption_key()
                from app.core.config.settings import get_settings as get_app_settings

                settings = get_app_settings()
                prev_key = getattr(settings, "PHI_ENCRYPTION_PREVIOUS_KEY", None)
            else:
                key = direct_key
                prev_key = previous_key

            encryption_service_instance = BaseEncryptionService(
                secret_key=key,
                salt=prev_key,
                direct_key=direct_key,
                previous_key=prev_key,
            )
            logger.info(
                "Successfully created global encryption_service_instance using get_encryption_service."
            )

        return encryption_service_instance
    except Exception as e:
        logger.error(f"Error creating encryption service: {e!s}")
        # Fallback to a default instance for testing
        from app.infrastructure.security.encryption.base_encryption_service import (
            BaseEncryptionService,
        )

        return BaseEncryptionService(
            secret_key=DEFAULT_TEST_KEY,
            direct_key=direct_key,
            previous_key=previous_key,
        )


# Import main components at the end to avoid circular imports
from app.infrastructure.security.encryption.base_encryption_service import (
    KDF_ITERATIONS,
    VERSION_PREFIX,
    BaseEncryptionService,
)

# Field-level encryption utilities - after base class is imported
from app.infrastructure.security.encryption.field_encryptor import FieldEncryptor
from app.infrastructure.security.encryption.ml_encryption_service import (
    MLEncryptionService,
    get_ml_encryption_service,
)


# PHI specific encryption functions
def encrypt_phi(data: dict[str, Any] | str) -> dict[str, Any] | str:
    """Encrypt PHI data with HIPAA-compliant encryption.

    Args:
        data: The data to encrypt (dictionary or string)

    Returns:
        Encrypted data in the same format as input
    """
    if isinstance(data, dict):
        # Create a BaseEncryptionService instance for encrypting the dictionary
        encryption_service = BaseEncryptionService(secret_key=get_encryption_key())
        return encryption_service.encrypt_dict(data)
    else:
        # For simple string values, use the encrypt_value function
        return encrypt_value(str(data))


def decrypt_phi(encrypted_data: dict[str, Any] | str) -> dict[str, Any] | str:
    """Decrypt PHI data that was encrypted with encrypt_phi.

    Args:
        encrypted_data: The encrypted data to decrypt

    Returns:
        Decrypted data in the same format as input
    """
    if isinstance(encrypted_data, dict):
        # Create a BaseEncryptionService instance for decrypting the dictionary
        encryption_service = BaseEncryptionService(secret_key=get_encryption_key())
        return encryption_service.decrypt_dict(encrypted_data)
    else:
        # For simple string values, use the decrypt_value function
        return decrypt_value(encrypted_data)


def encrypt_field(value: str) -> str:
    """Encrypt a single field with HIPAA-compliant encryption.

    Args:
        value: The value to encrypt

    Returns:
        Encrypted value as string
    """
    return encrypt_value(value)


def decrypt_field(encrypted_value: str) -> str:
    """Decrypt a field that was encrypted with encrypt_field.

    Args:
        encrypted_value: The encrypted value to decrypt

    Returns:
        Decrypted value
    """
    return decrypt_value(encrypted_value)


def generate_phi_key() -> str:
    """Generate a cryptographically secure key for PHI encryption.

    Returns:
        A base64-encoded 32-byte key suitable for Fernet encryption
    """
    key = base64.urlsafe_b64encode(os.urandom(32)).decode()
    return key


def create_encryption_service(
    secret_key: str | None = None, salt: str | None = None
) -> BaseEncryptionService:
    """
    Create a new instance of the encryption service.

    Args:
        secret_key: Optional encryption key
        salt: Optional salt for key derivation

    Returns:
        BaseEncryptionService: New encryption service instance
    """
    # Get key if not provided
    if secret_key is None:
        secret_key = get_default_encryption_key()

    # Create the service
    return BaseEncryptionService(secret_key=secret_key, salt=salt)


# Import ML encryption service after all helper functions are defined
# This prevents circular imports


def create_ml_encryption_service(
    secret_key: str | None = None, salt: str | None = None
) -> MLEncryptionService:
    """
    Create a new instance of the ML encryption service.

    Args:
        secret_key: Optional encryption key
        salt: Optional salt for key derivation

    Returns:
        MLEncryptionService: New ML encryption service instance
    """
    # Get key if not provided
    if secret_key is None:
        secret_key = get_default_encryption_key()

    # Create the service
    return MLEncryptionService(secret_key=secret_key, salt=salt)


# Set default exports to maintain clean imports across the codebase
__all__ = [
    "BaseEncryptionService",
    "FieldEncryptor",
    "MLEncryptionService",
    "create_encryption_service",
    "create_ml_encryption_service",
    "decrypt_field",
    "decrypt_phi",
    "decrypt_value",
    "encrypt_field",
    "encrypt_phi",
    "encrypt_value",
    "encryption_service_instance",
    "generate_phi_key",
    "get_encryption_key",
    "get_encryption_service",
    "get_settings",
]

# Potentially import from encryption_service if needed elsewhere
# from app.infrastructure.security.encryption.encryption_service import EncryptionService
# from app.infrastructure.security.encryption.encryption import (
#     EncryptionHandler,
#     KeyRotationManager,
#     AESEncryption
# )
