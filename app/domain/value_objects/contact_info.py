# app/domain/value_objects/contact_info.py
"""
Contact information value object with HIPAA-compliant PHI protection.

This module provides a secure implementation of patient contact information
that ensures PHI is properly protected according to HIPAA requirements.
"""

import json
import logging
import re
from dataclasses import dataclass
from typing import Any, ClassVar, Dict, Optional

from app.core.config.settings import get_settings
from app.infrastructure.security.encryption.base_encryption_service import (
    BaseEncryptionService,
    get_encryption_service,
)

# Configure logger with no PHI exposure
logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ContactInfo:
    """
    Value object for patient contact information with HIPAA-compliant PHI protection.

    This class ensures proper validation, sanitation, and protection of PHI data,
    implementing field-level encryption for sensitive information.

    Notes:
        - This implements a value object pattern with immutability (frozen=True)
        - All fields are properly validated during initialization
        - No PHI is exposed in error messages or exceptions
        - Supports encrypted serialization for database storage
    """

    # Public attributes
    email: Optional[str] = None
    phone: Optional[str] = None
    preferred_contact_method: Optional[str] = None

    # Class constants for validation
    EMAIL_PATTERN: ClassVar[str] = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    VALID_CONTACT_METHODS: ClassVar[set] = {"email", "phone", "none"}

    # Class-level encryption service cache
    _encryption_service: ClassVar[Optional[BaseEncryptionService]] = None

    # Private attribute for encryption state
    _is_encrypted: bool = False

    def __post_init__(self) -> None:
        """
        Validate contact information.

        Performs input validation and sanitization without exposing PHI in error messages.
        """
        # Since this is a frozen dataclass, we need to use object.__setattr__ for _is_encrypted
        object.__setattr__(self, "_is_encrypted", self._detect_encryption_state())

        # Skip validation if fields are already encrypted
        if self._is_encrypted:
            return

        self._validate_email(self.email)
        self._validate_phone(self.phone)
        self._validate_preferred_contact_method(self.preferred_contact_method)

    def _detect_encryption_state(self) -> bool:
        """
        Detect if the fields are already encrypted.

        Returns:
            bool: True if fields appear to be encrypted, False otherwise
        """
        # Check if any field has the encryption version prefix
        # Use the BaseEncryptionService version prefix constant
        encryption_svc = self._get_encryption_service()
        prefix = encryption_svc.VERSION_PREFIX if encryption_svc else "v1:"

        # Check relevant fields
        if self.email and isinstance(self.email, str) and self.email.startswith(prefix):
            return True
        if self.phone and isinstance(self.phone, str) and self.phone.startswith(prefix):
            return True

        return False

    @staticmethod
    def _validate_email(email: Optional[str]) -> None:
        """
        Validate email format without exposing the email in error messages.

        Args:
            email: Email address to validate

        Raises:
            ValueError: If email format is invalid (without including the email in the message)
        """
        if email is None:
            return

        # Sanitize error messages to avoid exposing PHI
        if not isinstance(email, str):
            raise ValueError("Email must be a string")

        pattern = re.compile(ContactInfo.EMAIL_PATTERN)
        if not pattern.match(email):
            raise ValueError("Invalid email format")

    @staticmethod
    def _validate_phone(phone: Optional[str]) -> None:
        """
        Validate phone number format without exposing the phone number in error messages.

        Args:
            phone: Phone number to validate

        Raises:
            ValueError: If phone format is invalid (without including the phone in the message)
        """
        if phone is None:
            return

        # Sanitize error messages to avoid exposing PHI
        if not isinstance(phone, str):
            raise ValueError("Phone number must be a string")

        # Remove any non-digit characters for validation
        digits = re.sub(r"\D", "", phone)
        if len(digits) < 10:
            raise ValueError("Phone number must have at least 10 digits")

    @staticmethod
    def _validate_preferred_contact_method(method: Optional[str]) -> None:
        """
        Validate preferred contact method.

        Args:
            method: Preferred contact method

        Raises:
            ValueError: If the method is invalid
        """
        if method is None:
            return

        method_lower = method.lower()
        if method_lower not in ContactInfo.VALID_CONTACT_METHODS:
            valid_methods = ", ".join(
                f"'{m}'" for m in ContactInfo.VALID_CONTACT_METHODS
            )
            raise ValueError(
                f"Preferred contact method must be one of: {valid_methods}"
            )

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "ContactInfo":
        """
        Create a ContactInfo instance from a dictionary.

        Args:
            data: Dictionary containing contact information

        Returns:
            ContactInfo: New instance initialized with the provided data

        Raises:
            ValueError: If validation fails (without exposing PHI in error messages)
        """
        if not data:
            return cls()

        try:
            return cls(
                email=data.get("email"),
                phone=data.get("phone"),
                preferred_contact_method=data.get("preferred_contact_method"),
            )
        except ValueError as e:
            # Log error with type but without PHI
            logger.error(f"ContactInfo validation error: {type(e).__name__}")
            raise ValueError("Invalid contact information format") from e

    def to_dict(self, include_empty: bool = False) -> Dict[str, Any]:
        """
        Convert to dictionary.

        Args:
            include_empty: Whether to include None values in the result

        Returns:
            Dict[str, Any]: Dictionary representation of contact information
        """
        data = {"email": self.email, "phone": self.phone}

        if self.preferred_contact_method:
            data["preferred_contact_method"] = self.preferred_contact_method

        # Filter out None values if requested
        if not include_empty:
            data = {k: v for k, v in data.items() if v is not None}

        return data

    def to_json(self) -> str:
        """
        Convert to JSON string representation.

        Returns:
            str: JSON string representation
        """
        return json.dumps(self.to_dict())

    @classmethod
    def _get_encryption_service(cls) -> BaseEncryptionService:
        """
        Get the encryption service, creating it if needed.

        Returns:
            BaseEncryptionService: The encryption service
        """
        if cls._encryption_service is None:
            cls._encryption_service = get_encryption_service()
        return cls._encryption_service

    def encrypt(self) -> "ContactInfo":
        """
        Create an encrypted version of this ContactInfo.

        Returns:
            ContactInfo: New instance with encrypted fields
        """
        # Skip if already encrypted
        if self._is_encrypted:
            return self

        # Get encryption service
        encryption_service = self._get_encryption_service()

        # Create new instance with encrypted fields
        email_encrypted = encryption_service.encrypt(self.email) if self.email else None
        phone_encrypted = encryption_service.encrypt(self.phone) if self.phone else None

        # Create a new instance with the _is_encrypted flag explicitly set to True
        # This is necessary because dataclass is frozen
        result = ContactInfo(
            email=email_encrypted,
            phone=phone_encrypted,
            preferred_contact_method=self.preferred_contact_method,
        )

        # Set _is_encrypted flag explicitly to ensure it's True even if detection would fail
        object.__setattr__(result, "_is_encrypted", True)

        return result

    def decrypt(self) -> "ContactInfo":
        """
        Create a decrypted version of this ContactInfo.

        Returns:
            ContactInfo: New instance with decrypted fields
        """
        # Skip if not encrypted
        if not self._is_encrypted:
            return self

        try:
            # Get encryption service
            encryption_service = self._get_encryption_service()

            # Create new instance with decrypted fields
            email_decrypted = (
                encryption_service.decrypt(self.email) if self.email else None
            )
            phone_decrypted = (
                encryption_service.decrypt(self.phone) if self.phone else None
            )

            # Create a new instance with the _is_encrypted flag explicitly set to False
            result = ContactInfo(
                email=email_decrypted,
                phone=phone_decrypted,
                preferred_contact_method=self.preferred_contact_method,
            )

            # Explicitly set _is_encrypted to False to ensure consistency
            object.__setattr__(result, "_is_encrypted", False)

            return result
        except Exception as e:
            # Handle decryption errors without exposing PHI
            logger.error(f"Error decrypting ContactInfo: {type(e).__name__}")
            # Return a blank ContactInfo instance rather than exposing partial PHI
            return ContactInfo()

    def has_phi(self) -> bool:
        """
        Check if this ContactInfo contains any PHI.

        Returns:
            bool: True if any PHI fields are populated
        """
        return bool(self.email or self.phone)

    def redact_phi(self) -> Dict[str, Any]:
        """
        Create a redacted version suitable for logging.

        Returns:
            Dict[str, Any]: Dictionary with PHI fields redacted
        """
        data = self.to_dict(include_empty=True)

        # Redact PHI fields
        if self.email:
            data["email"] = "[REDACTED EMAIL]"
        if self.phone:
            data["phone"] = "[REDACTED PHONE]"

        return data


def create_secure_contact_info(
    email: Optional[str] = None,
    phone: Optional[str] = None,
    preferred_method: Optional[str] = None,
) -> ContactInfo:
    """
    Factory function to safely create contact info with validation.

    Args:
        email: Email address
        phone: Phone number
        preferred_method: Preferred contact method

    Returns:
        ContactInfo: Valid contact information

    Raises:
        ValueError: If input validation fails (without exposing PHI)
    """
    try:
        return ContactInfo(
            email=email, phone=phone, preferred_contact_method=preferred_method
        )
    except ValueError as e:
        # Log error without exposing PHI
        logger.error(f"Error creating ContactInfo: {type(e).__name__}")
        raise ValueError("Invalid contact information") from e
