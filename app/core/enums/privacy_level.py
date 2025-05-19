"""
Core domain enums for privacy and HIPAA compliance levels.

This module defines standardized privacy level classifications used across the system.
Following clean architecture principles, these enums exist in the core domain layer
to ensure consistent HIPAA compliance and data privacy enforcement.
"""
from enum import Enum


class PrivacyLevel(Enum):
    """
    Enumeration of privacy protection levels for data handling.

    These levels determine how strictly the system enforces PHI detection
    and data sanitization in accordance with HIPAA regulations.
    """

    # Maximum privacy protection - any potential PHI raises exceptions
    STRICT = "strict"

    # Standard HIPAA compliance level - known PHI patterns are blocked
    HIPAA_COMPLIANT = "hipaa_compliant"

    # Moderate protection - warnings for potential PHI but allows operation
    MODERATE = "moderate"

    # Minimal protection - logs warnings only, for development environments
    MINIMAL = "minimal"

    # No privacy protection - for non-production test environments only
    NONE = "none"

    def __str__(self) -> str:
        """String representation of the privacy level."""
        return self.value

    @property
    def is_production_safe(self) -> bool:
        """
        Indicates if this privacy level is suitable for production environments.

        Returns:
            bool: True if the level is suitable for production use with real PHI
        """
        return self in (PrivacyLevel.STRICT, PrivacyLevel.HIPAA_COMPLIANT)

    @property
    def allows_phi_exceptions(self) -> bool:
        """
        Indicates if this level should raise exceptions when PHI is detected.

        Returns:
            bool: True if PHI detection should raise exceptions
        """
        return self in (PrivacyLevel.STRICT, PrivacyLevel.HIPAA_COMPLIANT)
