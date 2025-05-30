"""
Role enumeration for the Novamind Digital Twin Backend.

This module defines the role types used for authentication and
authorization throughout the application.
"""

from enum import Enum


class Role(str, Enum):
    """
    User roles for authorization and access control.

    Using string enum allows for serialization in JWT tokens and
    human-readable log entries for audit trails.
    """

    ADMIN = "ADMIN"
    CLINICIAN = "CLINICIAN"
    DOCTOR = "DOCTOR"
    NURSE = "NURSE"
    RESEARCHER = "RESEARCHER"
    PATIENT = "PATIENT"
    USER = "USER"
    PROVIDER = "PROVIDER"  # Added for test compatibility

    def __str__(self) -> str:
        """String representation of the role."""
        return self.value
