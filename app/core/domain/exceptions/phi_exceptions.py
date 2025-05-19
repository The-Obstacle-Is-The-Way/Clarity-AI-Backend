"""
PHI (Protected Health Information) Exception Hierarchy.

This module defines domain exceptions related to PHI handling for HIPAA compliance.
These exceptions are part of the core domain layer and define the business rules
for protecting sensitive health information as required by HIPAA.
"""


class PHIException(Exception):
    """
    Base exception for all PHI-related errors.

    All exceptions related to PHI handling should inherit from this class
    to enable proper error handling and auditing for HIPAA compliance.
    """

    def __init__(self, message: str = "PHI operation error"):
        self.message = message
        super().__init__(self.message)


class PHIInUrlError(PHIException):
    """
    Exception raised when PHI is detected in a URL.

    HIPAA compliance requires that no PHI ever appears in URLs, as they may
    be logged, cached, or otherwise exposed. This exception indicates that
    PHI was detected in a URL path or query parameter.
    """

    def __init__(self, message: str = "Protected health information detected in URL"):
        super().__init__(message)


class PHISanitizationError(PHIException):
    """
    Exception raised when PHI sanitization fails.

    This exception indicates an error occurred while attempting to sanitize
    PHI from response data, potentially leading to PHI disclosure risks.
    """

    def __init__(self, message: str = "Failed to sanitize PHI from response"):
        super().__init__(message)


class PHIEncryptionError(PHIException):
    """
    Exception raised when PHI encryption operations fail.

    HIPAA requires encryption of PHI at rest and in transit. This exception
    indicates failure in encryption operations, potentially exposing PHI.
    """

    def __init__(self, message: str = "Failed to encrypt PHI"):
        super().__init__(message)


class PHIAccessViolationError(PHIException):
    """
    Exception raised when unauthorized access to PHI is attempted.

    HIPAA requires strict access controls for PHI. This exception indicates
    an unauthorized access attempt was detected and blocked.
    """

    def __init__(self, message: str = "Unauthorized access to PHI"):
        super().__init__(message)


class PHIAuditFailureError(PHIException):
    """
    Exception raised when PHI audit logging fails.

    HIPAA requires comprehensive audit logging of all PHI access. This exception
    indicates a failure in the audit logging system, which is a compliance risk.
    """

    def __init__(self, message: str = "Failed to log PHI access for audit"):
        super().__init__(message)
