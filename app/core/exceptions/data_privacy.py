"""
Data privacy and PHI-related exceptions.

Contains specialized exceptions for handling privacy violations and PHI detection.
"""
from typing import Any

from app.core.exceptions.base_exceptions import BaseException


class DataPrivacyError(BaseException):
    """
    Exception raised when potential PHI (Protected Health Information) is detected.

    This exception ensures HIPAA compliance by preventing accidental processing or
    storage of Protected Health Information in inappropriate contexts.
    """

    def __init__(
        self,
        message: str = "Protected Health Information (PHI) detected in request data",
        details: dict[str, Any] | None = None,
    ):
        """
        Initialize a DataPrivacyError exception.

        Args:
            message: Human-readable message describing the privacy violation
            details: Optional dictionary with additional context about the violation
        """
        super().__init__(message=message, details=details)
        self.code = "PHI_DETECTED"
        self.status_code = 400  # Bad Request
