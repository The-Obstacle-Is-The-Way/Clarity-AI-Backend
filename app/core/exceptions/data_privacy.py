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
        detail: dict[str, Any] | None = None,
        *args: Any,
        **kwargs: Any
    ) -> None:
        """
        Initialize a DataPrivacyError exception.

        Args:
            message: Human-readable message describing the privacy violation
            detail: Optional dictionary with additional context about the violation
            *args: Additional positional arguments for extensibility
            **kwargs: Additional keyword arguments for extensibility
        """
        super().__init__(message, detail, *args, **kwargs)
        self.code = "PHI_DETECTED"
        self.status_code = 400  # Bad Request
