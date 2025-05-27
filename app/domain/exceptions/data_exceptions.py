"""
Exception classes related to data operations.

This module defines exceptions raised when data integrity or availability issues occur.
"""

from typing import Any

from app.domain.exceptions.base_exceptions import BaseApplicationError


class DataIntegrityError(BaseApplicationError):
    """Raised when data fails integrity checks."""

    def __init__(self, message: str = "Data integrity violation", *args: Any, **kwargs: Any) -> None:
        super().__init__(message, *args, **kwargs)


class DataNotFoundError(BaseApplicationError):
    """Raised when requested data cannot be found."""

    def __init__(self, message: str = "Data not found", *args: Any, **kwargs: Any) -> None:
        super().__init__(message, *args, **kwargs)
