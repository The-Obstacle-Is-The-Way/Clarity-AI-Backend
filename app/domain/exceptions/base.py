"""
Base domain exceptions.

This module defines the base exception class for all domain exceptions.
"""


class DomainException(Exception):
    """Base exception for all domain-specific exceptions."""

    def __init__(self, message: str = "A domain error occurred"):
        """
        Initialize the domain exception.

        Args:
            message: The error message
        """
        self.message = message
        super().__init__(message)

    def __str__(self) -> str:
        """Return a string representation of the exception."""
        return self.message
