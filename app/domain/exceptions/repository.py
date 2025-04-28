"""
Repository exceptions module.

This module defines exceptions related to repository operations.
"""

from app.domain.exceptions.base import DomainException


class RepositoryException(DomainException):
    """Base exception for repository-related errors."""
    def __init__(self, message: str = "Repository operation failed"):
        super().__init__(message)


class EntityNotFoundException(RepositoryException):
    """Exception raised when an entity is not found."""
    def __init__(self, message: str = "Entity not found"):
        super().__init__(message)


class DuplicateEntityException(RepositoryException):
    """Exception raised when attempting to create a duplicate entity."""
    def __init__(self, message: str = "Entity already exists"):
        super().__init__(message)


class DatabaseConnectionException(RepositoryException):
    """Exception raised when there is a database connection error."""
    def __init__(self, message: str = "Database connection error"):
        super().__init__(message)


class TransactionException(RepositoryException):
    """Exception raised when there is an error in a database transaction."""
    def __init__(self, message: str = "Transaction error"):
        super().__init__(message)


# Alias for backward compatibility
RepositoryError = RepositoryException
