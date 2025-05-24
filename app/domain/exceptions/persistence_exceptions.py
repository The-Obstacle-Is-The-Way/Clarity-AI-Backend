"""
Exception classes related to persistence operations.

This module defines exceptions raised during database and repository operations.
"""

from app.domain.exceptions.base_exceptions import BaseApplicationError


class PersistenceError(BaseApplicationError):
    """Base class for persistence-related exceptions."""

    def __init__(
        self,
        message: str = "Persistence operation failed",
        original_exception: Exception | None = None,
        *args,
        **kwargs,
    ):
        super().__init__(message, *args, **kwargs)
        self.original_exception = original_exception


class EntityNotFoundError(PersistenceError):
    """Raised when an entity cannot be found in the persistence layer."""

    def __init__(
        self,
        entity_type: str | None = None,
        entity_id: str | None = None,
        message: str | None = None,
        *args,
        **kwargs,
    ):
        if message is None:
            if entity_type and entity_id:
                message = f"{entity_type} with ID {entity_id} not found"
            elif entity_type:
                message = f"{entity_type} not found"
            else:
                message = "Entity not found"
        super().__init__(message, *args, **kwargs)
        self.entity_type = entity_type
        self.entity_id = entity_id


class RepositoryError(PersistenceError):
    """Raised when a repository operation fails."""

    def __init__(
        self,
        message: str = "Repository operation failed",
        repository: str | None = None,
        operation: str | None = None,
        *args,
        **kwargs,
    ):
        if repository and operation:
            message = f"{message} in {repository} during {operation}"
        elif repository:
            message = f"{message} in {repository}"
        super().__init__(message, *args, **kwargs)
        self.repository = repository
        self.operation = operation


class DataIntegrityError(PersistenceError):
    """Error raised when a data integrity constraint is violated."""

    def __init__(self, message: str = "Data integrity constraint violated"):
        super().__init__(message)
        self.message = message


class ConnectionError(PersistenceError):
    """Error raised when a database connection fails."""

    def __init__(self, message: str = "Database connection failed"):
        super().__init__(message)
        self.message = message


class TransactionError(PersistenceError):
    """Error raised when a transaction operation fails."""

    def __init__(self, message: str = "Transaction operation failed"):
        super().__init__(message)
        self.message = message


class MigrationError(PersistenceError):
    """Error raised when a database migration fails."""

    def __init__(self, message: str = "Database migration failed"):
        super().__init__(message)
        self.message = message


class QueryError(PersistenceError):
    """Error raised when a database query fails."""

    def __init__(self, message: str = "Database query failed"):
        super().__init__(message)
        self.message = message


class SerializationError(PersistenceError):
    """Error raised when entity serialization or deserialization fails."""

    def __init__(self, message: str = "Entity serialization or deserialization failed"):
        super().__init__(message)
        self.message = message
