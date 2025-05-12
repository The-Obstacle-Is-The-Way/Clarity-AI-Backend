"""
Exception classes for persistence-related errors.

This module defines exceptions that can be raised by the persistence layer.
"""

from app.domain.exceptions.base_exceptions import BaseApplicationError

class PersistenceError(BaseApplicationError):
    """Base class for persistence-related errors."""
    def __init__(self, message: str = "Persistence operation failed"):
        super().__init__(message)
        self.message = message

class RepositoryError(PersistenceError):
    """Error raised when a repository operation fails."""
    def __init__(self, message: str = "Repository operation failed"):
        super().__init__(message)
        self.message = message

class EntityNotFoundError(PersistenceError):
    """Error raised when an entity is not found in a repository."""
    def __init__(self, entity_type: str, entity_id: str):
        message = f"{entity_type} with ID {entity_id} not found"
        super().__init__(message)
        self.entity_type = entity_type
        self.entity_id = entity_id

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