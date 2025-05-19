"""
SQLAlchemy custom types package.

This package contains custom type definitions for SQLAlchemy models.
"""

# Imports needed for GUID class
import uuid
from typing import Any

from sqlalchemy import String
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.engine import Dialect
from sqlalchemy.types import TypeDecorator


# --- Canonical GUID Definition ---
class GUID(TypeDecorator):
    """Platform-independent GUID type.

    Uses PostgreSQL's UUID type when available, otherwise uses String(36).

    This implementation ensures compatibility between PostgreSQL in production
    and SQLite in tests, solving the common mapping issues with UUID columns.
    """

    # Default to String(36) for SQLite and other non-PostgreSQL databases
    impl = String(36)
    cache_ok = True

    def load_dialect_impl(self, dialect: Dialect) -> Any:
        """
        Load the appropriate implementation based on the dialect.

        Args:
            dialect: SQLAlchemy dialect

        Returns:
            PostgresUUID for PostgreSQL, String for other databases
        """
        if dialect.name == "postgresql":
            return dialect.type_descriptor(PG_UUID(as_uuid=True))
        return dialect.type_descriptor(String(36))

    def process_bind_param(self, value: str | uuid.UUID | None, dialect: Dialect) -> str | None:
        """
        Process the parameter value before binding to SQL statement.

        Args:
            value: UUID object or string
            dialect: SQLAlchemy dialect

        Returns:
            String representation of UUID for non-PostgreSQL dialects,
            raw UUID for PostgreSQL dialect
        """
        if value is None:
            return None

        if dialect.name == "postgresql":
            # PostgreSQL handles UUID objects natively
            return value

        # Convert UUID objects to strings for other databases
        if isinstance(value, uuid.UUID):
            return str(value)
        return value

    def process_result_value(self, value: Any, dialect: Dialect) -> uuid.UUID | None:
        """
        Process the result value from SQL result set.

        Args:
            value: Value from database
            dialect: SQLAlchemy dialect

        Returns:
            UUID object if the value is not None, None otherwise
        """
        if value is None:
            return None

        # If already a UUID object (from PostgreSQL), return it directly
        if isinstance(value, uuid.UUID):
            return value

        # Convert string to UUID for non-PostgreSQL databases
        try:
            return uuid.UUID(value)
        except (ValueError, TypeError):
            # Handle potential issues if the value isn't a valid UUID string
            return None  # Or log error?

    @property
    def python_type(self):
        return uuid.UUID


# --- End Canonical GUID ---


# Other type imports (relative within this package)
# Import encrypted types (relative)
from .encrypted_types import EncryptedString
from .json_encoded_dict import JSONEncodedDict
from .list_decorators import (
    FloatListDecorator,
    StringListDecorator,
)

# Ensure GUID is included in __all__ along with others
__all__ = [
    "GUID",
    "EncryptedString",
    "FloatListDecorator",
    "JSONEncodedDict",
    "StringListDecorator",
]
