"""
SQLAlchemy TypeDecorators for lists of primitive types.

This module provides TypeDecorators for handling lists of strings and floats
with cross-database compatibility. These types ensure consistent handling
between PostgreSQL (using native ARRAY type) and SQLite (using JSON serialization).
"""

import json
from collections.abc import Sequence

from sqlalchemy import types
from sqlalchemy.dialects.postgresql import ARRAY


class StringListDecorator(types.TypeDecorator):
    """
    SQLAlchemy type decorator for string lists.

    Uses PostgreSQL's native ARRAY type when available,
    otherwise serializes as a JSON array in a TEXT column.
    """

    impl = types.Text
    cache_ok = True

    def load_dialect_impl(self, dialect):
        """
        Use PostgreSQL's native ARRAY type when available,
        otherwise use TEXT for string-based storage.

        Args:
            dialect: SQLAlchemy dialect

        Returns:
            Dialect-specific implementation
        """
        if dialect.name == "postgresql":
            return dialect.type_descriptor(ARRAY(types.String))
        else:
            return dialect.type_descriptor(types.Text)

    def process_bind_param(self, value, dialect):
        """
        Process the value before binding to SQL statement.

        Args:
            value: List of strings or None
            dialect: SQLAlchemy dialect

        Returns:
            Processed value for the specific dialect
        """
        if value is None:
            return None

        # Ensure we have a list
        if not isinstance(value, list | tuple):
            raise ValueError(f"Expected list or tuple, got {type(value)}: {value}")

        # For PostgreSQL, return the list directly
        if dialect.name == "postgresql":
            return value

        # For other dialects (like SQLite), serialize to JSON
        return json.dumps(value)

    def process_result_value(self, value, dialect):
        """
        Process the database value before returning it to Python.

        Args:
            value: Value from database
            dialect: SQLAlchemy dialect

        Returns:
            List of strings
        """
        if value is None:
            return []

        # For PostgreSQL, the value is already a list
        if dialect.name == "postgresql":
            return value if isinstance(value, list) else list(value)

        # For other dialects, deserialize from JSON
        try:
            result = json.loads(value)
            if not isinstance(result, list):
                return [str(result)]
            return [str(item) for item in result]
        except (json.JSONDecodeError, TypeError):
            # Fallback for invalid JSON
            return []


class FloatListDecorator(types.TypeDecorator):
    """
    SQLAlchemy type decorator for float lists.

    Uses PostgreSQL's native ARRAY type when available,
    otherwise serializes as a JSON array in a TEXT column.
    """

    impl = types.Text
    cache_ok = True

    def load_dialect_impl(self, dialect):
        """
        Use PostgreSQL's native ARRAY type when available,
        otherwise use TEXT for string-based storage.

        Args:
            dialect: SQLAlchemy dialect

        Returns:
            Dialect-specific implementation
        """
        if dialect.name == "postgresql":
            return dialect.type_descriptor(ARRAY(types.Float))
        else:
            return dialect.type_descriptor(types.Text)

    def process_bind_param(self, value, dialect):
        """
        Process the value before binding to SQL statement.

        Args:
            value: List of floats or None
            dialect: SQLAlchemy dialect

        Returns:
            Processed value for the specific dialect
        """
        if value is None:
            return None

        # Ensure we have a list or sequence
        if not isinstance(value, list | tuple | Sequence):
            raise ValueError(f"Expected list, tuple or sequence, got {type(value)}: {value}")

        # For PostgreSQL, return the list directly
        if dialect.name == "postgresql":
            return value

        # For other dialects (like SQLite), serialize to JSON
        return json.dumps(value)

    def process_result_value(self, value, dialect):
        """
        Process the database value before returning it to Python.

        Args:
            value: Value from database
            dialect: SQLAlchemy dialect

        Returns:
            List of floats
        """
        if value is None:
            return []

        # For PostgreSQL, the value is already a list
        if dialect.name == "postgresql":
            return value if isinstance(value, list) else list(value)

        # For other dialects, deserialize from JSON
        try:
            result = json.loads(value)
            if not isinstance(result, list):
                return [float(result)]
            return [float(item) for item in result]
        except (json.JSONDecodeError, TypeError, ValueError):
            # Fallback for invalid JSON or float conversion errors
            return []
