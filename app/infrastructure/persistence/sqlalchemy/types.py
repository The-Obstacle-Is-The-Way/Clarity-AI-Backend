import json
import uuid
from typing import Any, Optional

from sqlalchemy import Float as sa_Float
from sqlalchemy import String, Text, TypeDecorator
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID


class JSONEncodedDict(TypeDecorator):
    """Represents an immutable structure as a json-encoded string.

    Usage: Column(JSONEncodedDict)

    Provides transparent JSON serialization/deserialization for dictionary
    types, storing them as TEXT in SQLite and JSONB in PostgreSQL.
    """

    impl = Text  # Default implementation for SQLite
    cache_ok = True

    def load_dialect_impl(self, dialect):
        """Load dialect-specific implementation."""
        if dialect.name == 'postgresql':
            # Use JSONB for PostgreSQL
            return dialect.type_descriptor(JSONB())
        else:
            # Use Text for other dialects (like SQLite)
            return dialect.type_descriptor(Text())

    def process_bind_param(self, value: dict | None, dialect) -> str | None:
        """Serialize Python dict to JSON string before saving."""
        if dialect.name == 'postgresql':
            # PostgreSQL handles JSONB directly
            return value
        if value is not None:
            return json.dumps(value)
        return None

    def process_result_value(self, value: str | None, dialect) -> dict | None:
        """Deserialize JSON string to Python dict after loading."""
        if dialect.name == 'postgresql':
            # PostgreSQL returns dict directly from JSONB
            return value
        if value is not None:
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                # Handle cases where the stored text is not valid JSON
                # Log error or return default
                return None 
        return None


class StringListDecorator(TypeDecorator):
    """Represents a list of strings, stored as JSON TEXT in SQLite
    and ARRAY(String) in PostgreSQL.
    """
    impl = Text # Default for SQLite
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == 'postgresql':
            return dialect.type_descriptor(ARRAY(Text))
        else:
            return dialect.type_descriptor(Text())

    def process_bind_param(self, value: list[str] | None, dialect) -> str | None:
        if dialect.name == 'postgresql':
            # PostgreSQL handles ARRAY directly
            return value 
        if value is not None:
            # Serialize list to JSON string for SQLite
            return json.dumps(value)
        return None

    def process_result_value(self, value: str | None, dialect) -> list[str] | None:
        if dialect.name == 'postgresql':
            # PostgreSQL returns list directly from ARRAY
            return value 
        if value is not None:
            try:
                # Deserialize JSON string to list for SQLite
                result = json.loads(value)
                if isinstance(result, list):
                    return result
                return None # Or raise error if format is unexpected
            except json.JSONDecodeError:
                # Log error or return default
                return None 
        return None


class FloatListDecorator(TypeDecorator):
    """Represents a list of floats, stored as JSON TEXT in SQLite
    and ARRAY(Float) in PostgreSQL.
    """
    impl = Text # Default for SQLite
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == 'postgresql':
            # Use native ARRAY(Float) for PostgreSQL
            return dialect.type_descriptor(ARRAY(sa_Float))
        else:
            # Use TEXT for SQLite
            return dialect.type_descriptor(Text())

    def process_bind_param(self, value: list[float] | None, dialect) -> str | None:
        if dialect.name == 'postgresql':
            # PostgreSQL handles ARRAY(Float) directly
            return value
        if value is not None:
            # Serialize list of floats to JSON string for SQLite
            return json.dumps(value)
        return None

    def process_result_value(self, value: str | None, dialect) -> list[float] | None:
        if dialect.name == 'postgresql':
            # PostgreSQL returns list directly from ARRAY(Float)
            return value
        if value is not None:
            try:
                # Deserialize JSON string to list of floats for SQLite
                result = json.loads(value)
                if isinstance(result, list) and all(isinstance(item, (int, float)) for item in result):
                    # Convert ints to floats if mixed, though ideally source is float
                    return [float(item) for item in result] 
                return None # Or raise error
            except json.JSONDecodeError:
                 # Log error or return default
                return None
        return None


# Export the custom types
__all__ = ['JSONEncodedDict', 'StringListDecorator', 'FloatListDecorator']
