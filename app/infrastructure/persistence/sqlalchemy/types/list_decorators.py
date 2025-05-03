"""
SQLAlchemy TypeDecorators for lists of primitive types.

This module provides TypeDecorators for handling lists of strings and floats
with cross-database compatibility. These types ensure consistent handling
between PostgreSQL (using native ARRAY type) and SQLite (using JSON serialization).
"""

import json
from typing import List, Optional, Type, Any, Union
from sqlalchemy import types
from sqlalchemy.dialects import postgresql


class BaseListDecorator(types.TypeDecorator):
    """
    Base class for list type decorators with cross-database compatibility.
    
    This abstract base class provides the foundation for implementing
    list type decorators that work across different database backends.
    """
    
    cache_ok = True
    
    def __init__(self, item_type: Optional[Type] = None, *args, **kwargs):
        """Initialize with optional item type for validation."""
        super().__init__(*args, **kwargs)
        self.item_type = item_type
    
    def load_dialect_impl(self, dialect):
        """Load the appropriate dialect implementation."""
        if dialect.name == 'postgresql':
            # Use native PostgreSQL ARRAY type
            return dialect.type_descriptor(self.pg_array_type)
        else:
            # Fall back to JSON for other databases like SQLite
            return dialect.type_descriptor(types.JSON)
    
    def process_bind_param(self, value: Optional[List], dialect) -> Optional[Union[List, str]]:
        """Convert the value for storage in the database."""
        if value is None:
            return None
            
        # Validate item types if specified
        if self.item_type and any(not isinstance(item, self.item_type) for item in value):
            raise ValueError(f"All items must be of type {self.item_type.__name__}")
            
        if dialect.name == 'postgresql':
            # PostgreSQL handles arrays natively
            return value
        else:
            # For other dialects like SQLite, serialize to JSON
            return json.dumps(value)
    
    def process_result_value(self, value: Any, dialect) -> Optional[List]:
        """Convert the value retrieved from the database."""
        if value is None:
            return None
            
        if dialect.name == 'postgresql':
            # PostgreSQL returns native arrays
            return list(value)
        else:
            # For other dialects, deserialize from JSON
            if isinstance(value, str):
                return json.loads(value)
            return value


class StringListDecorator(BaseListDecorator):
    """
    TypeDecorator for lists of strings.
    
    Provides cross-database compatibility for string lists between
    PostgreSQL ARRAY(String) and JSON-serialized lists in SQLite.
    """
    
    pg_array_type = postgresql.ARRAY(types.String)
    
    def __init__(self, *args, **kwargs):
        """Initialize with string as the item type."""
        super().__init__(item_type=str, *args, **kwargs)


class FloatListDecorator(BaseListDecorator):
    """
    TypeDecorator for lists of floats.
    
    Provides cross-database compatibility for float lists between
    PostgreSQL ARRAY(Float) and JSON-serialized lists in SQLite.
    """
    
    pg_array_type = postgresql.ARRAY(types.Float)
    
    def __init__(self, *args, **kwargs):
        """Initialize with float as the item type."""
        super().__init__(item_type=float, *args, **kwargs)
