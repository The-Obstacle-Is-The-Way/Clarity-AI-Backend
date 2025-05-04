"""
SQLAlchemy TypeDecorator for JSON-serialized dictionaries.

This module provides a TypeDecorator that handles encoding and decoding of
dictionaries as JSON data, with cross-database compatibility.
"""

import json

from sqlalchemy import types


class JSONEncodedDict(types.TypeDecorator):
    """
    Represents a dictionary as a JSON-encoded string.
    
    Provides proper JSON serialization/deserialization of dictionaries for 
    storage in a database, with cross-database compatibility.
    """
    
    impl = types.JSON
    cache_ok = True

    def process_bind_param(self, value, dialect):
        """Convert Python dictionary to a JSON string before storing."""
        if value is None:
            return None
        return json.dumps(value)

    def process_result_value(self, value, dialect):
        """Convert JSON string to Python dictionary when retrieving from DB."""
        if value is None:
            return None
        if isinstance(value, dict):
            # Already a dictionary (SQLAlchemy may have already deserialized it)
            return value
        return json.loads(value)
    
    def coerce_compared_value(self, op, value):
        """Properly handle operators with JSON values."""
        if isinstance(value, dict):
            # For dict literals, use a JSON type
            return self.impl
        return super().coerce_compared_value(op, value)
