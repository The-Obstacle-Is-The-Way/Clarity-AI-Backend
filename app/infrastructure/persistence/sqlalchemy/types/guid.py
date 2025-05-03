"""
Cross-database compatible GUID/UUID SQLAlchemy type.

This module provides a SQLAlchemy type for handling UUIDs in a way
that works across different database backends, specifically PostgreSQL
and SQLite.
"""

import uuid
from sqlalchemy import types
from sqlalchemy.dialects.postgresql import UUID as PostgresUUID


class GUID(types.TypeDecorator):
    """
    Platform-independent GUID type.
    
    Uses PostgreSQL's UUID type when available, otherwise 
    uses a CHAR(36), storing as a stringified UUID.
    """
    
    impl = types.CHAR
    cache_ok = True
    
    def load_dialect_impl(self, dialect):
        """
        Use PostgreSQL's native UUID type when available, 
        otherwise use CHAR(36) for string-based storage.
        
        Args:
            dialect: SQLAlchemy dialect
            
        Returns:
            Dialect-specific implementation
        """
        if dialect.name == 'postgresql':
            return dialect.type_descriptor(PostgresUUID())
        else:
            return dialect.type_descriptor(types.CHAR(36))
    
    def process_bind_param(self, value, dialect):
        """
        Process the value before binding to SQL statement.
        
        Args:
            value: UUID value or string
            dialect: SQLAlchemy dialect
            
        Returns:
            Processed value appropriate for the dialect
        """
        if value is None:
            return value
        
        if dialect.name == 'postgresql':
            return str(value) if isinstance(value, uuid.UUID) else value
        else:
            if not isinstance(value, uuid.UUID):
                try:
                    value = uuid.UUID(value)
                except (TypeError, ValueError):
                    raise ValueError(f"Invalid UUID: {value}")
            return str(value)
    
    def process_result_value(self, value, dialect):
        """
        Process the database value before returning it to Python.
        
        Args:
            value: Value from database
            dialect: SQLAlchemy dialect
            
        Returns:
            Python UUID object
        """
        if value is None:
            return value
        
        if not isinstance(value, uuid.UUID):
            try:
                value = uuid.UUID(value)
            except (TypeError, ValueError):
                raise ValueError(f"Invalid UUID: {value}")
        return value
