# -*- coding: utf-8 -*-
"""
Cross-database compatible UUID type for SQLAlchemy.

This module provides a GUID type that works across different database dialects,
particularly for handling the PostgreSQL UUID vs SQLite string storage differences.
"""

import uuid
from typing import Any, Optional, Union, cast

from sqlalchemy import String
from sqlalchemy.dialects.postgresql import UUID as PostgresUUID
from sqlalchemy.engine import Dialect
from sqlalchemy.types import TypeDecorator


class GUID(TypeDecorator):
    """
    Platform-independent GUID type.
    
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
        if dialect.name == 'postgresql':
            return dialect.type_descriptor(PostgresUUID(as_uuid=True))
        return dialect.type_descriptor(String(36))
    
    def process_bind_param(self, value: Optional[Union[str, uuid.UUID]], dialect: Dialect) -> Optional[str]:
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
            
        if dialect.name == 'postgresql':
            # PostgreSQL handles UUID objects natively
            return value
            
        # Convert UUID objects to strings for other databases
        if isinstance(value, uuid.UUID):
            return str(value)
        return value
    
    def process_result_value(self, value: Any, dialect: Dialect) -> Optional[uuid.UUID]:
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
        return uuid.UUID(value)