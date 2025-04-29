# -*- coding: utf-8 -*-
"""
Base SQLAlchemy declarative base for all models.

This module provides a single source of truth for the SQLAlchemy declarative base
used by all model classes in the application. This pattern eliminates registry conflicts
by ensuring all models use the same metadata instance and registry.

Following clean architecture principles, this serves as the foundation for all
SQLAlchemy models, creating a consistent database schema and behavior across
the entire application.

ARCHITECTURAL NOTE: This is the ONLY Base class that should be used across the entire
application. All other Base definitions should be removed or replaced with imports
from this module.
"""

import uuid
from typing import Any, Dict, Optional
from datetime import datetime

from sqlalchemy import Column, DateTime, MetaData, Integer, String, func, text
from sqlalchemy.ext.asyncio import AsyncAttrs
from sqlalchemy.orm import registry, declarative_base

# Create a shared registry that will be used across all models
# This eliminates the multiple registry problem during testing
_registry = registry()

# Create a shared metadata instance
_metadata = MetaData()

# Create a single declarative base with AsyncAttrs support for async operations
# All models should inherit from this Base class
Base = declarative_base(metadata=_metadata, cls=AsyncAttrs)


class TimestampMixin:
    """
    Mixin to add created_at and updated_at timestamps to models.
    
    This mixin provides standard timestamp tracking for database models,
    automatically setting and updating timestamps.
    """
    
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        comment="When this record was created"
    )
    
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
        comment="When this record was last updated"
    )


class AuditMixin:
    """
    Mixin for HIPAA-compliant audit fields.
    
    Adds fields required for proper audit trails in a HIPAA-compliant system.
    """
    created_by = Column(
        String(36),
        nullable=True,
        comment="User ID who created this record"
    )
    
    updated_by = Column(
        String(36),
        nullable=True,
        comment="User ID who last updated this record"
    )
    
    audit_id = Column(
        String(36),
        default=lambda: str(uuid.uuid4()),
        nullable=False,
        comment="Unique ID for audit trail reference"
    )


# Export the Base class and mixins as the public API
__all__ = ['Base', 'TimestampMixin', 'AuditMixin']
