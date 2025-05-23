"""Base SQLAlchemy models module.

This module defines the CANONICAL declarative base class (Base)
used for all ORM models in this application.

It also provides common mixins.
"""

import logging
import uuid

from sqlalchemy import UUID as SQLAlchemyUUID
from sqlalchemy import Column, DateTime
from sqlalchemy.ext.asyncio import AsyncAttrs
from sqlalchemy.sql import func

# Import the canonical registry
from app.infrastructure.persistence.sqlalchemy.registry import mapper_registry

# Configure logging
logger = logging.getLogger(__name__)

# Generate the canonical Base class using the central registry
Base = mapper_registry.generate_base(cls=AsyncAttrs)


class TimestampMixin:
    """Mixin for timestamp fields using Column syntax."""
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class AuditMixin:
    """Mixin for audit trail fields using Column syntax."""
    # Add audit_id column for HIPAA compliance
    audit_id = Column(SQLAlchemyUUID(as_uuid=True), default=uuid.uuid4, nullable=True)
    created_by = Column(SQLAlchemyUUID(as_uuid=True), nullable=True)
    updated_by = Column(SQLAlchemyUUID(as_uuid=True), nullable=True)


__all__ = [
    "AuditMixin",
    "Base",
    "TimestampMixin",
]

logger.info("Canonical SQLAlchemy Base and core mixins configured.")
