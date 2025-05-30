"""Base SQLAlchemy models module.

This module defines the CANONICAL declarative base class (Base)
used for all ORM models in this application.

It also provides common mixins.
"""

from __future__ import annotations

import logging
import uuid
from typing import TYPE_CHECKING

from sqlalchemy import UUID as SQLAlchemyUUID
from sqlalchemy import Column

# Import the proper type-safe Base from config
from app.infrastructure.persistence.sqlalchemy.config.base import (
    Base,
    BaseSQLModel,
)
from app.infrastructure.persistence.sqlalchemy.config.base import (
    TimestampMixin as ConfigTimestampMixin,
)

if TYPE_CHECKING:
    from sqlalchemy.orm import Mapped

# Configure logging
logger = logging.getLogger(__name__)

# Re-export the type-safe Base for backward compatibility
__all__ = [
    "AuditMixin",
    "Base",
    "BaseSQLModel",
    "TimestampMixin",
]


class TimestampMixin(ConfigTimestampMixin):
    """Mixin for timestamp fields using Column syntax.

    Inherits from the config TimestampMixin for consistency.
    Follows SOLID principles by extending the base functionality.
    """

    pass


class AuditMixin:
    """Mixin for audit trail fields using Column syntax.

    Provides HIPAA-compliant audit tracking for all models.
    Follows Single Responsibility Principle - handles only audit concerns.
    """

    if TYPE_CHECKING:
        audit_id: Mapped[uuid.UUID | None]
        created_by: Mapped[uuid.UUID | None]
        updated_by: Mapped[uuid.UUID | None]
    else:
        # Add audit_id column for HIPAA compliance
        audit_id = Column(SQLAlchemyUUID(as_uuid=True), default=uuid.uuid4, nullable=True)
        created_by = Column(SQLAlchemyUUID(as_uuid=True), nullable=True)
        updated_by = Column(SQLAlchemyUUID(as_uuid=True), nullable=True)


logger.info("Canonical SQLAlchemy Base and core mixins configured with type safety.")
