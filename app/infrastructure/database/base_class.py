"""SQLAlchemy Mixin class definitions for the Clarity AI Digital Twin Platform.

This module defines reusable mixin classes for ORM models.

IMPORTANT: Mixins defined here should not have their own Base or registry.
They provide attributes to be mixed into models that use the central
declarative Base from app.infrastructure.persistence.sqlalchemy.models.base.
"""

import logging
import uuid

from sqlalchemy import Column, DateTime, String, func  # Removed MetaData

# Removed: from sqlalchemy.ext.asyncio import AsyncAttrs
from sqlalchemy.ext.declarative import declared_attr  # Keep for @declared_attr

# Removed: from sqlalchemy.orm import registry
from sqlalchemy.sql import func

from app.domain.utils.datetime_utils import now_utc

# Configure logging
logger = logging.getLogger(__name__)

# Removed: metadata = MetaData()
# Removed: mapper_registry = registry(metadata=metadata)
# Removed: Base = declarative_base(metadata=metadata, cls=AsyncAttrs)
# Removed: _registered_models = set()

# Removed register_model function
# Removed validate_models function


class TimestampMixin:  # Inherit from object (or nothing)
    """
    Mixin to add created_at and updated_at timestamps to models.

    This mixin provides standard timestamp tracking for database models,
    automatically setting and updating timestamps.
    """

    @declared_attr
    def created_at(cls):
        return Column(
            DateTime(timezone=True),
            default=now_utc,
            server_default=func.now(),
            nullable=False,
            comment="Timestamp of when the record was created in UTC.",
        )

    @declared_attr
    def updated_at(cls):
        return Column(
            DateTime(timezone=True),
            default=now_utc,
            server_default=func.now(),
            onupdate=func.now(),
            nullable=False,
            comment="Timestamp of when the record was last updated in UTC.",
        )


class AuditMixin:  # Inherit from object (or nothing)
    """
    Mixin for HIPAA-compliant audit fields.

    Adds fields required for proper audit trails in a HIPAA-compliant system.
    """

    created_by = Column(String(36), nullable=True, comment="User ID who created this record")

    updated_by = Column(String(36), nullable=True, comment="User ID who last updated this record")

    audit_id = Column(
        String(36),
        default=lambda: str(uuid.uuid4()),
        nullable=False,
        comment="Unique ID for audit trail reference",
    )


# Removed BaseModel class

# ensure_all_models_loaded is problematic here as it also had its own logger
# and _registered_models. This function should be handled by the central registry
# or the __init__.py in the models package if necessary. For now, remove.

# Removed ensure_all_models_loaded function
