"""Base SQLAlchemy models module.

This module defines the CANONICAL declarative base class (Base)
used for all ORM models in this application.

It also re-exports common mixins.
"""

import logging

# Import the central SQLAlchemy registry
from app.infrastructure.persistence.sqlalchemy.registry import registry as sa_registry

# Import common mixins from their canonical location
from app.infrastructure.database.base_class import AuditMixin, TimestampMixin

# Import AsyncAttrs for async model support
from sqlalchemy.ext.asyncio import AsyncAttrs

# Configure logging
logger = logging.getLogger(__name__)

# Generate the canonical Base class using the central registry
# and include AsyncAttrs for asynchronous capabilities.
Base = sa_registry.generate_base(cls=AsyncAttrs)

# BaseModel can be defined here if it's a common utility for models
# inheriting *this* Base. If it was tied to the old incorrect Base,
# it might need adjustment or removal if not generally applicable.
# For now, let's assume it's a general utility.
class BaseModel(Base):
    """
    Base model class for all SQLAlchemy models inheriting from the canonical Base.
    
    This class provides common functionality for all models,
    such as to_dict() and from_dict() methods (example).
    
    All model classes should inherit from this class if they need these utilities
    and are based on the canonical `Base`.
    """
    __abstract__ = True
    
    # Example to_dict method, actual implementation might vary
    def to_dict(self, **kwargs):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

    # Any other common methods or properties can be added here.

__all__ = [
    'AuditMixin',
    'Base',
    'BaseModel',  # If kept
    'TimestampMixin',
]

logger.info("Canonical SQLAlchemy Base and core mixins configured.")
