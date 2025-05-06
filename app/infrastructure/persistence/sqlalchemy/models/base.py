"""Base SQLAlchemy models module - DEPRECATED.

IMPORTANT: This module is deprecated. Use app.infrastructure.database.base_class instead.

This module previously defined the Base class but now imports it from the canonical source.
This module is kept to maintain backward compatibility with existing imports.

Following clean architecture principles, we've centralized the SQLAlchemy base class
in app.infrastructure.database.base_class.py to prevent registry conflicts and maintain
a single source of truth.
"""

import logging

# Configure logging
logger = logging.getLogger(__name__)

# Import from our canonical source - this is the ONLY correct import location
from app.infrastructure.database.base_class import (
    AuditMixin,
    Base,
    BaseModel,
    TimestampMixin,
    register_model,
    validate_models
)

# Re-export these symbols for backward compatibility
__all__ = [
    'AuditMixin',
    'Base',
    'BaseModel',
    'TimestampMixin',
    'register_model',
    'validate_models'
]

# Log a deprecation warning
logger.warning(
    "This module is deprecated. Import Base and related components from "
    "app.infrastructure.database.base_class instead."
)
