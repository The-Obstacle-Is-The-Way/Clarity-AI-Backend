"""
DEPRECATED: SQLAlchemy user model proxy module.

This module provides backward compatibility for the UserModel class, which has been 
replaced by the canonical SQLAlchemy User model in app.infrastructure.persistence.sqlalchemy.models.user.

ATTENTION: This module exists only for backward compatibility. 
All new code should use the canonical User model directly.
"""

import logging

logger = logging.getLogger(__name__)

try:
    # Import the canonical User model to ensure we only have one source of truth
    from app.infrastructure.persistence.sqlalchemy.models.user import User

    # Create a backward-compatible alias
    UserModel = User
    
    # Log this usage for debugging and future migration
    logger.debug("UserModel alias used - this codebase should be migrated to use User directly")
    
    # WARNING: It's critical that we don't create a new model here!
    # UserModel is just an alias to the canonical User model.
except ImportError as e:
    # Fallback implementation for circular import protection
    # This prevents circular imports during module initialization
    # The proper User model will be used at runtime
    logger.warning(f"Using UserModel fallback implementation due to import error: {e}")
    
    # Import only what's needed for the type definition
    from sqlalchemy.ext.declarative import declarative_base

    from app.infrastructure.persistence.sqlalchemy.models.base import AuditMixin, TimestampMixin
    
    # Create a placeholder Base that won't be used for actual mapping
    _Base = declarative_base()
    
    # Define a placeholder UserModel that will be replaced at runtime
    class UserModel(_Base, TimestampMixin, AuditMixin):
        __tablename__ = "users"
        # This is just a placeholder and won't be used for actual mapping
        __abstract__ = True
        
        def __repr__(self):
            return "<UserModel Placeholder - NOT FOR ACTUAL USE>"

# Export the alias
__all__ = ['UserModel']