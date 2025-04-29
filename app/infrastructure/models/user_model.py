"""
DEPRECATED: SQLAlchemy user model proxy module.

This module provides backward compatibility for the UserModel class, which has been 
replaced by the canonical SQLAlchemy User model in app.infrastructure.persistence.sqlalchemy.models.user.

ATTENTION: This module exists only for backward compatibility. 
All new code should use the canonical User model directly.
"""

# Import the canonical User model to ensure we only have one source of truth
from app.infrastructure.persistence.sqlalchemy.models.user import User

# Create a backward-compatible alias
UserModel = User

# WARNING: It's critical that we don't create a new model here!
# UserModel is just an alias to the canonical User model.

__all__ = ['UserModel']