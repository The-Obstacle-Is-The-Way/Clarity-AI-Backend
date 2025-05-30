"""
DEPRECATED: SQLAlchemy user model proxy module.

This module provides backward compatibility for the UserModel class, which has been
replaced by the canonical SQLAlchemy User model in app.infrastructure.persistence.sqlalchemy.models.user.

ATTENTION: This module exists only for backward compatibility.
All new code should use the canonical User model directly.
"""

import logging
from typing import Any, ClassVar

logger = logging.getLogger(__name__)


# This proxy class forwards all operations to the canonical User class
# This avoids circular imports while ensuring UserModel and User are identical in behavior
class UserModelProxy:
    """
    Proxy class that forwards all operations to the canonical User class.
    This acts like User in all respects but avoids circular imports.
    """

    _user_class: ClassVar[type[Any]] = None

    def __new__(cls, *args, **kwargs):
        if cls._user_class is None:
            from app.infrastructure.persistence.sqlalchemy.models.user import User

            cls._user_class = User
            logger.debug("UserModel proxy initialized with canonical User class")

        # Return an instance of the actual User class instead of this proxy
        return cls._user_class(*args, **kwargs)

    @classmethod
    def __class_getitem__(cls, key):
        if cls._user_class is None:
            from app.infrastructure.persistence.sqlalchemy.models.user import User

            cls._user_class = User
        return cls._user_class.__class_getitem__(key)

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if cls._user_class is None:
            from app.infrastructure.persistence.sqlalchemy.models.user import User

            cls._user_class = User


# Use the proxy as the UserModel
UserModel = UserModelProxy

# Export the alias
__all__ = ["UserModel"]
