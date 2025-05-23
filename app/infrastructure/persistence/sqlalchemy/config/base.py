"""
SQLAlchemy base configuration.

This module provides the declarative base for SQLAlchemy models
and other shared SQLAlchemy-related functionality.
"""


from sqlalchemy import Column, DateTime, Integer
from sqlalchemy.ext.asyncio import AsyncAttrs
from sqlalchemy.sql import func

# Import the canonical Base from the registry module
from app.infrastructure.persistence.sqlalchemy.registry import mapper_registry

# Create declarative base with async attributes support using canonical registry
Base = mapper_registry.generate_base(cls=AsyncAttrs)


class TimestampMixin:
    """
    Mixin to add created_at and updated_at timestamps to models.

    This mixin provides standard timestamp tracking for database models,
    automatically setting and updating timestamps.
    """

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class BaseSQLModel(Base):
    """
    Base class for all SQLAlchemy models.

    This class provides common functionality for all models,
    including a primary key and a string representation method.
    """

    __abstract__ = True

    id = Column(Integer, primary_key=True, index=True)

    def __repr__(self) -> str:
        """
        Get string representation of model instance.

        Returns:
            String representation
        """
        attrs = []
        for key, value in self.__dict__.items():
            if not key.startswith("_"):
                attrs.append(f"{key}={value!r}")

        return f"{self.__class__.__name__}({', '.join(attrs)})"

    def dict(self) -> dict:
        """
        Get dictionary representation of model instance.

        Returns:
            Dictionary with all non-SQLAlchemy attributes
        """
        result = {}
        for key, value in self.__dict__.items():
            if not key.startswith("_"):
                result[key] = value

        return result
