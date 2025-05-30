"""
SQLAlchemy base configuration.

This module provides the declarative base for SQLAlchemy models
and other shared SQLAlchemy-related functionality.

Follows SQLAlchemy 2.0 typing patterns and SOLID principles.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sqlalchemy import Column, DateTime, Integer
from sqlalchemy.ext.asyncio import AsyncAttrs
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.sql import func

# Import the canonical registry for metadata consistency
from app.infrastructure.persistence.sqlalchemy.registry import metadata

if TYPE_CHECKING:
    from sqlalchemy.orm import Mapped


class Base(DeclarativeBase, AsyncAttrs):
    """
    SQLAlchemy 2.0 declarative base with async support.

    This provides type-safe base class following modern SQLAlchemy patterns.
    Combines DeclarativeBase for proper typing with AsyncAttrs for async support.

    Follows SOLID principles:
    - Single Responsibility: Pure base class definition
    - Open/Closed: Extensible through inheritance
    - Dependency Inversion: Depends on abstractions (DeclarativeBase)
    """

    # Use the shared metadata from registry for consistency
    metadata = metadata


class TimestampMixin:
    """
    Mixin to add created_at and updated_at timestamps to models.

    This mixin provides standard timestamp tracking for database models,
    automatically setting and updating timestamps.

    Follows Single Responsibility Principle - handles only timestamp concerns.
    """

    if TYPE_CHECKING:
        created_at: Mapped[DateTime]
        updated_at: Mapped[DateTime]
    else:
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

    Follows SOLID principles:
    - Single Responsibility: Common model functionality
    - Open/Closed: Extensible for domain-specific models
    - Interface Segregation: Minimal interface for all models
    """

    __abstract__ = True

    if TYPE_CHECKING:
        id: Mapped[int]
    else:
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

    def dict(self) -> dict[str, Any]:
        """
        Get dictionary representation of model instance.

        Returns:
            Dictionary with all non-SQLAlchemy attributes
        """
        result: dict[str, Any] = {}
        for key, value in self.__dict__.items():
            if not key.startswith("_"):
                result[key] = value

        return result
