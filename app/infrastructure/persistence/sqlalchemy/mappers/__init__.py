"""
SQLAlchemy entity mappers package.

This package contains mapper classes that translate between domain entities
and SQLAlchemy persistence models, preserving clean architecture boundaries.
"""

from app.infrastructure.persistence.sqlalchemy.mappers.user_mapper import UserMapper

__all__ = ["UserMapper"]
