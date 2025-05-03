# -*- coding: utf-8 -*-
"""
SQLAlchemy custom types package.

This package contains custom type definitions for SQLAlchemy models.
"""

from app.infrastructure.persistence.sqlalchemy.types.postgres_compatible_uuid import GUID

__all__ = ["GUID"]