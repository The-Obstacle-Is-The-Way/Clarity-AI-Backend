# -*- coding: utf-8 -*-
"""
Base SQLAlchemy declarative base for all models.

This module provides a single source of truth for the SQLAlchemy declarative base
used by all model classes in the application. This pattern eliminates registry conflicts
by ensuring all models use the same metadata instance and registry.

Following clean architecture principles, this serves as the foundation for all
SQLAlchemy models, creating a consistent database schema and behavior across
the entire application.
"""

from sqlalchemy import MetaData
from sqlalchemy.orm import registry
from sqlalchemy.orm import declarative_base

# Create a shared registry that will be used across all models
# This eliminates the multiple registry problem during testing
_registry = registry()

# Create a single declarative base with a unique metadata instance
# All models should inherit from this Base class
Base = declarative_base(metadata=MetaData())

# Export the Base class as the only public API
__all__ = ['Base']
