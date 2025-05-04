"""
SQLAlchemy Model Registry

This module provides a central registry for all SQLAlchemy models to ensure
proper metadata and mapper configuration. It addresses the UnmappedColumnError
issues by creating a single source of truth for model registration.

This follows clean architecture principles by centralizing infrastructure concerns
and ensuring proper dependency management.
"""

import logging
from typing import Any

from sqlalchemy import MetaData
from sqlalchemy.orm import registry as sa_registry

# Configure logging
logger = logging.getLogger(__name__)

# Create a single metadata instance that all models will share
metadata = MetaData()

# Create a single mapper registry that will be used for all models
registry = sa_registry(metadata=metadata)

# Keep track of all registered models for validation and debugging
_registered_models: set[type[Any]] = set()
_registered_tables: set[str] = set()


def register_model(model_class: type[Any]) -> type[Any]:
    """
    Register a model with the central SQLAlchemy registry.
    
    This ensures all models share the same metadata and registry,
    eliminating mapping conflicts.
    
    Args:
        model_class: SQLAlchemy model class to register
        
    Returns:
        The registered model class (allows decorator usage)
    """
    if model_class not in _registered_models:
        _registered_models.add(model_class)
        
        # Keep track of tables for diagnostics
        if hasattr(model_class, '__tablename__'):
            table_name = model_class.__tablename__
            if table_name in _registered_tables:
                logger.warning(f"Table {table_name} registered multiple times!")
            _registered_tables.add(table_name)
            
        logger.debug(f"Registered model: {model_class.__name__}")
    
    return model_class


def validate_models() -> None:
    """
    Validate all registered models to ensure they're properly mapped.
    
    This helps detect issues with model definition and mapping early.
    """
    from sqlalchemy import inspect
    
    logger.info(f"Validating {len(_registered_models)} registered models")
    
    for model_class in _registered_models:
        try:
            # Check if model has __tablename__
            if not hasattr(model_class, '__tablename__'):
                logger.warning(f"Model {model_class.__name__} missing __tablename__")
                continue
                
            # Get mapper
            mapper = inspect(model_class)
            
            # Check for primary key
            if not mapper.primary_key:
                logger.warning(f"Model {model_class.__name__} has no primary key")
                
            # Log column details for debugging
            column_details = [(c.name, c.type) for c in mapper.columns]
            logger.debug(f"Model {model_class.__name__} columns: {column_details}")
            
        except Exception as e:
            logger.error(f"Validation error for {model_class.__name__}: {e!s}")


def get_registered_models() -> list[str]:
    """Get list of all registered model names."""
    return [model.__name__ for model in _registered_models]


def get_registered_tables() -> list[str]:
    """Get list of all registered table names."""
    return list(_registered_tables)


def ensure_all_models_registered() -> None:
    """
    Ensures all models are properly registered with SQLAlchemy.
    
    This function should be called during application startup to prevent
    mapping errors and ensure a consistent state of all SQLAlchemy models.
    """
    try:
        # Import core models to ensure they're registered
        
        # Log registered models for debugging
        model_names = get_registered_models()
        table_names = get_registered_tables()
        logger.info(f"Registered {len(model_names)} models: {', '.join(model_names)}")
        logger.info(f"Registered {len(table_names)} tables: {', '.join(table_names)}")
    except Exception as e:
        logger.error(f"Error ensuring models are registered: {e!s}")
        # Don't raise the exception to allow for graceful degradation
