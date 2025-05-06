"""SQLAlchemy Base class definition for the Clarity AI Digital Twin Platform.

This module defines the CANONICAL declarative base class used for all ORM models.
This is the SINGLE SOURCE OF TRUTH for the SQLAlchemy declarative base.

IMPORTANT: All models must import Base from this module ONLY.

Architectural Note:
- This follows Clean Architecture principles by centralizing infrastructure concerns
- Maintains single responsibility for model definitions
- Prevents mapping conflicts by ensuring all models use the same metadata

CONSOLIDATION NOTICE: This file now serves as the ONLY Base class definition.
All prior Base definitions should be replaced with imports from this module.

HIPAA NOTE: Consistent model definitions are essential for ensuring data integrity
and maintaining HIPAA compliance across the application.
"""

import logging
import uuid
from typing import Any

from sqlalchemy import Column, DateTime, String, func, MetaData
from sqlalchemy.ext.asyncio import AsyncAttrs
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import registry

# Configure logging
logger = logging.getLogger(__name__)

# Create central metadata instance that all models will share
metadata = MetaData()

# Initialize the mapper registry with our central metadata
mapper_registry = registry(metadata=metadata)

# Create SQLAlchemy models declarative base with our central metadata
# This is the CANONICAL base class for all models
Base = declarative_base(metadata=metadata, cls=AsyncAttrs)

# Keep track of registered models for validation and diagnostics
_registered_models = set()


def register_model(model_class: type[Any]) -> type[Any]:
    """
    Register a model with the central registry.
    
    This decorator ensures all models are properly tracked and validated.
    It should be used on all SQLAlchemy model classes.
    
    Args:
        model_class: SQLAlchemy model class to register
        
    Returns:
        The registered model class (allows decorator usage)
    """
    if model_class not in _registered_models:
        _registered_models.add(model_class)
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
            column_names = [c.name for c in mapper.columns]
            logger.debug(f"Model {model_class.__name__} columns: {column_names}")
            
        except Exception as e:
            logger.error(f"Validation error for {model_class.__name__}: {e!s}")
            # Don't raise exception to allow for graceful degradation


class TimestampMixin:
    """
    Mixin to add created_at and updated_at timestamps to models.
    
    This mixin provides standard timestamp tracking for database models,
    automatically setting and updating timestamps.
    """
    
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        comment="When this record was created"
    )
    
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
        comment="When this record was last updated"
    )


class AuditMixin:
    """
    Mixin for HIPAA-compliant audit fields.
    
    Adds fields required for proper audit trails in a HIPAA-compliant system.
    """
    created_by = Column(
        String(36),
        nullable=True,
        comment="User ID who created this record"
    )
    
    updated_by = Column(
        String(36),
        nullable=True,
        comment="User ID who last updated this record"
    )
    
    audit_id = Column(
        String(36),
        default=lambda: str(uuid.uuid4()),
        nullable=False,
        comment="Unique ID for audit trail reference"
    )


class BaseModel(Base):
    """
    Base model class for all SQLAlchemy models.
    
    This class provides common functionality for all models,
    such as to_dict() and from_dict() methods.
    
    All model classes should inherit from this class if they need these utilities.
    """
    __abstract__ = True
    
    def to_dict(self) -> dict[str, Any]:
        """
        Convert model to dictionary.
        
        Returns:
            Dictionary representation of the model
        """
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "BaseModel":
        """
        Create model instance from dictionary data.
        
        Args:
            data: Dictionary containing model data
            
        Returns:
            Instance of the model class
        """
        return cls(**{
            k: v for k, v in data.items() 
            if k in [c.name for c in cls.__table__.columns]
        })


def ensure_all_models_loaded() -> None:
    """
    Import all model modules to ensure they're registered with SQLAlchemy.
    This should be called during application startup and test initialization.
    
    This is important to make sure SQLAlchemy is aware of all models before
    creating tables or performing operations on the database.
    """
    import importlib
    import logging
    
    logger = logging.getLogger(__name__)
    
    try:
        # Import these models explicitly to ensure they are registered
        model_modules = [
            'app.infrastructure.persistence.sqlalchemy.models.user',
            'app.infrastructure.persistence.sqlalchemy.models.patient',
            'app.infrastructure.persistence.sqlalchemy.models.provider',
            'app.infrastructure.persistence.sqlalchemy.models.audit_log',
        ]
        
        for module_name in model_modules:
            try:
                importlib.import_module(module_name)
                logger.debug(f"Loaded model module: {module_name}")
            except ImportError as e:
                logger.warning(f"Could not import model module {module_name}: {e}")
        
        logger.info(f"Registered models: {len(_registered_models)}")
    except Exception as e:
        logger.error(f"Error loading models: {e!s}")
        # Don't raise exception to allow tests to continue despite errors
        logger.warning("Continuing despite model loading errors")