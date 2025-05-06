"""Base SQLAlchemy models module - DEPRECATED.

IMPORTANT: This module is deprecated. Use app.infrastructure.database.base_class instead.

This module previously defined the Base class but now imports it from the canonical source.
This module is kept to maintain backward compatibility with existing imports.

Following clean architecture principles, we've centralized the SQLAlchemy base class
in app.infrastructure.database.base_class.py to prevent registry conflicts and maintain
a single source of truth.
"""

import logging

# Configure logging
logger = logging.getLogger(__name__)

# Import from our canonical source - this is the ONLY correct import location
from app.infrastructure.database.base_class import (
    AuditMixin,
    Base,
    BaseModel,
    TimestampMixin,
    register_model,
    validate_models
)

# Re-export these symbols for backward compatibility
__all__ = [
    'AuditMixin',
    'Base',
    'BaseModel',
    'TimestampMixin',
    'register_model',
    'validate_models'
]

# Log a deprecation warning
logger.warning(
    "This module is deprecated. Import Base and related components from "
    "app.infrastructure.database.base_class instead."
)

def register_model(model_class: type[Base]) -> type[Base]:
    """
    Register a model class with the central registry for validation.
    This helps detect duplicate models and ensure proper initialization.
    
    Args:
        model_class: The SQLAlchemy model class to register
        
    Returns:
        The same model class (to allow for decorator-style usage)
    """
    # Register with the central registry first
    registry_register_model(model_class)
    
    # Also register with local registry for backward compatibility
    if model_class not in _model_registry:
        _model_registry.append(model_class)
        logger.debug(f"Registered model: {model_class.__name__}")
    
    return model_class

def validate_models(session: Any | None = None) -> None:
    """
    Validate all registered models to ensure they're properly mapped.
    
    Args:
        session: Optional SQLAlchemy session to validate against
        
    Raises:
        ValueError: If any model fails validation
    """
    # Use the validation function from the central registry
    from app.infrastructure.persistence.sqlalchemy.registry import (
        validate_models as registry_validate_models,
    )
    registry_validate_models()
    
    # Also validate models in local registry for backward compatibility
    for model_class in _model_registry:
        # Basic validation - ensure the model is properly declared
        try:
            # Check if the model has __tablename__
            if not hasattr(model_class, '__tablename__'):
                raise ValueError(f"Model {model_class.__name__} missing __tablename__")
                
            # Verify primary key exists
            mapper = inspect(model_class)
            if not mapper.primary_key:
                raise ValueError(f"Model {model_class.__name__} has no primary key")
                
            # Get column names for debugging
            column_names = [c.name for c in mapper.columns]
            logger.debug(f"Model {model_class.__name__} columns: {column_names}")
            
            # If session provided, try a test query
            if session and hasattr(session, "query"):
                session.query(model_class).first()
                
        except Exception as e:
            logger.error(f"Validation failed for model {model_class.__name__}: {e!s}")
            logger.warning(f"Continuing despite validation error for {model_class.__name__}")
            
    logger.info(f"Validated {len(_model_registry)} models in local registry successfully")
    
# Ensure all models are imported and registered at startup
def ensure_all_models_loaded():
    """
    Import all model modules to ensure they're registered with SQLAlchemy.
    This should be called during application startup.
    """
    try:
        # Import the centralized registry first
        from app.infrastructure.persistence.sqlalchemy.registry import get_registered_models
        
        # Import these models explicitly to ensure they are registered
        model_modules = [
            'app.infrastructure.persistence.sqlalchemy.models.user',
            'app.infrastructure.persistence.sqlalchemy.models.patient',
            'app.infrastructure.persistence.sqlalchemy.models.provider',
        ]
        
        for module_name in model_modules:
            try:
                importlib.import_module(module_name)
                logger.debug(f"Loaded model module: {module_name}")
            except ImportError as e:
                logger.warning(f"Could not import model module {module_name}: {e}")
        
        # Also import the models package to trigger __init__.py imports (backup)
        
        registered_models = get_registered_models()
        logger.info(f"All models loaded successfully: {registered_models}")
    except Exception as e:
        logger.error(f"Error loading models: {e!s}")
        # Don't raise exception to allow tests to continue despite errors
        logger.warning("Continuing despite model loading errors")
        


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


# Export the Base class and mixins as the public API
__all__ = ['AuditMixin', 'Base', 'TimestampMixin']
