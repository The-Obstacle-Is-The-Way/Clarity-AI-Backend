"""
SQLAlchemy persistence implementation for the Novamind Digital Twin Platform.

This module provides SQLAlchemy-based data access implementations that follow
clean architecture principles while ensuring HIPAA compliance for all PHI data.
"""

# Re-export unit of work classes from their new location
from app.infrastructure.persistence.sqlalchemy.unit_of_work.unit_of_work import SQLAlchemyUnitOfWork
from app.infrastructure.persistence.sqlalchemy.unit_of_work.async_unit_of_work import AsyncSQLAlchemyUnitOfWork
from app.infrastructure.persistence.sqlalchemy.unit_of_work.unit_of_work_factory import UnitOfWorkFactory

# Re-export repositories for backward compatibility
from app.infrastructure.persistence.sqlalchemy.repositories.appointment_repository import (
    AppointmentRepository, 
    SQLAlchemyAppointmentRepository
)

# Export registry
from app.infrastructure.persistence.sqlalchemy.registry import (
    registry,
    metadata, 
    register_model,
    ensure_all_models_registered,
    validate_models
)

__all__ = [
    # Unit of Work
    "SQLAlchemyUnitOfWork",
    "AsyncSQLAlchemyUnitOfWork",
    "UnitOfWorkFactory",
    
    # Repositories
    "AppointmentRepository",
    "SQLAlchemyAppointmentRepository",
    
    # Registry
    "registry",
    "metadata",
    "register_model",
    "ensure_all_models_registered",
    "validate_models"
]