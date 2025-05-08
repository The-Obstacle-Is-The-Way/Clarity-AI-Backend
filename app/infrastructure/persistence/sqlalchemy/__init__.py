"""
SQLAlchemy persistence implementation for the Novamind Digital Twin Platform.

This module provides SQLAlchemy-based data access implementations that follow
clean architecture principles while ensuring HIPAA compliance for all PHI data.
"""

# Import unit of work classes directly from their location
from app.infrastructure.persistence.sqlalchemy.unit_of_work.unit_of_work import SQLAlchemyUnitOfWork
from app.infrastructure.persistence.sqlalchemy.unit_of_work.async_unit_of_work import AsyncSQLAlchemyUnitOfWork
from app.infrastructure.persistence.sqlalchemy.unit_of_work.unit_of_work_factory import UnitOfWorkFactory

# Import repositories directly from their location
from app.infrastructure.persistence.sqlalchemy.repositories.appointment_repository import (
    AppointmentRepository, 
    SQLAlchemyAppointmentRepository
)

# Import database classes directly from their location 
from app.infrastructure.persistence.sqlalchemy.config.database import (
    Database,
    DatabaseFactory,
    get_database,
    get_db_instance,
    get_db_session,
    DBSessionDep
)

# Base model from models
from app.infrastructure.persistence.sqlalchemy.models.base import Base

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
    
    # Database
    "Database",
    "DatabaseFactory", 
    "get_database",
    "get_db_instance",
    "get_db_session",
    "DBSessionDep",
    "Base",
    
    # Registry
    "registry",
    "metadata",
    "register_model",
    "ensure_all_models_registered",
    "validate_models"
]