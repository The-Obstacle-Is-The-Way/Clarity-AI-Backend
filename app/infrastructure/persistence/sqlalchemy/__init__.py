"""
SQLAlchemy persistence implementation for the Novamind Digital Twin Platform.

This module provides SQLAlchemy-based data access implementations that follow
clean architecture principles while ensuring HIPAA compliance for all PHI data.
"""

# Import unit of work classes directly from their location
# Import database classes directly from their location
from app.infrastructure.persistence.sqlalchemy.config.database import (
    Database,
    DatabaseFactory,
    DBSessionDep,
    get_database,
    get_db_instance,
    get_db_session,
)

# Base model from models
from app.infrastructure.persistence.sqlalchemy.models.base import Base

# Export registry
from app.infrastructure.persistence.sqlalchemy.registry import (
    ensure_all_models_registered,
    metadata,
    register_model,
    registry,
    validate_models,
)

# Import repositories directly from their location
from app.infrastructure.persistence.sqlalchemy.repositories.appointment_repository import (
    AppointmentRepository,
    SQLAlchemyAppointmentRepository,
)
from app.infrastructure.persistence.sqlalchemy.unit_of_work.async_unit_of_work import (
    AsyncSQLAlchemyUnitOfWork,
)
from app.infrastructure.persistence.sqlalchemy.unit_of_work.unit_of_work import (
    SQLAlchemyUnitOfWork,
)
from app.infrastructure.persistence.sqlalchemy.unit_of_work.unit_of_work_factory import (
    UnitOfWorkFactory,
)

__all__ = [
    # Repositories
    "AppointmentRepository",
    "AsyncSQLAlchemyUnitOfWork",
    "Base",
    "DBSessionDep",
    # Database
    "Database",
    "DatabaseFactory",
    "SQLAlchemyAppointmentRepository",
    # Unit of Work
    "SQLAlchemyUnitOfWork",
    "UnitOfWorkFactory",
    "ensure_all_models_registered",
    "get_database",
    "get_db_instance",
    "get_db_session",
    "metadata",
    "register_model",
    # Registry
    "registry",
    "validate_models",
]
