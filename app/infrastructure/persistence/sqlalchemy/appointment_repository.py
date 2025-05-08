"""
This module is deprecated and will be removed in a future version.
Import AppointmentRepository from app.infrastructure.persistence.sqlalchemy.repositories.appointment_repository instead.
"""

import warnings

warnings.warn(
    "This module is deprecated. Import AppointmentRepository from "
    "app.infrastructure.persistence.sqlalchemy.repositories.appointment_repository instead.",
    DeprecationWarning,
    stacklevel=2
)

from app.infrastructure.persistence.sqlalchemy.repositories.appointment_repository import (
    AppointmentRepository, 
    SQLAlchemyAppointmentRepository
)

__all__ = ["AppointmentRepository", "SQLAlchemyAppointmentRepository"]
