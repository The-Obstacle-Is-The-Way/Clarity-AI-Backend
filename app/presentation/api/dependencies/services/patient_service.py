"""
Patient service dependency provider.

This module defines dependencies for patient-related services, following
Clean Architecture principles with proper abstraction between layers.
"""

from typing import Annotated

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.application.services.patient_service import PatientService
from app.core.interfaces.repositories.patient_repository_interface import IPatientRepository
from app.infrastructure.persistence.sqlalchemy.repositories.patient_repository import (
    PatientRepositoryImpl,
)
from app.presentation.api.dependencies.database import get_db


def get_patient_repository(db_session: AsyncSession = Depends(get_db)) -> IPatientRepository:
    """
    Provides a patient repository implementation.
    
    Args:
        db_session: SQLAlchemy async database session
        
    Returns:
        An implementation of the IPatientRepository interface
    """
    return PatientRepositoryImpl(db_session=db_session)


def get_patient_service(
    repository: IPatientRepository = Depends(get_patient_repository),
) -> PatientService:
    """
    Provides a patient service implementation.
    
    Args:
        repository: Repository for patient data access
        
    Returns:
        An implementation of the PatientService
    """
    return PatientService(repository=repository)


# Type annotations for dependency injection
PatientRepositoryDep = Annotated[IPatientRepository, Depends(get_patient_repository)]
PatientServiceDep = Annotated[PatientService, Depends(get_patient_service)]


__all__ = [
    "PatientRepositoryDep",
    "PatientServiceDep",
    "get_patient_repository",
    "get_patient_service",
]
