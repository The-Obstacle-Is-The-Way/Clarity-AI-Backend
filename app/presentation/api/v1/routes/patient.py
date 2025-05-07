import logging
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.application.services.patient_service import PatientService
from app.domain.repositories.patient_repository import PatientRepository
from app.infrastructure.persistence.sqlalchemy.repositories.patient_repository import (
    PatientRepository as SQLPatientRepoImpl,
)
from app.presentation.api.dependencies.database import get_db
from app.presentation.api.dependencies.patient import get_patient_id as get_validated_patient_id_for_read
from app.presentation.api.dependencies.auth import CurrentUserDep, DomainUser
from app.presentation.api.schemas.patient import (
    PatientRead,
    PatientCreateRequest,
    PatientCreateResponse,
)

# Placeholder dependency - replace with actual service implementation later
def get_patient_service(
    db_session: AsyncSession = Depends(get_db)
) -> PatientService:
    """Dependency provider for PatientService."""
    repo = SQLPatientRepoImpl(db_session=db_session) 
    return PatientService(repository=repo) 

logger = logging.getLogger(__name__)

router = APIRouter()

@router.get(
    "/{patient_id}",
    response_model=PatientRead, 
    summary="Get Patient by ID",
    description="Retrieve details for a specific patient."
)
async def read_patient(
    patient_uuid: UUID = Depends(get_validated_patient_id_for_read),
    service: PatientService = Depends(get_patient_service)
) -> PatientRead: 
    """Retrieve a patient by their unique ID after authorization."""
    patient = await service.get_patient_by_id(patient_uuid)
    if patient is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Patient with id {patient_uuid} not found"
        )
    return patient 

@router.post(
    "/",
    response_model=PatientCreateResponse, 
    status_code=status.HTTP_201_CREATED, 
    summary="Create Patient",
    description="Create a new patient record."
)
async def create_patient_endpoint(
    patient_data: PatientCreateRequest, 
    service: PatientService = Depends(get_patient_service),
    current_user: DomainUser = Depends(CurrentUserDep)
) -> PatientCreateResponse: 
    """Create a new patient."""
    logger.info(f"User {current_user.id} attempting to create patient: {patient_data.name.first_name} {patient_data.name.last_name}")
    try:
        created_patient = await service.create_patient(patient_data, created_by_id=current_user.id)
        return created_patient
    except Exception as e:
        logger.error(f"Error creating patient by user {current_user.id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred while creating the patient."
        ) from e

# Add other routes (PUT, DELETE, LIST) later
