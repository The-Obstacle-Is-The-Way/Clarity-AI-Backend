"""Patient management API routes.

This module defines the API routes for managing patient resources, including CRUD operations
and related biometric alert rules. All endpoints use proper dependency injection, interface-based
architecture, and HIPAA-compliant error handling.
"""

import logging
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Path, status

from app.application.services.biometric_alert_rule_service import BiometricAlertRuleService
from app.core.domain.entities.patient import Patient
from app.core.domain.entities.user import UserRole
from app.presentation.api.dependencies.auth import CurrentUserDep, DomainUser, require_roles
from app.presentation.api.dependencies.patient import get_patient_id as get_validated_patient_id_for_read
from app.presentation.api.dependencies.services.patient_service import PatientServiceDep
from app.presentation.api.schemas.patient import (
    PatientCreateRequest,
    PatientCreateResponse,
    PatientRead,
    PatientUpdateRequest,
)
from app.presentation.api.v1.endpoints.biometric_alert_rules import (
    get_patient_alert_rules,
    get_rule_service,
)
from app.presentation.api.v1.schemas.biometric_alert_rules import AlertRuleResponse


logger = logging.getLogger(__name__)

router = APIRouter()

# MODIFIED: Remove the local mock dependency function
# async def mock_get_current_user_for_route() -> DomainUser:
#     return DomainUser(
#         id=uuid.uuid4(),
#         email="route_mock_user@example.com",
#         username="route_mock_user",
#         full_name="Route Mock User",
#         password_hash="somehash",
#         roles={UserRole.ADMIN},
#         status=UserStatus.ACTIVE
#     )


@router.get(
    "/{patient_id}",
    response_model=PatientRead,
    name="patients:read_patient",
    summary="Get a specific patient by ID",
    description="Retrieve detailed information about a specific patient using their UUID.",
    tags=["Patients"],
)
async def read_patient(
    patient_id: UUID = Depends(get_validated_patient_id_for_read),
    service: PatientServiceDep = Depends(),
) -> PatientRead:
    """
    Retrieve a patient by their ID.
    
    Args:
        patient_id: UUID of the patient to retrieve
        service: Patient service dependency
        
    Returns:
        Patient data if found
        
    Raises:
        HTTPException: If patient not found
    """
    logger.info(f"Endpoint read_patient: Fetching patient with ID {patient_id}")
    patient = await service.get_patient_by_id(patient_id)
    if patient is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Patient not found")
    return patient

@router.post(
    "/",
    response_model=PatientCreateResponse,
    status_code=status.HTTP_201_CREATED,
    name="patients:create_patient",
    summary="Create a new patient",
)
async def create_patient(
    patient_data: PatientCreateRequest,
    service: PatientServiceDep = Depends(),
    current_user: CurrentUserDep = Depends(),
) -> Patient:
    """Create a new patient.

    Args:
        patient_data: Patient data for creation
        service: Patient service dependency
        current_user: The authenticated user creating the patient

    Returns:
        The newly created patient

    Raises:
        HTTPException: If there's an error during creation
    """
    logger.info(f"Endpoint create_patient called by user {current_user.id}")
    try:
        # Ensure we have the creator's ID
        new_patient = await service.create_patient(
            patient_data=patient_data, created_by=current_user.id
        )
        return new_patient
    except Exception as e:
        logger.error(f"Error creating patient by user {current_user.id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred while creating the patient.",
        ) from e





@router.put(
    "/{patient_id}",
    response_model=PatientRead,
    name="patients:update_patient",
    summary="Update an existing patient",
    dependencies=[Depends(require_roles([UserRole.ADMIN, UserRole.CLINICIAN]))]
)
async def update_patient(
    patient_id: UUID,
    patient_update_data: PatientUpdateRequest,
    service: PatientServiceDep = Depends(),
) -> PatientRead:
    """Update an existing patient.
    
    Args:
        patient_id: The ID of the patient to update
        patient_update_data: New patient data for update
        service: Patient service dependency
        
    Returns:
        The updated patient
        
    Raises:
        HTTPException: If the patient is not found
    """
    logger.info(f"Endpoint update_patient called for patient_id: {patient_id}")
    updated_patient = await service.update_patient(patient_id, patient_update_data)
    if updated_patient is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Patient not found")
    return updated_patient


@router.delete(
    "/{patient_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    name="patients:delete_patient",
    summary="Delete a patient",
    dependencies=[Depends(require_roles([UserRole.ADMIN]))]
)
async def delete_patient(
    patient_id: UUID,
    service: PatientServiceDep = Depends(),
) -> None:
    """Delete a patient.
    
    Args:
        patient_id: The ID of the patient to delete
        service: Patient service dependency
        
    Raises:
        HTTPException: If the patient is not found
    """
    logger.info(f"Endpoint delete_patient called for patient_id: {patient_id}")
    deleted = await service.delete_patient(patient_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Patient not found")


@router.get(
    "/",
    response_model=list[PatientRead],
    name="patients:list_patients",
    summary="List all patients",
    dependencies=[Depends(require_roles([UserRole.ADMIN, UserRole.CLINICIAN]))]
)
async def list_patients(
    service: PatientServiceDep = Depends(),
) -> list[PatientRead]:
    """List all patients.
    
    Args:
        service: Patient service dependency
        
    Returns:
        List of all patients
    """
    logger.info("Endpoint list_patients called")
    return await service.get_all_patients()


@router.get(
    "/{patient_id}/biometric-alert-rules",
    response_model=list[AlertRuleResponse],
    name="patients:get_biometric_alert_rules",
    summary="Get biometric alert rules for a patient"
)
async def get_patient_biometric_alert_rules(
    patient_id: UUID = Path(..., description="Patient ID"),
    current_user: DomainUser | None = None,
    rule_service: BiometricAlertRuleService = Depends(get_rule_service),
) -> list[AlertRuleResponse]:
    """
    Get biometric alert rules for a specific patient.

    This endpoint forwards requests to the biometric alert rules service.

    Args:
        patient_id: Patient ID
        current_user: Authenticated user
        rule_service: Alert rule service

    Returns:
        List of alert rules for the patient
    """
    logger.info(f"Forwarding request for patient {patient_id} alert rules")

    # Forward to the existing implementation
    return await get_patient_alert_rules(patient_id, current_user, rule_service)
