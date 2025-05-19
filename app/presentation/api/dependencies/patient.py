"""
Patient-related Dependencies for the Presentation Layer.
"""

import logging
import uuid
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.params import Path

from app.core.domain.entities.patient import Patient
from app.core.domain.entities.user import UserRole

# Import from patient repository module
from app.core.interfaces.repositories.patient_repository import IPatientRepository

# Import from auth module
from app.presentation.api.dependencies.auth import CurrentUserDep

# Import from sibling auth module
# Import from database module
from app.presentation.api.dependencies.database import get_patient_repository_dependency

logger = logging.getLogger(__name__)


async def get_patient_id(
    patient_id: Annotated[str, Path(description="The UUID of the patient.")],
    current_user: CurrentUserDep,
    patient_repo: IPatientRepository = Depends(get_patient_repository_dependency),
    # session: AsyncSession = Depends(get_async_session) # Not used directly, repo uses it
) -> Patient:  # Return type should be the domain entity
    logger.info(
        f"get_patient_id called for patient_id: {patient_id} by user: {current_user.username}"
    )

    # Validate patient_id format
    try:
        validated_patient_uuid = uuid.UUID(patient_id)
    except ValueError:
        logger.warning(f"Invalid patient_id format: {patient_id}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid patient ID format."
        )

    # Authorization Logic:
    # A PATIENT can only access their own data.
    # A CLINICIAN or ADMIN can access any patient's data (further checks might apply elsewhere).

    is_patient_role = UserRole.PATIENT in current_user.roles
    is_clinician_role = UserRole.CLINICIAN in current_user.roles
    is_admin_role = UserRole.ADMIN in current_user.roles

    if is_patient_role and not (is_clinician_role or is_admin_role):  # Patient ONLY
        # If the current user is a patient, they can only access their own data.
        # Their user_id (current_user.id) must match the patient_id they are trying to access.
        # This assumes patient_id in the path *is* the user_id for a patient user accessing their own patient record.
        # Or, it means the Patient record's user_id field should match current_user.id.
        # For this check, we assume the `patient_id` in the URL for a patient accessing their own data *is* their own user_id.

        # Convert both to strings for comparison to handle UUID vs string properly
        user_id_str = str(current_user.id)
        patient_id_str = str(validated_patient_uuid)

        logger.debug(
            f"Comparing user_id: {user_id_str} to patient_id: {patient_id_str}"
        )

        if user_id_str != patient_id_str:
            logger.warning(
                f"Patient user {current_user.username} (ID: {current_user.id}) "
                f"attempted to access patient data for {validated_patient_uuid} - FORBIDDEN."
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Patients can only access their own data.",
            )
        logger.info(
            f"Patient user {current_user.username} accessing their own data for patient_id: {validated_patient_uuid}"
        )
    elif not (is_clinician_role or is_admin_role):
        # If user is not a patient, and also not a clinician or admin, they have no access by default.
        logger.warning(
            f"User {current_user.username} (Roles: {current_user.roles}) "
            f"attempted to access patient data for {validated_patient_uuid} - FORBIDDEN (insufficient base roles)."
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User does not have sufficient privileges to access patient data.",
        )
    # If user is Clinician or Admin, they are allowed to proceed to fetch the patient record.
    # More granular access checks (e.g., clinician assigned to patient) would typically occur in a service layer
    # or by checking a linking table, but for this dependency, role-based access is primary.
    logger.info(
        f"User {current_user.username} (Roles: {current_user.roles}) authorized to attempt fetch for patient_id: {validated_patient_uuid}"
    )

    # Retrieve patient from repository
    # db_patient = await patient_repo.get_by_id(patient_id=validated_patient_uuid, session=session) # Old way with session
    db_patient = await patient_repo.get_by_id(
        patient_id=validated_patient_uuid
    )  # Corrected call

    if db_patient is None:
        logger.warning(
            f"Patient with id {validated_patient_uuid} not found in database."
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Patient with id {validated_patient_uuid} not found",
        )

    return db_patient
