"""
Patient-related Dependencies for the Presentation Layer.
"""

from uuid import UUID

from fastapi import Depends, HTTPException, status

from app.core.domain.entities.user import User, UserRole
from app.core.utils.logging import get_logger

# Import from sibling auth module
from .auth import get_current_user

logger = get_logger(__name__)


async def get_patient_id(
    patient_id: UUID,
    current_user: User = Depends(get_current_user)
) -> UUID:
    """Dependency to validate patient ID access based on user role.

    Ensures:
    - Patients can only access their own data.
    - Clinicians and Admins can access any patient data (further checks may apply elsewhere).
    - Other roles are denied access.
    """
    # Normalize role checks, handling potential None values
    primary_role_value = (current_user.role or "").upper()
    secondary_roles_set = {str(r).upper() for r in (current_user.roles or [])}

    is_patient = primary_role_value == UserRole.PATIENT.value
    is_clinician_or_admin = (
        primary_role_value in {UserRole.CLINICIAN.value, UserRole.ADMIN.value} or
        secondary_roles_set.intersection({UserRole.CLINICIAN.value, UserRole.ADMIN.value})
    )

    if is_patient:
        # Ensure patient ID in path matches the authenticated user's ID
        if str(current_user.id) != str(patient_id):
            logger.warning(
                f"Patient {current_user.id} attempted to access data for patient {patient_id}"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Patients can only access their own data.",
            )
    elif not is_clinician_or_admin:
        # Deny access if not patient, clinician, or admin
        logger.error(
            f"User {current_user.id} with role(s) {current_user.role}/{current_user.roles} "
            f"attempted access to patient {patient_id} data."
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions."
        )
    # Implicitly allow access for Clinician/Admin roles here
    # More granular checks (e.g., clinician assigned to patient) should be done
    # in the service layer if needed.

    return patient_id
