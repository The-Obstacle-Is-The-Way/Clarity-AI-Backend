"""
API Endpoints for Appointment Scheduling.

Provides endpoints for creating, retrieving, updating, and deleting appointments.
"""
from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.domain.entities.appointment import (
    AppointmentStatus,
)  # For query param validation

# Assuming User type from auth dependency matches this import or is compatible (e.g., dict)
from app.domain.entities.user import User

# from app.application.services.appointment_service import AppointmentService # Use this when service layer is built
from app.domain.repositories.appointment_repository import (
    IAppointmentRepository,  # Temporary direct repo access
)
from app.domain.utils.datetime_utils import now_utc

# Import dependencies
from app.presentation.api.dependencies.auth import (
    get_current_user,  # , require_role # Add role check if needed
)

# Import schemas
from app.presentation.api.schemas.appointment import (
    AppointmentCreate,
    AppointmentResponse,
    AppointmentUpdate,
)

# Initialize router
router = APIRouter()


# --- Placeholder Dependencies ---
async def get_appointment_repo() -> IAppointmentRepository:
    # Placeholder: Return a mock or raise NotImplementedError until implemented
    from unittest.mock import AsyncMock

    mock_repo = AsyncMock(spec=IAppointmentRepository)

    # Configure mock methods as needed for testing
    async def mock_get(appt_id):
        return None

    async def mock_list(**kwargs):
        return []

    mock_repo.get_by_id = mock_get
    mock_repo.list_by_patient_id = mock_list
    mock_repo.list_by_provider_id = mock_list
    return mock_repo


# --- API Endpoints ---


@router.post(
    "",
    response_model=AppointmentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Schedule Appointment",
    description="Schedule a new appointment between a patient and a provider.",
    # dependencies=[Depends(require_role("clinician"))] # Or scheduler role
)
async def schedule_appointment(
    appointment_data: AppointmentCreate,
    current_user: User = Depends(get_current_user),
    repo: IAppointmentRepository = Depends(get_appointment_repo),
):
    """
    Schedules a new appointment.

    Requires appropriate permissions (e.g., clinician, scheduler, or patient scheduling own).
    """
    # TODO: Add authorization: Can current_user schedule for this patient/provider?
    # TODO: Add validation: Check for provider availability / overlapping appointments using repo.find_overlapping_appointments

    try:
        from app.domain.entities.appointment import Appointment  # Import entity

        new_appointment_entity = Appointment(**appointment_data.model_dump())

        # Mock create for now
        async def mock_create(appt):
            appt.id = uuid4()
            return appt

        repo.create = mock_create

        created_appointment = await repo.create(new_appointment_entity)
        return created_appointment
    except ValueError as ve:  # Catch validation errors from entity __post_init__
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except Exception:
        # Log error
        # logger.error(f"Failed to schedule appointment: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to schedule appointment",
        )


@router.get(
    "/{appointment_id}",
    response_model=AppointmentResponse,
    summary="Get Appointment Details",
    description="Retrieve details for a specific appointment.",
)
async def get_appointment(
    appointment_id: UUID,
    current_user: User = Depends(get_current_user),
    repo: IAppointmentRepository = Depends(get_appointment_repo),
):
    """
    Retrieves details of a specific appointment by its ID.
    Requires user to be associated with the appointment (patient/provider) or have admin rights.
    """

    # Mock get_by_id for now
    async def mock_get_id(appt_id):
        if str(appt_id) == "123e4567-e89b-12d3-a456-426614174002":  # Example ID
            from uuid import uuid4

            from app.domain.entities.appointment import Appointment, AppointmentType

            return Appointment(
                id=UUID("123e4567-e89b-12d3-a456-426614174002"),
                patient_id=uuid4(),
                provider_id=uuid4(),
                start_time=now_utc(),
                end_time=now_utc() + timedelta(hours=1),
                appointment_type=AppointmentType.FOLLOW_UP,
            )
        return None

    repo.get_by_id = mock_get_id

    appointment = await repo.get_by_id(appointment_id)
    if not appointment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Appointment not found"
        )

    # TODO: Add authorization: Can current_user view this appointment?
    # Example check:
    # if isinstance(current_user, dict):
    #    user_id_str = current_user.get('id')
    #    user_role = current_user.get('role')
    #    if not (user_role in ['admin', 'scheduler'] or \
    #            str(appointment.patient_id) == user_id_str or \
    #            str(appointment.provider_id) == user_id_str):
    #        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to view this appointment")

    return appointment


@router.get(
    "",
    response_model=list[AppointmentResponse],
    summary="List Appointments",
    description="Retrieve a list of appointments based on filter criteria.",
)
async def list_appointments(
    patient_id: UUID | None = Query(None, description="Filter by patient ID"),
    provider_id: UUID | None = Query(None, description="Filter by provider ID"),
    start_date: datetime
    | None = Query(None, description="Filter by start date (inclusive)"),
    end_date: datetime
    | None = Query(None, description="Filter by end date (exclusive)"),
    status: AppointmentStatus
    | None = Query(None, description="Filter by appointment status"),
    limit: int = Query(
        50, ge=1, le=200, description="Maximum number of appointments to return"
    ),
    offset: int = Query(0, ge=0, description="Number of appointments to skip"),
    current_user: User = Depends(get_current_user),
    repo: IAppointmentRepository = Depends(get_appointment_repo),
):
    """
    Lists appointments, filterable by patient, provider, date range, and status.
    Requires appropriate permissions to view the requested appointments.
    """
    # TODO: Add authorization based on query params and user role
    # E.g., Patient can only list their own appointments (patient_id must match user ID)
    # Clinician can list their own or their patients' appointments
    # Admin/Scheduler can list any

    query_filters = {
        "patient_id": patient_id,
        "provider_id": provider_id,
        "start_date": start_date,
        "end_date": end_date,
        "status": status,
        # Pass limit/offset if repository handles pagination
    }

    # Simplistic fetch - replace with specific repo calls based on params
    if patient_id:
        # Mock list_by_patient_id
        async def mock_list_patient(pat_id, sd, ed, st):
            return []

        repo.list_by_patient_id = mock_list_patient
        appointments = await repo.list_by_patient_id(
            patient_id, start_date, end_date, status
        )  # Add limit/offset later
    elif provider_id:
        # Mock list_by_provider_id
        async def mock_list_provider(prov_id, sd, ed, st):
            return []

        repo.list_by_provider_id = mock_list_provider
        appointments = await repo.list_by_provider_id(
            provider_id, start_date, end_date, status
        )  # Add limit/offset later
    else:
        # Add logic for admin/scheduler listing all (requires pagination)
        appointments = []  # Placeholder
        # raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Listing all appointments requires specific roles/filters.")

    return appointments


@router.put(
    "/{appointment_id}",
    response_model=AppointmentResponse,
    summary="Update Appointment",
    description="Update details or status of an existing appointment.",
    # dependencies=[Depends(require_role("clinician"))] # Or scheduler role
)
async def update_appointment(
    appointment_id: UUID,
    appointment_update: AppointmentUpdate,
    current_user: User = Depends(get_current_user),
    repo: IAppointmentRepository = Depends(get_appointment_repo),
):
    """
    Updates an existing appointment. Allows modifying time, status, location, notes.
    Requires appropriate permissions.
    """

    # Mock get_by_id for update
    async def mock_get_id_for_update(appt_id):
        # Return a mock appointment that can be updated
        from uuid import uuid4

        from app.domain.entities.appointment import Appointment, AppointmentType

        return Appointment(
            id=appt_id,
            patient_id=uuid4(),
            provider_id=uuid4(),
            start_time=now_utc(),
            end_time=now_utc() + timedelta(hours=1),
            appointment_type=AppointmentType.FOLLOW_UP,
        )

    repo.get_by_id = mock_get_id_for_update

    existing_appointment = await repo.get_by_id(appointment_id)
    if not existing_appointment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Appointment not found"
        )

    # TODO: Add authorization: Can current_user update this appointment?

    update_data = appointment_update.model_dump(exclude_unset=True)
    if not update_data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="No update data provided."
        )

    # Apply updates to the entity (simplified)
    updated = False
    for key, value in update_data.items():
        if hasattr(existing_appointment, key):
            setattr(existing_appointment, key, value)
            updated = True

    if not updated:
        return existing_appointment  # No changes applied

    # TODO: Add validation for rescheduling (check overlaps) if time changed

    try:
        # Use entity methods if they exist (e.g., for status change validation)
        if "status" in update_data:
            existing_appointment.update_status(
                update_data["status"]
            )  # Uses entity method
        # Simplified touch logic for mock
        existing_appointment.touch()

        # Mock update response for now
        async def mock_update(appt):
            return appt

        repo.update = mock_update

        updated_appointment = await repo.update(existing_appointment)
        if updated_appointment is None:  # Should not happen with mock
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update appointment",
            )
        return updated_appointment
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except Exception:
        # Log error
        # logger.error(f"Failed to update appointment: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update appointment",
        )


@router.delete(
    "/{appointment_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Cancel Appointment",
    description="Cancel an existing appointment. Typically sets status to 'cancelled'.",
    # dependencies=[Depends(require_role("clinician"))] # Or patient/scheduler
)
async def cancel_appointment(
    appointment_id: UUID,
    current_user: User = Depends(get_current_user),
    repo: IAppointmentRepository = Depends(get_appointment_repo),
):
    """
    Cancels an appointment (sets status to cancelled).
    Requires appropriate permissions. Consider if a hard delete is ever needed.
    """

    # Mock get_by_id for cancel
    async def mock_get_id_for_cancel(appt_id):
        # Return a mock appointment that can be cancelled
        from uuid import uuid4

        from app.domain.entities.appointment import (
            Appointment,
            AppointmentStatus,
            AppointmentType,
        )

        return Appointment(
            id=appt_id,
            patient_id=uuid4(),
            provider_id=uuid4(),
            start_time=now_utc(),
            end_time=now_utc() + timedelta(hours=1),
            appointment_type=AppointmentType.FOLLOW_UP,
            status=AppointmentStatus.SCHEDULED,
        )

    repo.get_by_id = mock_get_id_for_cancel

    existing_appointment = await repo.get_by_id(appointment_id)
    if not existing_appointment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Appointment not found"
        )

    # TODO: Add authorization check

    # Usually, we update status rather than delete
    if existing_appointment.status == AppointmentStatus.CANCELLED:
        return  # Already cancelled

    existing_appointment.update_status(AppointmentStatus.CANCELLED)

    # Mock update for now
    async def mock_update(appt):
        return appt

    repo.update = mock_update

    updated_appointment = await repo.update(existing_appointment)
    if updated_appointment is None:  # Should not happen with mock
        # logger.error(f"Failed to cancel appointment {appointment_id}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to cancel appointment",
        )

    # No content response for successful cancellation/update
    return


# Need uuid4 for mock create and timedelta
from datetime import timedelta
from uuid import uuid4
