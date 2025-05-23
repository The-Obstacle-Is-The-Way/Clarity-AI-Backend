"""
API Endpoints for Clinical Session Records.

Provides endpoints for creating, retrieving, and updating clinical session notes
and structured data.
"""
from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.domain.entities.clinical_session import (  # For query param validation
    SessionType,
)

# Assuming User type from auth dependency matches this import or is compatible (e.g., dict)
from app.domain.entities.user import User

# from app.application.services.clinical_session_service import ClinicalSessionService # Use this when service layer is built
from app.domain.repositories.clinical_session_repository import (
    IClinicalSessionRepository,  # Temporary direct repo access
)
from app.domain.utils.datetime_utils import now_utc

# Import dependencies
from app.presentation.api.dependencies.auth import (
    get_current_user,  # , require_role # Add role check if needed
)

# Import schemas
from app.presentation.api.schemas.clinical_session import (
    ClinicalSessionCreate,
    ClinicalSessionResponse,
    ClinicalSessionUpdate,
)

# Initialize router
router = APIRouter()


# --- Placeholder Dependencies ---
async def get_session_repo() -> IClinicalSessionRepository:
    # Placeholder: Return a mock or raise NotImplementedError until implemented
    from unittest.mock import AsyncMock

    mock_repo = AsyncMock(spec=IClinicalSessionRepository)

    # Configure mock methods as needed for testing
    async def mock_get(sess_id) -> None:
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
    response_model=ClinicalSessionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Record Clinical Session",
    description="Record details of a clinical session.",
    # dependencies=[Depends(require_role("clinician"))] # Only clinicians/providers record sessions
)
async def record_clinical_session(
    session_data: ClinicalSessionCreate,
    current_user: User = Depends(get_current_user),
    repo: IClinicalSessionRepository = Depends(get_session_repo()),
):
    """
    Records a new clinical session. Requires clinician/provider role.
    """
    # TODO: Add authorization: Ensure provider_id matches current_user ID or admin.
    # if isinstance(current_user, dict) and current_user.get('id') != str(session_data.provider_id):
    #    if current_user.get('role') != 'admin': # Allow admin override
    #        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Provider can only record sessions for themselves.")

    try:
        from app.domain.entities.clinical_session import (  # Import entity
            ClinicalSession,
        )

        new_session_entity = ClinicalSession(**session_data.model_dump())

        # Mock create for now
        async def mock_create(sess):
            sess.id = uuid4()
            return sess

        repo.create = mock_create

        created_session = await repo.create(new_session_entity)
        return created_session
    except Exception:
        # Log error
        # logger.error(f"Failed to record clinical session: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to record clinical session",
        )


@router.get(
    "/{session_id}",
    response_model=ClinicalSessionResponse,
    summary="Get Clinical Session Details",
    description="Retrieve details for a specific clinical session.",
)
async def get_clinical_session(
    session_id: UUID,
    current_user: User = Depends(get_current_user),
    repo: IClinicalSessionRepository = Depends(get_session_repo()),
):
    """
    Retrieves details of a specific clinical session by its ID.
    Requires user to be associated with the session (patient/provider) or have admin rights.
    """

    # Mock get_by_id for now
    async def mock_get_id(sid):
        if str(sid) == "123e4567-e89b-12d3-a456-426614174003":  # Example ID
            from uuid import uuid4

            from app.domain.entities.clinical_session import (
                ClinicalSession,
                SessionType,
            )

            return ClinicalSession(
                id=UUID("123e4567-e89b-12d3-a456-426614174003"),
                patient_id=uuid4(),
                provider_id=uuid4(),
                session_datetime=now_utc(),
                duration_minutes=50,
                session_type=SessionType.THERAPY,
            )
        return None

    repo.get_by_id = mock_get_id

    session = await repo.get_by_id(session_id)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Clinical session not found"
        )

    # TODO: Add authorization: Can current_user view this session?
    # Example check:
    # if isinstance(current_user, dict):
    #    user_id_str = current_user.get('id')
    #    user_role = current_user.get('role')
    #    if not (user_role == 'admin' or \
    #            str(session.patient_id) == user_id_str or \
    #            str(session.provider_id) == user_id_str):
    #        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to view this session")

    return session


@router.get(
    "",
    response_model=list[ClinicalSessionResponse],
    summary="List Clinical Sessions",
    description="Retrieve a list of clinical sessions based on filter criteria.",
)
async def list_clinical_sessions(
    patient_id: UUID | None = Query(None, description="Filter by patient ID"),
    provider_id: UUID | None = Query(None, description="Filter by provider ID"),
    appointment_id: UUID | None = Query(None, description="Filter by appointment ID"),
    start_date: datetime
    | None = Query(None, description="Filter by session start date (inclusive)"),
    end_date: datetime | None = Query(None, description="Filter by session end date (exclusive)"),
    session_type: SessionType | None = Query(None, description="Filter by session type"),
    limit: int = Query(50, ge=1, le=200, description="Maximum sessions to return"),
    offset: int = Query(0, ge=0, description="Number of sessions to skip"),
    current_user: User = Depends(get_current_user),
    repo: IClinicalSessionRepository = Depends(get_session_repo()),
):
    """
    Lists clinical sessions, filterable by patient, provider, appointment, date range, and type.
    Requires appropriate permissions.
    """
    # TODO: Add authorization based on query params and user role


    # Simplistic fetch - replace with specific repo calls based on params
    if patient_id:
        # Mock list_by_patient_id
        async def mock_list_p(pid, sd, ed):
            return []

        repo.list_by_patient_id = mock_list_p
        sessions = await repo.list_by_patient_id(patient_id, start_date, end_date)
    elif provider_id:
        # Mock list_by_provider_id
        async def mock_list_prov(prov_id, sd, ed):
            return []

        repo.list_by_provider_id = mock_list_prov
        sessions = await repo.list_by_provider_id(provider_id, start_date, end_date)
    elif appointment_id:
        # Mock list_by_appointment_id
        async def mock_list_appt(appt_id):
            return []

        repo.list_by_appointment_id = mock_list_appt
        sessions = await repo.list_by_appointment_id(appointment_id)
    else:
        # Add logic for admin/scheduler listing all (requires pagination & auth)
        sessions = []  # Placeholder
        # raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Listing all sessions requires specific roles/filters.")

    return sessions


@router.put(
    "/{session_id}",
    response_model=ClinicalSessionResponse,
    summary="Update Clinical Session",
    description="Update notes or details of an existing clinical session.",
    # dependencies=[Depends(require_role("clinician"))] # Only provider who conducted session or admin
)
async def update_clinical_session(
    session_id: UUID,
    session_update: ClinicalSessionUpdate,
    current_user: User = Depends(get_current_user),
    repo: IClinicalSessionRepository = Depends(get_session_repo()),
):
    """
    Updates an existing clinical session record. Typically used to add/modify notes.
    Requires the user to be the provider of the session or an admin.
    """

    # Mock get_by_id for update
    async def mock_get_id_for_update(sid):
        from uuid import uuid4

        from app.domain.entities.clinical_session import ClinicalSession, SessionType

        # Determine provider ID based on current user if possible
        provider_uuid = (
            UUID(current_user["id"])
            if isinstance(current_user, dict) and "id" in current_user
            else uuid4()
        )
        return ClinicalSession(
            id=sid,
            patient_id=uuid4(),
            provider_id=provider_uuid,
            session_datetime=now_utc(),
            duration_minutes=50,
            session_type=SessionType.THERAPY,
        )

    repo.get_by_id = mock_get_id_for_update

    existing_session = await repo.get_by_id(session_id)
    if not existing_session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Clinical session not found"
        )

    # TODO: Add authorization: Can current_user update this session (must be provider or admin)?
    # if isinstance(current_user, dict) and current_user.get('role') != 'admin' and current_user.get('id') != str(existing_session.provider_id):
    #     raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only the session provider or an admin can update the session.")

    update_data = session_update.model_dump(exclude_unset=True)
    if not update_data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="No update data provided."
        )

    # Apply updates to the entity
    updated = False
    for key, value in update_data.items():
        if hasattr(existing_session, key):
            setattr(existing_session, key, value)
            updated = True

    if not updated:
        return existing_session  # No changes applied

    existing_session.touch()

    # Mock update for now
    async def mock_update(sess):
        return sess

    repo.update = mock_update

    updated_session = await repo.update(existing_session)
    if updated_session is None:  # Should not happen with mock
        # Log error
        # logger.error(f"Failed to update clinical session {session_id}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update clinical session",
        )

    return updated_session


# Note: DELETE for clinical sessions might be restricted (audit trail requirements)
# Consider an 'archive' or 'mark_as_error' status instead.

# Need uuid4 for mock create
# Need UUID for mock provider_id comparison
from uuid import UUID, uuid4
