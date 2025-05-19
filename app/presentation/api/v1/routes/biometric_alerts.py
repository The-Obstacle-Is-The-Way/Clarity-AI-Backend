"""
Biometric Alerts Endpoints Module.

This module provides REST API endpoints for creating, retrieving, and managing
biometric alerts in a HIPAA-compliant manner with strict security controls
and proper audit logging.
"""


import uuid

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Path,
    Query,
)
from fastapi import status as http_status
from pydantic import UUID4

from app.core.domain.entities.alert import Alert, AlertPriority, AlertStatus, AlertType
from app.core.domain.entities.user import User
from app.core.errors.security_exceptions import InvalidCredentialsError
from app.core.interfaces.services.alert_service_interface import AlertServiceInterface
from app.presentation.api.dependencies.auth import get_current_active_user
from app.presentation.api.dependencies.rate_limiter import sensitive_rate_limit
from app.presentation.api.schemas.alert import (
    AlertCreateRequest,
    AlertResponse,
    AlertsFilterParams,
    AlertUpdateRequest,
)
from app.presentation.api.v1.dependencies.biometric import get_alert_service

# Create router with prefix and tags for OpenAPI documentation
router = APIRouter(
    tags=["biometric-alerts"],
    dependencies=[Depends(sensitive_rate_limit())],  # Apply HIPAA-compliant rate limiting
)


@router.get(
    "",
    response_model=list[AlertResponse],
    summary="Get biometric alerts",
    description="Get a list of biometric alerts with optional filtering",
)
async def get_alerts(
    status_param: AlertStatus
    | None = Query(None, alias="status", description="Filter by alert status"),
    priority: AlertPriority | None = Query(None, description="Filter by alert priority"),
    alert_type: AlertType | None = Query(None, description="Filter by alert type"),
    start_date: str | None = Query(None, description="Filter by start date (ISO format)"),
    end_date: str | None = Query(None, description="Filter by end date (ISO format)"),
    patient_id_str: str
    | None = Query(None, alias="patient_id", description="Patient ID if accessing as provider"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of records to return"),
    offset: int = Query(0, ge=0, description="Number of records to skip"),
    alert_service: AlertServiceInterface = Depends(get_alert_service),
    current_user: User = Depends(get_current_active_user),
) -> list[AlertResponse]:
    """
    Get a list of biometric alerts with optional filtering.

    This endpoint provides alerts for biometric data that require attention,
    such as abnormal readings or critical health indicators. For healthcare
    providers, patient_id can be specified to access a patient's alerts.

    Args:
        status: Optional filter by alert status
        priority: Optional filter by alert priority
        alert_type: Optional filter by alert type
        start_date: Optional filter by start date
        end_date: Optional filter by end date
        patient_id: Optional patient ID when accessed by a provider
        limit: Maximum number of records to return
        offset: Number of records to skip
        alert_service: Injected alert service
        current_user: Current authenticated user

    Returns:
        List of alert data

    Raises:
        HTTPException: If user is not authorized to access this data
    """
    try:
        patient_id: uuid.UUID | None = None
        if patient_id_str:
            try:
                patient_id = uuid.UUID(patient_id_str, version=4)
            except ValueError:
                raise HTTPException(
                    status_code=http_status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"Invalid patient_id format: Must be a valid UUIDv4. Received: {patient_id_str}",
                )

        # Determine if request is for self or for a patient (provider access)
        subject_id = str(patient_id) if patient_id else current_user.id

        # Check authorization if requesting patient data
        if patient_id and patient_id != current_user.id:
            # This will raise an exception if not authorized
            await alert_service.validate_access(current_user.id, str(patient_id))

        # Convert filter params
        filters = AlertsFilterParams(
            status=status_param,
            priority=priority,
            alert_type=alert_type,
            start_date=start_date,
            end_date=end_date,
        )

        # Get alerts from service
        alerts = await alert_service.get_alerts(
            subject_id=subject_id, filters=filters, limit=limit, offset=offset
        )

        # Convert to response model
        return [
            AlertResponse(
                id=alert.id,
                alert_type=alert.alert_type,
                timestamp=alert.timestamp,
                status=alert.status,
                priority=alert.priority,
                message=alert.message,
                data=alert.data,
                user_id=alert.user_id,
                resolved_at=alert.resolved_at,
                resolution_notes=alert.resolution_notes,
            )
            for alert in alerts
        ]

    except InvalidCredentialsError as e:
        raise HTTPException(
            status_code=http_status.HTTP_401_UNAUTHORIZED,
            detail="Not authorized to access this patient's alert data",
        ) from e
    except Exception as e:
        # Log the exception but don't expose details in response
        # This is for HIPAA compliance
        raise HTTPException(
            status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred processing the alerts request",
        ) from e


@router.get(
    "/{alert_id}",
    response_model=AlertResponse,
    summary="Get single alert",
    description="Get detailed information for a specific alert by ID",
)
async def get_alert(
    alert_id: UUID4 = Path(..., description="Alert ID"),
    alert_service: AlertServiceInterface = Depends(get_alert_service),
    current_user: User = Depends(get_current_active_user),
) -> AlertResponse:
    """
    Get detailed information for a specific alert.

    Args:
        alert_id: ID of the alert to retrieve
        alert_service: Injected alert service
        current_user: Current authenticated user

    Returns:
        Detailed alert data

    Raises:
        HTTPException: If record not found or user not authorized
    """
    try:
        # Get the alert (includes access validation)
        alert = await alert_service.get_alert_by_id(alert_id=str(alert_id), user_id=current_user.id)

        if not alert:
            raise HTTPException(
                status_code=http_status.HTTP_404_NOT_FOUND, detail="Alert not found"
            )

        # Convert to response model
        return AlertResponse(
            id=alert.id,
            alert_type=alert.alert_type,
            timestamp=alert.timestamp,
            status=alert.status,
            priority=alert.priority,
            message=alert.message,
            data=alert.data,
            user_id=alert.user_id,
            resolved_at=alert.resolved_at,
            resolution_notes=alert.resolution_notes,
        )

    except InvalidCredentialsError as e:
        raise HTTPException(
            status_code=http_status.HTTP_401_UNAUTHORIZED,
            detail="Not authorized to access this alert",
        ) from e
    except Exception as e:
        # HIPAA-compliant error handling
        raise HTTPException(
            status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred retrieving the alert",
        ) from e


@router.post(
    "",
    response_model=AlertResponse,
    status_code=http_status.HTTP_201_CREATED,
    summary="Create alert",
    description="Create a new biometric alert",
)
async def create_alert(
    alert_data: AlertCreateRequest,
    alert_service: AlertServiceInterface = Depends(get_alert_service),
    current_user: User = Depends(get_current_active_user),
) -> AlertResponse:
    """
    Create a new biometric alert.

    Args:
        alert_data: Data for the new alert
        alert_service: Injected alert service
        current_user: Current authenticated user

    Returns:
        The created alert

    Raises:
        HTTPException: If validation fails or an error occurs
    """
    try:
        # Create domain entity from request data
        alert = Alert(
            id=None,  # Will be generated
            alert_type=alert_data.alert_type,
            timestamp=alert_data.timestamp,
            status=AlertStatus.OPEN,  # New alerts are always open
            priority=alert_data.priority,
            message=alert_data.message,
            data=alert_data.data or {},
            user_id=alert_data.patient_id or current_user.id,
            resolved_at=None,
            resolution_notes=None,
        )

        # Check if user has permissions to create an alert for this patient
        if alert_data.patient_id and alert_data.patient_id != current_user.id:
            await alert_service.validate_access(current_user.id, alert_data.patient_id)

        # Create the alert
        created_alert = await alert_service.create_alert(alert)

        # Convert to response model
        return AlertResponse(
            id=created_alert.id,
            alert_type=created_alert.alert_type,
            timestamp=created_alert.timestamp,
            status=created_alert.status,
            priority=created_alert.priority,
            message=created_alert.message,
            data=created_alert.data,
            user_id=created_alert.user_id,
            resolved_at=created_alert.resolved_at,
            resolution_notes=created_alert.resolution_notes,
        )

    except InvalidCredentialsError as e:
        raise HTTPException(
            status_code=http_status.HTTP_401_UNAUTHORIZED,
            detail="Not authorized to create an alert for this patient",
        ) from e
    except ValueError as e:
        raise HTTPException(status_code=http_status.HTTP_400_BAD_REQUEST, detail=str(e)) from e
    except Exception as e:
        # HIPAA-compliant error handling
        raise HTTPException(
            status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred creating the alert",
        ) from e


@router.put(
    "/{alert_id}",
    response_model=AlertResponse,
    summary="Update alert",
    description="Update an existing alert",
)
async def update_alert(
    alert_id: UUID4 = Path(..., description="Alert ID"),
    alert_data: AlertUpdateRequest = None,
    alert_service: AlertServiceInterface = Depends(get_alert_service),
    current_user: User = Depends(get_current_active_user),
) -> AlertResponse:
    """
    Update an existing alert.

    Args:
        alert_id: ID of the alert to update
        alert_data: Updated data for the alert
        alert_service: Injected alert service
        current_user: Current authenticated user

    Returns:
        The updated alert

    Raises:
        HTTPException: If record not found, validation fails, or user not authorized
    """
    try:
        # Check if alert exists and user has access
        existing_alert = await alert_service.get_alert_by_id(
            alert_id=str(alert_id), user_id=current_user.id
        )

        if not existing_alert:
            raise HTTPException(
                status_code=http_status.HTTP_404_NOT_FOUND, detail="Alert not found"
            )

        # Update the alert with new data
        updated_alert = Alert(
            id=str(alert_id),
            alert_type=existing_alert.alert_type,  # Alert type cannot be changed
            timestamp=existing_alert.timestamp,  # Original timestamp preserved
            status=alert_data.status or existing_alert.status,
            priority=alert_data.priority or existing_alert.priority,
            message=alert_data.message or existing_alert.message,
            data=alert_data.data or existing_alert.data,
            user_id=existing_alert.user_id,  # User ID cannot be changed
            resolved_at=alert_data.resolved_at
            if alert_data.status == AlertStatus.RESOLVED
            else existing_alert.resolved_at,
            resolution_notes=alert_data.resolution_notes or existing_alert.resolution_notes,
        )

        # Update the alert
        result = await alert_service.update_alert(updated_alert)

        # Convert to response model
        return AlertResponse(
            id=result.id,
            alert_type=result.alert_type,
            timestamp=result.timestamp,
            status=result.status,
            priority=result.priority,
            message=result.message,
            data=result.data,
            user_id=result.user_id,
            resolved_at=result.resolved_at,
            resolution_notes=result.resolution_notes,
        )

    except InvalidCredentialsError as e:
        raise HTTPException(
            status_code=http_status.HTTP_401_UNAUTHORIZED,
            detail="Not authorized to update this alert",
        ) from e
    except ValueError as e:
        raise HTTPException(status_code=http_status.HTTP_400_BAD_REQUEST, detail=str(e)) from e
    except Exception as e:
        # HIPAA-compliant error handling
        raise HTTPException(
            status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred updating the alert",
        ) from e


@router.delete(
    "/{alert_id}",
    status_code=http_status.HTTP_204_NO_CONTENT,
    summary="Delete alert",
    description="Delete a specific alert by ID",
)
async def delete_alert(
    alert_id: UUID4 = Path(..., description="Alert ID"),
    alert_service: AlertServiceInterface = Depends(get_alert_service),
    current_user: User = Depends(get_current_active_user),
) -> None:
    """
    Delete a specific alert.

    Args:
        alert_id: ID of the alert to delete
        alert_service: Injected alert service
        current_user: Current authenticated user

    Raises:
        HTTPException: If record not found or user not authorized
    """
    try:
        # Check if alert exists and user has access
        existing_alert = await alert_service.get_alert_by_id(
            alert_id=str(alert_id), user_id=current_user.id
        )

        if not existing_alert:
            raise HTTPException(
                status_code=http_status.HTTP_404_NOT_FOUND, detail="Alert not found"
            )

        # Check if user has admin rights for alert deletion
        if not await alert_service.can_delete_alert(current_user.id, str(alert_id)):
            raise HTTPException(
                status_code=http_status.HTTP_403_FORBIDDEN,
                detail="Not authorized to delete this alert",
            )

        # Delete the alert
        success = await alert_service.delete_alert(alert_id=str(alert_id))

        if not success:
            raise HTTPException(
                status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to delete alert",
            )

    except InvalidCredentialsError as e:
        raise HTTPException(
            status_code=http_status.HTTP_401_UNAUTHORIZED,
            detail="Not authorized to delete this alert",
        ) from e
    except Exception as e:
        # HIPAA-compliant error handling
        raise HTTPException(
            status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred deleting the alert",
        ) from e
