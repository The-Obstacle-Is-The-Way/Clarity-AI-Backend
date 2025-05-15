"""
Biometric Alerts API endpoints.

This module implements API endpoints for managing biometric alerts,
following clean architecture principles with proper separation of concerns.
"""

import logging
from typing import List, Optional
from uuid import UUID
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from pydantic import BaseModel, Field

from app.core.domain.entities.alert import Alert, AlertPriority, AlertStatus, AlertType
from app.core.domain.entities.user import User
from app.presentation.api.dependencies.auth import get_current_active_user
from app.presentation.api.schemas.alert import (
    AlertCreateRequest,
    AlertResponse,
    AlertsFilterParams,
    AlertUpdateRequest,
)
from app.core.interfaces.services.alert_service_interface import AlertServiceInterface
from app.presentation.api.v1.dependencies.biometric import get_alert_service

logger = logging.getLogger(__name__)

router = APIRouter(
    tags=["Biometric Alerts"],
)

@router.get("", response_model=List[AlertResponse])
async def get_alerts(
    status_param: Optional[AlertStatus] = Query(None, alias="status", description="Filter by alert status"),
    priority: Optional[AlertPriority] = Query(None, description="Filter by alert priority"),
    alert_type: Optional[AlertType] = Query(None, description="Filter by alert type"),
    start_date: Optional[str] = Query(None, description="Filter by start date (ISO format)"),
    end_date: Optional[str] = Query(None, description="Filter by end date (ISO format)"),
    patient_id: Optional[UUID] = Query(None, description="Patient ID if accessing as provider"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of records to return"),
    offset: int = Query(0, ge=0, description="Number of records to skip"),
    alert_service: AlertServiceInterface = Depends(get_alert_service),
    current_user: User = Depends(get_current_active_user)
) -> List[AlertResponse]:
    """
    Get a list of biometric alerts with optional filtering.
    
    This endpoint provides alerts for biometric data that require attention,
    such as abnormal readings or critical health indicators. For healthcare 
    providers, patient_id can be specified to access a patient's alerts.
    
    Args:
        status_param: Optional filter by alert status
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
        # Determine if request is for self or for a patient (provider access)
        subject_id = str(patient_id) if patient_id else current_user.id
        
        # Check authorization if requesting patient data
        if patient_id and str(patient_id) != current_user.id:
            # This will raise an exception if not authorized
            await alert_service.validate_access(current_user.id, str(patient_id))
            
        # Convert filter params
        filters = AlertsFilterParams(
            status=status_param,
            priority=priority,
            alert_type=alert_type,
            start_date=start_date,
            end_date=end_date
        )
        
        # Get alerts from service
        alerts = await alert_service.get_alerts(
            subject_id=subject_id,
            filters=filters,
            limit=limit,
            offset=offset
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
                resolution_notes=alert.resolution_notes
            )
            for alert in alerts
        ]
        
    except Exception as e:
        logger.error(f"Error getting alerts: {str(e)}")
        # HIPAA-compliant error handling - don't expose internal error details
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while retrieving alerts"
        )

@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: UUID = Path(..., description="Alert ID"),
    alert_service: AlertServiceInterface = Depends(get_alert_service),
    current_user: User = Depends(get_current_active_user)
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
        alert = await alert_service.get_alert_by_id(
            alert_id=str(alert_id),
            user_id=current_user.id
        )
        
        if not alert:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Alert not found"
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
            resolution_notes=alert.resolution_notes
        )
        
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        logger.error(f"Error getting alert {alert_id}: {str(e)}")
        # HIPAA-compliant error handling
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred retrieving the alert"
        ) 