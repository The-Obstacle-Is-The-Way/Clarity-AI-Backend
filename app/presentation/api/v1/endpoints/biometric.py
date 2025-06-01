"""
Biometric data API endpoints.

This module provides Clean Architecture compliant endpoints for recording, retrieving, 
and analyzing patient biometric data across various measurement types.
"""

from datetime import datetime
from typing import Any, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status

from app.core.domain.entities.user import User
from app.core.interfaces.services.biometric_service_interface import IBiometricService
from app.core.utils.date_utils import utcnow
from app.core.utils.logging import get_logger
from app.presentation.api.dependencies.auth import get_current_active_user, get_current_user
from app.presentation.api.dependencies.biometric import get_biometric_service
from app.presentation.schemas.biometric import (
    BiometricCreateRequest,
    BiometricDataPoint,
    BiometricListResponse,
    BiometricResponse,
)

logger = get_logger(__name__)

# Create router without prefix - prefix will be added in api_router.py
router = APIRouter()


@router.get("/", response_model=BiometricListResponse)
async def get_biometrics(
    biometric_type: Optional[str] = Query(None, description="Filter by biometric type"),
    start_date: Optional[datetime] = Query(None, description="Start date for filtering"),
    end_date: Optional[datetime] = Query(None, description="End date for filtering"),
    limit: int = Query(100, description="Maximum number of records to return"),
    offset: int = Query(0, description="Number of records to skip"),
    current_user: User = Depends(get_current_active_user),
    biometric_service: IBiometricService = Depends(get_biometric_service),
) -> BiometricListResponse:
    """
    Retrieve a list of biometric measurements with optional filtering.
    
    This endpoint supports filtering by biometric type and date range,
    as well as pagination through limit and offset parameters.
    
    Args:
        biometric_type: Optional filter for specific biometric type
        start_date: Optional filter for measurements after this date
        end_date: Optional filter for measurements before this date
        limit: Maximum number of records to return (default: 100)
        offset: Number of records to skip (default: 0)
        current_user: The authenticated user making the request
        biometric_service: Service for biometric data operations
        
    Returns:
        List of biometric data points matching the criteria
        
    Raises:
        HTTPException: If there's an error retrieving the data
    """
    try:
        logger.info(
            "Retrieving biometrics with filters: type=%s, start=%s, end=%s, limit=%d, offset=%d",
            biometric_type, start_date, end_date, limit, offset
        )
        
        # Check if user has appropriate role/permissions
        if not current_user.has_permission("biometrics:read"):
            logger.warning(
                "User %s attempted to access biometrics without permission", 
                current_user.id
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to access biometric data"
            )
        
        biometrics = await biometric_service.get_biometrics(
            biometric_type=biometric_type,
            start_date=start_date,
            end_date=end_date,
            limit=limit,
            offset=offset,
            user_id=current_user.id
        )
        
        return BiometricListResponse(
            items=biometrics,
            total=len(biometrics),
            limit=limit,
            offset=offset
        )
        
    except Exception as e:
        logger.error("Error retrieving biometrics: %s", str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error retrieving biometric data"
        )


@router.get("/{biometric_id}", response_model=BiometricResponse)
async def get_biometric(
    biometric_id: UUID = Path(..., description="UUID of the biometric data point"),
    current_user: User = Depends(get_current_active_user),
    biometric_service: IBiometricService = Depends(get_biometric_service),
) -> BiometricResponse:
    """
    Retrieve a specific biometric measurement by ID.
    
    Args:
        biometric_id: UUID of the biometric data point
        current_user: The authenticated user making the request
        biometric_service: Service for biometric data operations
        
    Returns:
        Biometric data point matching the ID
        
    Raises:
        HTTPException: If the biometric data point is not found or the user lacks permission
    """
    try:
        logger.info("Retrieving biometric with ID: %s", biometric_id)
        
        # Check if user has appropriate role/permissions
        if not current_user.has_permission("biometrics:read"):
            logger.warning(
                "User %s attempted to access biometric %s without permission", 
                current_user.id, biometric_id
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to access biometric data"
            )
        
        biometric = await biometric_service.get_biometric(biometric_id)
        
        if not biometric:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Biometric with ID {biometric_id} not found"
            )
            
        # Check if user is authorized to view this specific biometric
        if not current_user.has_permission("biometrics:read:all") and biometric.patient_id != current_user.id:
            logger.warning(
                "User %s attempted to access biometric %s for another patient", 
                current_user.id, biometric_id
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to access this biometric data point"
            )
            
        return BiometricResponse(
            biometric=biometric,
            meta={"requested_at": utcnow()}
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error retrieving biometric %s: %s", biometric_id, str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error retrieving biometric data"
        )


@router.post("/", response_model=BiometricResponse, status_code=status.HTTP_201_CREATED)
async def create_biometric(
    biometric_data: BiometricCreateRequest,
    current_user: User = Depends(get_current_active_user),
    biometric_service: IBiometricService = Depends(get_biometric_service),
) -> BiometricResponse:
    """
    Record a new biometric measurement.
    
    Args:
        biometric_data: Data for the new biometric measurement
        current_user: The authenticated user making the request
        biometric_service: Service for biometric data operations
        
    Returns:
        Newly created biometric data point
        
    Raises:
        HTTPException: If there's an error creating the data point or the user lacks permission
    """
    try:
        logger.info(
            "Creating biometric: type=%s, patient_id=%s", 
            biometric_data.biometric_type, biometric_data.patient_id
        )
        
        # Check if user has appropriate role/permissions
        if not current_user.has_permission("biometrics:create"):
            logger.warning(
                "User %s attempted to create biometric without permission", 
                current_user.id
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to create biometric data"
            )
            
        # Check if user is authorized to create biometric for this patient
        if (not current_user.has_permission("biometrics:create:all") and 
            biometric_data.patient_id != current_user.id):
            logger.warning(
                "User %s attempted to create biometric for another patient %s", 
                current_user.id, biometric_data.patient_id
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to create biometric data for this patient"
            )
            
        # Add timestamp if not provided
        if not biometric_data.timestamp:
            biometric_data.timestamp = utcnow()
            
        biometric = await biometric_service.create_biometric(biometric_data)
        
        return BiometricResponse(
            biometric=biometric,
            meta={"created_at": utcnow()}
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error creating biometric: %s", str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error creating biometric data"
        )


@router.get("/patients/{patient_id}", response_model=BiometricListResponse)
async def get_patient_biometrics(
    patient_id: UUID = Path(..., description="UUID of the patient"),
    biometric_type: Optional[str] = Query(None, description="Filter by biometric type"),
    start_date: Optional[datetime] = Query(None, description="Start date for filtering"),
    end_date: Optional[datetime] = Query(None, description="End date for filtering"),
    limit: int = Query(100, description="Maximum number of records to return"),
    offset: int = Query(0, description="Number of records to skip"),
    current_user: User = Depends(get_current_active_user),
    biometric_service: IBiometricService = Depends(get_biometric_service),
) -> BiometricListResponse:
    """
    Retrieve all biometric measurements for a specific patient with optional filtering.
    
    Args:
        patient_id: UUID of the patient
        biometric_type: Optional filter for specific biometric type
        start_date: Optional filter for measurements after this date
        end_date: Optional filter for measurements before this date
        limit: Maximum number of records to return (default: 100)
        offset: Number of records to skip (default: 0)
        current_user: The authenticated user making the request
        biometric_service: Service for biometric data operations
        
    Returns:
        List of biometric data points for the patient matching the criteria
        
    Raises:
        HTTPException: If there's an error retrieving the data or the user lacks permission
    """
    try:
        logger.info(
            "Retrieving biometrics for patient %s with filters: type=%s, start=%s, end=%s", 
            patient_id, biometric_type, start_date, end_date
        )
        
        # Check if user has appropriate role/permissions
        if not current_user.has_permission("biometrics:read"):
            logger.warning(
                "User %s attempted to access patient biometrics without permission", 
                current_user.id
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to access biometric data"
            )
            
        # Check if user is authorized to view this patient's biometrics
        if (not current_user.has_permission("biometrics:read:all") and 
            patient_id != current_user.id):
            logger.warning(
                "User %s attempted to access biometrics for another patient %s", 
                current_user.id, patient_id
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to access biometric data for this patient"
            )
            
        biometrics = await biometric_service.get_patient_biometrics(
            patient_id=patient_id,
            biometric_type=biometric_type,
            start_date=start_date,
            end_date=end_date,
            limit=limit,
            offset=offset
        )
        
        return BiometricListResponse(
            items=biometrics,
            total=len(biometrics),
            limit=limit,
            offset=offset
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error retrieving patient biometrics: %s", str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error retrieving biometric data"
        )


@router.get("/patients/{patient_id}/types/{biometric_type}", response_model=BiometricListResponse)
async def get_patient_biometric_type(
    patient_id: UUID = Path(..., description="UUID of the patient"),
    biometric_type: str = Path(..., description="Type of biometric measurement"),
    start_date: Optional[datetime] = Query(None, description="Start date for filtering"),
    end_date: Optional[datetime] = Query(None, description="End date for filtering"),
    limit: int = Query(100, description="Maximum number of records to return"),
    offset: int = Query(0, description="Number of records to skip"),
    current_user: User = Depends(get_current_active_user),
    biometric_service: IBiometricService = Depends(get_biometric_service),
) -> BiometricListResponse:
    """
    Retrieve biometric measurements of a specific type for a patient.
    
    Args:
        patient_id: UUID of the patient
        biometric_type: Type of biometric measurement
        start_date: Optional filter for measurements after this date
        end_date: Optional filter for measurements before this date
        limit: Maximum number of records to return (default: 100)
        offset: Number of records to skip (default: 0)
        current_user: The authenticated user making the request
        biometric_service: Service for biometric data operations
        
    Returns:
        List of biometric data points of the specified type for the patient
        
    Raises:
        HTTPException: If there's an error retrieving the data or the user lacks permission
    """
    try:
        logger.info(
            "Retrieving %s biometrics for patient %s with date range: %s to %s", 
            biometric_type, patient_id, start_date, end_date
        )
        
        # Check if user has appropriate role/permissions
        if not current_user.has_permission("biometrics:read"):
            logger.warning(
                "User %s attempted to access patient biometrics without permission", 
                current_user.id
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to access biometric data"
            )
            
        # Check if user is authorized to view this patient's biometrics
        if (not current_user.has_permission("biometrics:read:all") and 
            patient_id != current_user.id):
            logger.warning(
                "User %s attempted to access biometrics for another patient %s", 
                current_user.id, patient_id
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to access biometric data for this patient"
            )
            
        biometrics = await biometric_service.get_patient_biometrics(
            patient_id=patient_id,
            biometric_type=biometric_type,
            start_date=start_date,
            end_date=end_date,
            limit=limit,
            offset=offset
        )
        
        return BiometricListResponse(
            items=biometrics,
            total=len(biometrics),
            limit=limit,
            offset=offset
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Error retrieving %s biometrics for patient %s: %s", 
            biometric_type, patient_id, str(e)
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error retrieving biometric data"
        )
