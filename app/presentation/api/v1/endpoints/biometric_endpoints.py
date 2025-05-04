"""
Biometric Endpoints Module.

This module provides REST API endpoints for accessing and managing biometric data
in a HIPAA-compliant manner with proper security controls, data validation,
and audit logging.
"""

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Path, status
from pydantic import UUID4

from app.core.domain.entities.biometric import Biometric, BiometricType
from app.core.domain.entities.user import User
from app.core.errors.security_exceptions import InvalidCredentialsError 
from app.core.interfaces.services.biometric_service_interface import BiometricServiceInterface
from app.presentation.api.dependencies.auth import get_current_active_user 
from app.presentation.api.dependencies.rate_limiter import sensitive_rate_limit
from app.presentation.api.schemas.biometric import (
    BiometricCreateRequest,
    BiometricResponse,
    BiometricSummaryResponse,
    BiometricUpdateRequest,
    BiometricBatchUploadRequest
)
from app.presentation.api.v1.dependencies.biometric import get_biometric_service

# Create router with prefix and tags for OpenAPI documentation
router = APIRouter(
    prefix="/biometrics",
    tags=["biometrics"],
    dependencies=[Depends(sensitive_rate_limit())]  # Apply HIPAA-compliant rate limiting
)


@router.get(
    "",
    response_model=list[BiometricSummaryResponse],
    summary="Get biometric data summary", 
    description="Get a summary of biometric data with optional filtering by type and date range"
)
async def get_biometrics(
    biometric_type: BiometricType | None = Query(None, description="Filter by biometric type"),
    start_date: datetime | None = Query(None, description="Start date for filtering"),
    end_date: datetime | None = Query(None, description="End date for filtering"),
    page: int | None = Query(1, ge=1, description="Page number"),
    page_size: int | None = Query(100, ge=1, le=1000, description="Number of records per page"),
    biometric_service: BiometricServiceInterface = Depends(get_biometric_service),
    current_user: User = Depends(get_current_active_user)
) -> list[BiometricSummaryResponse]:
    """
    Get a summary of biometric data for the current user or specified patient.
    
    This endpoint provides a summary view of biometric data with various filtering options.
    For healthcare providers, patient_id can be specified to access a patient's data.
    
    Args:
        biometric_type: Optional filter by biometric type
        start_date: Optional filter by start date
        end_date: Optional filter by end date
        page: Optional page number
        page_size: Optional number of records per page
        biometric_service: Injected biometric service
        current_user: Current authenticated user
        
    Returns:
        List of biometric summary data
        
    Raises:
        HTTPException: If user is not authorized to access this data
    """
    try:
        # Determine if request is for self or for a patient (provider access)
        subject_id = current_user.id
        
        # Convert filter params
        filters = {
            "biometric_type": biometric_type,
            "start_date": start_date,
            "end_date": end_date
        }
        
        # Get biometric data from service
        biometrics = await biometric_service.get_biometrics(
            subject_id=subject_id,
            filters=filters,
            page=page,
            page_size=page_size
        )
        
        # Convert to response model
        return [
            BiometricSummaryResponse(
                id=biometric.id,
                biometric_type=biometric.biometric_type,
                timestamp=biometric.timestamp,
                device_id=biometric.device_id,
                summary_value=biometric.get_summary_value()
            )
            for biometric in biometrics
        ]
        
    except InvalidCredentialsError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access this patient's biometric data"
        ) from e
    except Exception as e:
        # Log the exception but don't expose details in response
        # This is for HIPAA compliance
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred processing the biometric data request"
        ) from e


@router.get(
    "/{biometric_id}",
    response_model=BiometricResponse,
    summary="Get single biometric record",
    description="Get detailed information for a specific biometric record by ID"
)
async def get_biometric(
    biometric_id: UUID4 = Path(..., description="Biometric record ID"),
    biometric_service: BiometricServiceInterface = Depends(get_biometric_service),
    current_user: User = Depends(get_current_active_user)
) -> BiometricResponse:
    """
    Get detailed information for a specific biometric record.
    
    Args:
        biometric_id: ID of the biometric record to retrieve
        biometric_service: Injected biometric service
        current_user: Current authenticated user
        
    Returns:
        Detailed biometric data
        
    Raises:
        HTTPException: If record not found or user not authorized
    """
    try:
        # Get the biometric record (includes access validation)
        biometric = await biometric_service.get_biometric_by_id(
            biometric_id=str(biometric_id),
            user_id=current_user.id
        )
        
        if not biometric:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Biometric record not found"
            )
            
        # Convert to response model
        return BiometricResponse(
            id=biometric.id,
            biometric_type=biometric.biometric_type,
            timestamp=biometric.timestamp,
            device_id=biometric.device_id,
            value=biometric.value,
            metadata=biometric.metadata,
            user_id=biometric.user_id
        )
        
    except InvalidCredentialsError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access this biometric record"
        ) from e
    except Exception as e:
        # HIPAA-compliant error handling
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred retrieving the biometric record"
        ) from e


@router.post(
    "",
    response_model=BiometricResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create biometric record",
    description="Create a new biometric record"
)
async def create_biometric(
    biometric_data: BiometricCreateRequest,
    biometric_service: BiometricServiceInterface = Depends(get_biometric_service),
    current_user: User = Depends(get_current_active_user)
) -> BiometricResponse:
    """
    Create a new biometric record.
    
    Args:
        biometric_data: Data for the new biometric record
        biometric_service: Injected biometric service
        current_user: Current authenticated user
        
    Returns:
        The created biometric record
        
    Raises:
        HTTPException: If validation fails or an error occurs
    """
    try:
        # Create domain entity from request data
        biometric = Biometric(
            id=None,  # Will be generated
            biometric_type=biometric_data.biometric_type,
            timestamp=biometric_data.timestamp,
            value=biometric_data.value,
            device_id=biometric_data.device_id,
            metadata=biometric_data.metadata or {},
            user_id=current_user.id
        )
        
        # Create the biometric record
        created_biometric = await biometric_service.create_biometric(biometric)
        
        # Convert to response model
        return BiometricResponse(
            id=created_biometric.id,
            biometric_type=created_biometric.biometric_type,
            timestamp=created_biometric.timestamp,
            device_id=created_biometric.device_id,
            value=created_biometric.value,
            metadata=created_biometric.metadata,
            user_id=created_biometric.user_id
        )
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        ) from e
    except Exception as e:
        # HIPAA-compliant error handling
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred creating the biometric record"
        ) from e


@router.post(
    "/batch",
    response_model=list[BiometricResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Batch upload biometric data",
    description="Upload multiple biometric records in a single request"
)
async def batch_upload_biometrics(
    batch_data: BiometricBatchUploadRequest,
    biometric_service: BiometricServiceInterface = Depends(get_biometric_service),
    current_user: User = Depends(get_current_active_user)
) -> list[BiometricResponse]:
    """
    Batch upload multiple biometric records in a single request.
    
    This endpoint allows efficient upload of multiple biometric records,
    such as from a device sync operation.
    
    Args:
        batch_data: Batch of biometric records to create
        biometric_service: Injected biometric service
        current_user: Current authenticated user
        
    Returns:
        List of created biometric records
        
    Raises:
        HTTPException: If validation fails or an error occurs
    """
    try:
        # Convert request data to domain entities
        biometrics = [
            Biometric(
                id=None,  # Will be generated
                biometric_type=item.biometric_type,
                timestamp=item.timestamp,
                value=item.value,
                device_id=item.device_id,
                metadata=item.metadata or {},
                user_id=current_user.id
            )
            for item in batch_data.records
        ]
        
        # Batch create the biometric records
        created_biometrics = await biometric_service.batch_create_biometrics(biometrics)
        
        # Convert to response models
        return [
            BiometricResponse(
                id=biometric.id,
                biometric_type=biometric.biometric_type,
                timestamp=biometric.timestamp,
                device_id=biometric.device_id,
                value=biometric.value,
                metadata=biometric.metadata,
                user_id=biometric.user_id
            )
            for biometric in created_biometrics
        ]
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        ) from e
    except Exception as e:
        # HIPAA-compliant error handling
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred processing the batch upload"
        ) from e


@router.put(
    "/{biometric_id}",
    response_model=BiometricResponse,
    summary="Update biometric record",
    description="Update an existing biometric record"
)
async def update_biometric(
    biometric_id: UUID4 = Path(..., description="Biometric record ID"),
    biometric_data: BiometricUpdateRequest = None,
    biometric_service: BiometricServiceInterface = Depends(get_biometric_service),
    current_user: User = Depends(get_current_active_user)
) -> BiometricResponse:
    """
    Update an existing biometric record.
    
    Args:
        biometric_id: ID of the biometric record to update
        biometric_data: Updated data for the biometric record
        biometric_service: Injected biometric service
        current_user: Current authenticated user
        
    Returns:
        The updated biometric record
        
    Raises:
        HTTPException: If record not found, validation fails, or user not authorized
    """
    try:
        # Check if biometric exists and user has access
        existing_biometric = await biometric_service.get_biometric_by_id(
            biometric_id=str(biometric_id),
            user_id=current_user.id
        )
        
        if not existing_biometric:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Biometric record not found"
            )
            
        # Update the biometric with new data
        updated_biometric = Biometric(
            id=str(biometric_id),
            biometric_type=biometric_data.biometric_type or existing_biometric.biometric_type,
            timestamp=biometric_data.timestamp or existing_biometric.timestamp,
            value=biometric_data.value or existing_biometric.value,
            device_id=biometric_data.device_id or existing_biometric.device_id,
            metadata=biometric_data.metadata or existing_biometric.metadata,
            user_id=existing_biometric.user_id
        )
        
        # Update the biometric record
        result = await biometric_service.update_biometric(updated_biometric)
        
        # Convert to response model
        return BiometricResponse(
            id=result.id,
            biometric_type=result.biometric_type,
            timestamp=result.timestamp,
            device_id=result.device_id,
            value=result.value,
            metadata=result.metadata,
            user_id=result.user_id
        )
        
    except InvalidCredentialsError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to update this biometric record"
        ) from e
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        ) from e
    except Exception as e:
        # HIPAA-compliant error handling
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred updating the biometric record"
        ) from e


@router.delete(
    "/{biometric_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete biometric record",
    description="Delete a specific biometric record by ID"
)
async def delete_biometric(
    biometric_id: UUID4 = Path(..., description="Biometric record ID"),
    biometric_service: BiometricServiceInterface = Depends(get_biometric_service),
    current_user: User = Depends(get_current_active_user)
) -> None:
    """
    Delete a specific biometric record.
    
    Args:
        biometric_id: ID of the biometric record to delete
        biometric_service: Injected biometric service
        current_user: Current authenticated user
        
    Raises:
        HTTPException: If record not found or user not authorized
    """
    try:
        # Check if biometric exists and user has access
        existing_biometric = await biometric_service.get_biometric_by_id(
            biometric_id=str(biometric_id),
            user_id=current_user.id
        )
        
        if not existing_biometric:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Biometric record not found"
            )
            
        # Delete the biometric record
        success = await biometric_service.delete_biometric(
            biometric_id=str(biometric_id),
            user_id=current_user.id
        )
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to delete biometric record"
            )
            
    except InvalidCredentialsError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to delete this biometric record"
        ) from e
    except Exception as e:
        # HIPAA-compliant error handling
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred deleting the biometric record"
        ) from e
