"""
Digital Twins Endpoints Module.

This module provides REST API endpoints for managing digital twin models
in a HIPAA-compliant manner with proper security controls, data validation, and audit logging.
"""

from typing import Dict, Any, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Path, status
from pydantic import UUID4

from app.core.domain.entities.digital_twin import DigitalTwin, TwinType
from app.core.domain.entities.user import User
from app.core.errors.security_exceptions import AuthenticationError
from app.core.interfaces.services.digital_twin_service_interface import DigitalTwinServiceInterface
from app.presentation.api.dependencies.auth import get_current_active_user
from app.presentation.api.dependencies.rate_limiter import sensitive_rate_limit
from app.presentation.api.schemas.digital_twin import (
    DigitalTwinCreateRequest,
    DigitalTwinResponse,
    DigitalTwinUpdateRequest,
    TwinSimulationRequest,
    TwinSimulationResponse
)
from app.presentation.api.v1.dependencies.digital_twin import get_digital_twin_service

# Create router with prefix and tags for OpenAPI documentation
router = APIRouter(
    prefix="/digital-twins",
    tags=["digital-twins"],
    dependencies=[Depends(sensitive_rate_limit())]  # Apply HIPAA-compliant rate limiting
)


@router.get(
    "",
    response_model=List[DigitalTwinResponse],
    summary="Get digital twins", 
    description="Get a list of digital twins with optional filtering"
)
async def get_digital_twins(
    twin_type: Optional[TwinType] = Query(None, description="Filter by twin type"),
    patient_id: Optional[UUID4] = Query(None, description="Patient ID if accessing as provider"),
    include_details: bool = Query(False, description="Include detailed twin data"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of records to return"),
    offset: int = Query(0, ge=0, description="Number of records to skip"),
    digital_twin_service: DigitalTwinServiceInterface = Depends(get_digital_twin_service),
    current_user: User = Depends(get_current_active_user)
) -> List[DigitalTwinResponse]:
    """
    Get a list of digital twins with optional filtering.
    
    This endpoint provides access to digital twin models with various filtering options.
    For healthcare providers, patient_id can be specified to access a patient's digital twins.
    
    Args:
        twin_type: Optional filter by digital twin type
        patient_id: Optional patient ID when accessed by a provider
        include_details: Whether to include detailed twin data
        limit: Maximum number of records to return
        offset: Number of records to skip
        digital_twin_service: Injected digital twin service
        current_user: Current authenticated user
        
    Returns:
        List of digital twin data
        
    Raises:
        HTTPException: If user is not authorized to access this data
    """
    try:
        # Determine if request is for self or for a patient (provider access)
        subject_id = str(patient_id) if patient_id else current_user.id
        
        # Check authorization if requesting patient data
        if patient_id and patient_id != current_user.id:
            # This will raise an exception if not authorized
            await digital_twin_service.validate_access(current_user.id, str(patient_id))
            
        # Get digital twins from service
        twins = await digital_twin_service.get_digital_twins(
            subject_id=subject_id,
            twin_type=twin_type,
            include_details=include_details,
            limit=limit,
            offset=offset
        )
        
        # Convert to response model
        return [
            DigitalTwinResponse(
                id=twin.id,
                twin_type=twin.twin_type,
                name=twin.name,
                description=twin.description,
                created_at=twin.created_at,
                updated_at=twin.updated_at,
                version=twin.version,
                data=twin.data if include_details else None,
                user_id=twin.user_id
            )
            for twin in twins
        ]
        
    except AuthenticationError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access this patient's digital twins"
        ) from e
    except Exception as e:
        # Log the exception but don't expose details in response
        # This is for HIPAA compliance
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred processing the digital twins request"
        ) from e


@router.get(
    "/{twin_id}",
    response_model=DigitalTwinResponse,
    summary="Get single digital twin",
    description="Get detailed information for a specific digital twin by ID"
)
async def get_digital_twin(
    twin_id: UUID4 = Path(..., description="Digital twin ID"),
    digital_twin_service: DigitalTwinServiceInterface = Depends(get_digital_twin_service),
    current_user: User = Depends(get_current_active_user)
) -> DigitalTwinResponse:
    """
    Get detailed information for a specific digital twin.
    
    Args:
        twin_id: ID of the digital twin to retrieve
        digital_twin_service: Injected digital twin service
        current_user: Current authenticated user
        
    Returns:
        Detailed digital twin data
        
    Raises:
        HTTPException: If record not found or user not authorized
    """
    try:
        # Get the digital twin (includes access validation)
        twin = await digital_twin_service.get_digital_twin_by_id(
            twin_id=str(twin_id),
            user_id=current_user.id
        )
        
        if not twin:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Digital twin not found"
            )
            
        # Convert to response model
        return DigitalTwinResponse(
            id=twin.id,
            twin_type=twin.twin_type,
            name=twin.name,
            description=twin.description,
            created_at=twin.created_at,
            updated_at=twin.updated_at,
            version=twin.version,
            data=twin.data,
            user_id=twin.user_id
        )
        
    except AuthenticationError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access this digital twin"
        ) from e
    except Exception as e:
        # HIPAA-compliant error handling
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred retrieving the digital twin"
        ) from e


@router.post(
    "",
    response_model=DigitalTwinResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create digital twin",
    description="Create a new digital twin model"
)
async def create_digital_twin(
    twin_data: DigitalTwinCreateRequest,
    digital_twin_service: DigitalTwinServiceInterface = Depends(get_digital_twin_service),
    current_user: User = Depends(get_current_active_user)
) -> DigitalTwinResponse:
    """
    Create a new digital twin model.
    
    Args:
        twin_data: Data for the new digital twin
        digital_twin_service: Injected digital twin service
        current_user: Current authenticated user
        
    Returns:
        The created digital twin
        
    Raises:
        HTTPException: If validation fails or an error occurs
    """
    try:
        # Create domain entity from request data
        twin = DigitalTwin(
            id=None,  # Will be generated
            twin_type=twin_data.twin_type,
            name=twin_data.name,
            description=twin_data.description,
            created_at=None,  # Will be set by service
            updated_at=None,  # Will be set by service
            version="1.0",
            data=twin_data.data or {},
            user_id=twin_data.patient_id or current_user.id
        )
        
        # Check if user has permissions to create a twin for this patient
        if twin_data.patient_id and twin_data.patient_id != current_user.id:
            await digital_twin_service.validate_access(current_user.id, twin_data.patient_id)
        
        # Create the digital twin
        created_twin = await digital_twin_service.create_digital_twin(twin)
        
        # Convert to response model
        return DigitalTwinResponse(
            id=created_twin.id,
            twin_type=created_twin.twin_type,
            name=created_twin.name,
            description=created_twin.description,
            created_at=created_twin.created_at,
            updated_at=created_twin.updated_at,
            version=created_twin.version,
            data=created_twin.data,
            user_id=created_twin.user_id
        )
        
    except AuthenticationError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to create a digital twin for this patient"
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
            detail="An error occurred creating the digital twin"
        ) from e


@router.put(
    "/{twin_id}",
    response_model=DigitalTwinResponse,
    summary="Update digital twin",
    description="Update an existing digital twin model"
)
async def update_digital_twin(
    twin_id: UUID4 = Path(..., description="Digital twin ID"),
    twin_data: DigitalTwinUpdateRequest = None,
    digital_twin_service: DigitalTwinServiceInterface = Depends(get_digital_twin_service),
    current_user: User = Depends(get_current_active_user)
) -> DigitalTwinResponse:
    """
    Update an existing digital twin model.
    
    Args:
        twin_id: ID of the digital twin to update
        twin_data: Updated data for the digital twin
        digital_twin_service: Injected digital twin service
        current_user: Current authenticated user
        
    Returns:
        The updated digital twin
        
    Raises:
        HTTPException: If record not found, validation fails, or user not authorized
    """
    try:
        # Check if digital twin exists and user has access
        existing_twin = await digital_twin_service.get_digital_twin_by_id(
            twin_id=str(twin_id),
            user_id=current_user.id
        )
        
        if not existing_twin:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Digital twin not found"
            )
            
        # Update the digital twin with new data
        updated_twin = DigitalTwin(
            id=str(twin_id),
            twin_type=existing_twin.twin_type,  # Type cannot be changed
            name=twin_data.name or existing_twin.name,
            description=twin_data.description or existing_twin.description,
            created_at=existing_twin.created_at,
            updated_at=None,  # Will be updated by service
            version=twin_data.version or existing_twin.version,
            data=twin_data.data or existing_twin.data,
            user_id=existing_twin.user_id  # User ID cannot be changed
        )
        
        # Update the digital twin
        result = await digital_twin_service.update_digital_twin(updated_twin)
        
        # Convert to response model
        return DigitalTwinResponse(
            id=result.id,
            twin_type=result.twin_type,
            name=result.name,
            description=result.description,
            created_at=result.created_at,
            updated_at=result.updated_at,
            version=result.version,
            data=result.data,
            user_id=result.user_id
        )
        
    except AuthenticationError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to update this digital twin"
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
            detail="An error occurred updating the digital twin"
        ) from e


@router.delete(
    "/{twin_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete digital twin",
    description="Delete a specific digital twin by ID"
)
async def delete_digital_twin(
    twin_id: UUID4 = Path(..., description="Digital twin ID"),
    digital_twin_service: DigitalTwinServiceInterface = Depends(get_digital_twin_service),
    current_user: User = Depends(get_current_active_user)
) -> None:
    """
    Delete a specific digital twin.
    
    Args:
        twin_id: ID of the digital twin to delete
        digital_twin_service: Injected digital twin service
        current_user: Current authenticated user
        
    Raises:
        HTTPException: If record not found or user not authorized
    """
    try:
        # Check if digital twin exists and user has access
        existing_twin = await digital_twin_service.get_digital_twin_by_id(
            twin_id=str(twin_id),
            user_id=current_user.id
        )
        
        if not existing_twin:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Digital twin not found"
            )
            
        # Delete the digital twin
        success = await digital_twin_service.delete_digital_twin(
            twin_id=str(twin_id),
            user_id=current_user.id
        )
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to delete digital twin"
            )
            
    except AuthenticationError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to delete this digital twin"
        ) from e
    except Exception as e:
        # HIPAA-compliant error handling
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred deleting the digital twin"
        ) from e


@router.post(
    "/{twin_id}/simulate",
    response_model=TwinSimulationResponse,
    summary="Run digital twin simulation",
    description="Run a simulation on a digital twin model"
)
async def run_simulation(
    twin_id: UUID4 = Path(..., description="Digital twin ID"),
    simulation_params: TwinSimulationRequest = None,
    digital_twin_service: DigitalTwinServiceInterface = Depends(get_digital_twin_service),
    current_user: User = Depends(get_current_active_user)
) -> TwinSimulationResponse:
    """
    Run a simulation on a digital twin model.
    
    This endpoint allows running what-if scenarios and simulations on a digital twin
    to predict outcomes and analyze potential interventions.
    
    Args:
        twin_id: ID of the digital twin to simulate
        simulation_params: Parameters for the simulation
        digital_twin_service: Injected digital twin service
        current_user: Current authenticated user
        
    Returns:
        The simulation results
        
    Raises:
        HTTPException: If record not found, validation fails, or user not authorized
    """
    try:
        # Check if digital twin exists and user has access
        twin = await digital_twin_service.get_digital_twin_by_id(
            twin_id=str(twin_id),
            user_id=current_user.id
        )
        
        if not twin:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Digital twin not found"
            )
            
        # Run the simulation
        simulation_result = await digital_twin_service.run_simulation(
            twin_id=str(twin_id),
            simulation_type=simulation_params.simulation_type,
            parameters=simulation_params.parameters,
            timeframe_days=simulation_params.timeframe_days
        )
        
        # Convert to response model
        return TwinSimulationResponse(
            simulation_id=simulation_result.simulation_id,
            twin_id=str(twin_id),
            simulation_type=simulation_result.simulation_type,
            executed_at=simulation_result.executed_at,
            timeframe_days=simulation_result.timeframe_days,
            results=simulation_result.results
        )
        
    except AuthenticationError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to simulate this digital twin"
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
            detail="An error occurred running the simulation"
        ) from e
