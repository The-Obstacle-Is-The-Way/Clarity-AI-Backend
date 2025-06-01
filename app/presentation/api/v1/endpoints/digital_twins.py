"""
Digital Twin API Endpoints.

Provides API endpoints for interacting with patient digital twins.
Follows Clean Architecture principles with proper separation of concerns.
"""

import logging
from typing import Any, Dict, List
from uuid import UUID

from fastapi import APIRouter, Body, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse

from app.core.domain.entities.user import User, UserRole
from app.core.exceptions.base_exceptions import ModelExecutionError, ResourceNotFoundError
from app.core.interfaces.services.digital_twin_service_interface import DigitalTwinServiceInterface
from app.infrastructure.logging.audit_logger import audit_log_phi_access
from app.presentation.api.dependencies.auth import get_current_active_user, require_roles
from app.presentation.api.dependencies.digital_twin import get_digital_twin_service
from app.presentation.api.schemas.digital_twin import (
    ClinicalTextAnalysisRequest,
    ClinicalTextAnalysisResponse,
    DigitalTwinResponse,
    DigitalTwinStatusResponse,
    PersonalizedInsightResponse,
    TwinUpdateRequest,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    dependencies=[Depends(get_current_active_user)],
)


@router.get(
    "/",
    response_model=DigitalTwinResponse,
    summary="Get the current user's digital twin data",
)
async def get_digital_twin(
    digital_twin_service: DigitalTwinServiceInterface = Depends(get_digital_twin_service),
    current_user: User = Depends(get_current_active_user),
) -> DigitalTwinResponse:
    """
    Retrieve the digital twin representation for the currently authenticated user.
    
    This endpoint returns the digital twin data for the authenticated user,
    including psychological profile, behavior patterns, and relevant metadata.
    
    Args:
        digital_twin_service: Injected digital twin service
        current_user: Current authenticated user
        
    Returns:
        Digital twin data for the current user
        
    Raises:
        HTTPException: If digital twin not found or error occurs
    """
    logger.info(f"Fetching digital twin for user {current_user.id}")
    
    try:
        # Log the access for HIPAA compliance
        audit_log_phi_access(
            str(current_user.id),
            str(current_user.id),
            "get_digital_twin",
            details={"access_type": "self-access"},
        )
        
        twin_data = await digital_twin_service.get_twin_for_user(user_id=current_user.id)
        return DigitalTwinResponse(**twin_data)
    except ResourceNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Digital twin data not found for current user",
        )
    except Exception as e:
        logger.error(f"Error retrieving digital twin: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve digital twin data",
        )


@router.get(
    "/{patient_id}/status",
    response_model=DigitalTwinStatusResponse,
    summary="Get Digital Twin Status",
)
async def get_twin_status(
    patient_id: UUID,
    digital_twin_service: DigitalTwinServiceInterface = Depends(get_digital_twin_service),
    current_user: User = Depends(get_current_active_user),
) -> DigitalTwinStatusResponse:
    """
    Retrieve the status and completeness of a patient's digital twin.
    
    This endpoint provides information about the status of a patient's digital twin,
    including completeness metrics, last update time, and available features.
    
    Args:
        patient_id: ID of the patient
        digital_twin_service: Injected digital twin service
        current_user: Current authenticated user
        
    Returns:
        Status and completeness information for the digital twin
        
    Raises:
        HTTPException: If digital twin not found or user not authorized
    """
    try:
        # Log the access for HIPAA compliance
        audit_log_phi_access(
            str(current_user.id),
            str(patient_id),
            "get_twin_status",
            details={"access_type": "status-check"},
        )
        
        twin_status = await digital_twin_service.get_digital_twin_status(patient_id=patient_id)
        return twin_status
        
    except ResourceNotFoundError as e:
        logger.warning(f"Digital twin status not found: {e}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Digital twin status not found for patient {patient_id}",
        )
    except Exception as e:
        logger.error(f"Error retrieving digital twin status: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve digital twin status",
        )


@router.post(
    "/{patient_id}/update",
    response_model=DigitalTwinStatusResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Update Digital Twin",
    dependencies=[Depends(require_roles([UserRole.CLINICIAN, UserRole.ADMIN]))],
)
async def update_digital_twin(
    patient_id: UUID,
    update_request: TwinUpdateRequest,
    digital_twin_service: DigitalTwinServiceInterface = Depends(get_digital_twin_service),
    current_user: User = Depends(get_current_active_user),
) -> DigitalTwinStatusResponse:
    """
    Update a patient's digital twin with new information.
    
    This endpoint allows updating the digital twin with new data sources
    or requesting a regeneration based on existing data.
    
    Args:
        patient_id: ID of the patient
        update_request: Update parameters and data references
        digital_twin_service: Injected digital twin service
        current_user: Current authenticated user
        
    Returns:
        Updated status of the digital twin
        
    Raises:
        HTTPException: If update fails or user not authorized
    """
    try:
        # Log the access for HIPAA compliance
        audit_log_phi_access(
            str(current_user.id),
            str(patient_id),
            "update_digital_twin",
            details={"update_type": update_request.update_type},
        )
        
        updated_status = await digital_twin_service.update_digital_twin(
            patient_id=patient_id,
            update_type=update_request.update_type,
            data_sources=update_request.data_sources,
            requested_by=str(current_user.id),
        )
        return updated_status
        
    except ResourceNotFoundError as e:
        logger.warning(f"Digital twin update failed - resource not found: {e}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Digital twin not found for patient {patient_id}",
        )
    except Exception as e:
        logger.error(f"Error updating digital twin: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update digital twin",
        )


@router.get(
    "/{patient_id}/insights",
    response_model=List[PersonalizedInsightResponse],
    summary="Get Personalized Insights",
)
async def get_insights(
    patient_id: UUID,
    insight_type: str = None,
    limit: int = 10,
    digital_twin_service: DigitalTwinServiceInterface = Depends(get_digital_twin_service),
    current_user: User = Depends(get_current_active_user),
) -> List[PersonalizedInsightResponse]:
    """
    Get personalized insights derived from a patient's digital twin.
    
    This endpoint provides AI-generated insights about the patient based on
    their digital twin data, which may include behavioral patterns, treatment
    responses, and psychological insights.
    
    Args:
        patient_id: ID of the patient
        insight_type: Optional filter for specific insight types
        limit: Maximum number of insights to return
        digital_twin_service: Injected digital twin service
        current_user: Current authenticated user
        
    Returns:
        List of personalized insights for the patient
        
    Raises:
        HTTPException: If insights not available or user not authorized
    """
    try:
        # Log the access for HIPAA compliance
        audit_log_phi_access(
            str(current_user.id),
            str(patient_id),
            "get_insights",
            details={"insight_type": insight_type, "limit": limit},
        )
        
        insights = await digital_twin_service.get_personalized_insights(
            patient_id=patient_id,
            insight_type=insight_type,
            limit=limit,
        )
        return insights
        
    except ResourceNotFoundError as e:
        logger.warning(f"Insights not found: {e}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Insights not available for patient {patient_id}",
        )
    except Exception as e:
        logger.error(f"Error retrieving insights: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve personalized insights",
        )


@router.post(
    "/{patient_id}/analyze-text",
    response_model=ClinicalTextAnalysisResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Analyze Clinical Text with MentaLLaMA",
)
async def analyze_clinical_text(
    patient_id: UUID,
    analysis_request: ClinicalTextAnalysisRequest,
    digital_twin_service: DigitalTwinServiceInterface = Depends(get_digital_twin_service),
    current_user: User = Depends(get_current_active_user),
) -> ClinicalTextAnalysisResponse:
    """
    Analyze clinical text using the MentaLLaMA model integrated with the digital twin.
    
    This endpoint processes clinical text (notes, transcripts, etc.) through
    advanced natural language models to provide insights contextualized with
    the patient's digital twin.
    
    Args:
        patient_id: ID of the patient
        analysis_request: Text content and analysis parameters
        digital_twin_service: Injected digital twin service
        current_user: Current authenticated user
        
    Returns:
        Analysis results and context-aware insights
        
    Raises:
        HTTPException: If analysis fails or user not authorized
    """
    try:
        # Log the access for HIPAA compliance
        audit_log_phi_access(
            str(current_user.id),
            str(patient_id),
            "analyze_clinical_text",
            details={"analysis_type": analysis_request.analysis_type},
        )
        
        analysis_result = await digital_twin_service.analyze_clinical_text_mentallama(
            patient_id=patient_id,
            text=analysis_request.text,
            analysis_type=analysis_request.analysis_type,
        )
        
        return analysis_result
        
    except ResourceNotFoundError as e:
        logger.warning(f"Patient or digital twin not found: {e}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Patient or digital twin not found: {str(e)}",
        )
    except ModelExecutionError as e:
        logger.error(f"Model execution error in text analysis: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "detail": "An error occurred during text analysis",
                "error_code": "MODEL_EXECUTION_ERROR",
            },
        )
    except Exception as e:
        logger.error(f"Unexpected error analyzing clinical text: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred during clinical text analysis",
        )


@router.get(
    "/{patient_id}",
    response_model=DigitalTwinResponse,
    summary="Get Digital Twin for Patient",
    dependencies=[Depends(require_roles([UserRole.CLINICIAN, UserRole.ADMIN]))],
)
async def get_patient_digital_twin(
    patient_id: UUID,
    digital_twin_service: DigitalTwinServiceInterface = Depends(get_digital_twin_service),
    current_user: User = Depends(get_current_active_user),
) -> DigitalTwinResponse:
    """
    Retrieve the digital twin for a specific patient.
    
    This endpoint returns comprehensive digital twin data for the specified
    patient, including psychological profile, behavior patterns, and metadata.
    
    Args:
        patient_id: ID of the patient
        digital_twin_service: Injected digital twin service
        current_user: Current authenticated user
        
    Returns:
        Digital twin data for the specified patient
        
    Raises:
        HTTPException: If digital twin not found or user not authorized
    """
    try:
        # Log the access for HIPAA compliance
        audit_log_phi_access(
            str(current_user.id),
            str(patient_id),
            "get_patient_digital_twin",
            details={"access_type": "full-twin-access"},
        )
        
        twin_data = await digital_twin_service.get_twin_for_patient(patient_id=patient_id)
        return DigitalTwinResponse(**twin_data)
        
    except ResourceNotFoundError as e:
        logger.warning(f"Digital twin not found: {e}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Digital twin not found for patient {patient_id}",
        )
    except Exception as e:
        logger.error(f"Error retrieving patient digital twin: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve digital twin data",
        )