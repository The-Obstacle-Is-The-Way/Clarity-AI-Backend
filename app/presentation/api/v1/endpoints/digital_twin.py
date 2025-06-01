"""
Digital Twin Endpoints Module.

Provides API endpoints for interacting with the user's digital twin,
following Clean Architecture principles with proper separation of concerns.
"""

import logging
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse

from app.core.domain.entities.user import User
from app.core.exceptions.base_exceptions import (
    ModelExecutionError,
    ResourceNotFoundError,
)
from app.presentation.api.dependencies.auth import get_current_active_user
from app.presentation.api.v1.dependencies.digital_twin import (
    DigitalTwinServiceDep,
    MentaLLaMAServiceDep,
)
from app.presentation.api.schemas.digital_twin import (
    ClinicalTextAnalysisRequest,
    DigitalTwinResponse,
    DigitalTwinStatusResponse,
    PersonalizedInsightResponse,
    ClinicalTextAnalysisResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get(
    "/",
    response_model=DigitalTwinResponse,
    summary="Get the user's digital twin data",
    description="Retrieve the digital twin representation for the currently authenticated user.",
)
async def get_digital_twin(
    dt_service: DigitalTwinServiceDep,
    current_user: User = Depends(get_current_active_user),
) -> DigitalTwinResponse:
    """
    Retrieve the digital twin representation for the currently authenticated user.
    
    Args:
        dt_service: Dependency-injected Digital Twin service
        current_user: The authenticated user requesting their digital twin data
        
    Returns:
        The digital twin data structured according to the DigitalTwinResponse schema
        
    Raises:
        HTTPException: If the digital twin cannot be found or retrieved
    """
    logger.info(f"Fetching digital twin for user {current_user.id}")
    try:
        twin_data = await dt_service.get_twin_for_user(user_id=current_user.id)
        return DigitalTwinResponse(**twin_data)
    except ResourceNotFoundError:
        logger.warning(f"Digital twin not found for user {current_user.id}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Digital twin data not found for current user",
        ) from None
    except Exception as e:
        logger.error(f"Error retrieving digital twin: {e!s}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve digital twin",
        ) from e


@router.get(
    "/{patient_id}/status",
    response_model=DigitalTwinStatusResponse,
    summary="Get the digital twin status for a patient",
    description="Retrieve the status of a patient's digital twin, showing which components are available.",
)
async def get_twin_status(
    patient_id: UUID,
    dt_service: DigitalTwinServiceDep,
    current_user: User = Depends(get_current_active_user),
) -> dict[str, Any]:
    """
    Retrieve the status of a patient's digital twin, showing which components are available.
    
    Args:
        patient_id: The UUID of the patient whose digital twin status is being retrieved
        dt_service: Dependency-injected Digital Twin service
        current_user: The authenticated user making the request
        
    Returns:
        A dictionary containing the status information for the digital twin
        
    Raises:
        HTTPException: If the patient or their digital twin cannot be found
    """
    logger.info(f"Fetching digital twin status for patient {patient_id}")
    try:
        return await dt_service.get_digital_twin_status(patient_id=patient_id)
    except ResourceNotFoundError as e:
        logger.warning(f"Digital twin status not found for patient {patient_id}: {e!s}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Digital twin status not found: {e!s}",
        ) from e
    except Exception as e:
        logger.error(f"Error retrieving digital twin status: {e!s}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve digital twin status",
        ) from e


@router.get(
    "/{patient_id}/insights",
    response_model=PersonalizedInsightResponse,
    summary="Get comprehensive insights for a patient",
    description="Generate comprehensive personalized insights for a patient based on their digital twin.",
)
async def get_comprehensive_insights(
    patient_id: UUID,
    dt_service: DigitalTwinServiceDep,
    current_user: User = Depends(get_current_active_user),
) -> dict[str, Any]:
    """
    Generate comprehensive personalized insights for a patient based on their digital twin.
    
    Args:
        patient_id: The UUID of the patient for whom to generate insights
        dt_service: Dependency-injected Digital Twin service
        current_user: The authenticated user making the request
        
    Returns:
        A dictionary containing personalized insights generated from the digital twin
        
    Raises:
        HTTPException: If the patient cannot be found or insights cannot be generated
    """
    logger.info(f"Generating comprehensive insights for patient {patient_id}")
    try:
        return await dt_service.generate_comprehensive_patient_insights(patient_id=patient_id)
    except ResourceNotFoundError as e:
        logger.warning(f"Cannot generate insights - patient or twin not found: {e!s}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Patient or digital twin not found: {e!s}",
        )
    except ModelExecutionError as e:
        logger.error(f"Model execution error in insights generation: {e!s}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "detail": "An error occurred during model execution",
                "error_code": "MODEL_EXECUTION_ERROR",
            },
        )
    except Exception as e:
        logger.error(f"Error generating insights: {e!s}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unexpected error generating insights",
        ) from e


@router.post(
    "/{patient_id}/analyze-text",
    response_model=ClinicalTextAnalysisResponse,
    summary="Analyze clinical text using the digital twin",
    description="Analyze clinical text using MentaLLaMA integration with the patient's digital twin.",
)
async def analyze_clinical_text(
    patient_id: UUID,
    analysis_request: ClinicalTextAnalysisRequest,
    dt_service: DigitalTwinServiceDep,
    mentallama_service: MentaLLaMAServiceDep,
    current_user: User = Depends(get_current_active_user),
) -> dict[str, Any]:
    """
    Analyze clinical text using MentaLLaMA integration with the patient's digital twin.
    
    Args:
        patient_id: The UUID of the patient whose digital twin will be used for analysis
        analysis_request: The request containing text to analyze and analysis type
        dt_service: Dependency-injected Digital Twin service
        mentallama_service: Dependency-injected MentaLLaMA service
        current_user: The authenticated user making the request
        
    Returns:
        A dictionary containing analysis results from MentaLLaMA
        
    Raises:
        HTTPException: If the patient cannot be found or analysis fails
    """
    logger.info(f"Analyzing clinical text for patient {patient_id}")
    
    try:
        # Use the service to analyze the text
        return await dt_service.analyze_clinical_text_mentallama(
            patient_id=patient_id,
            text=analysis_request.text,
            analysis_type=analysis_request.analysis_type,
        )
    except ResourceNotFoundError as e:
        logger.warning(f"Patient or digital twin not found for text analysis: {e!s}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Patient or digital twin not found: {e!s}",
        )
    except ModelExecutionError as e:
        logger.error(f"Model execution error in text analysis: {e!s}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "detail": "An error occurred during model execution",
                "error_code": "MODEL_EXECUTION_ERROR",
            },
        )
    except Exception as e:
        logger.error(f"Error analyzing clinical text: {e!s}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unexpected error analyzing clinical text",
        ) from e
