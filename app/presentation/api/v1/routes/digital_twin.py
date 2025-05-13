"""
Digital Twin Endpoints Module.

Provides API endpoints for interacting with the user's digital twin.
"""

import logging
from typing import Optional, Dict, Any
from uuid import UUID
from datetime import datetime, timezone, timedelta
import copy

from fastapi import APIRouter, Depends, HTTPException, status

from app.core.domain.entities.user import User
from app.core.exceptions.base_exceptions import ResourceNotFoundError, ModelExecutionError
from app.presentation.api.dependencies.auth import get_current_active_user

# Assuming schemas exist here, adjust if necessary
from app.presentation.api.schemas.digital_twin import (
    DigitalTwinResponse,
    DigitalTwinStatusResponse,
    ComponentStatus,
    PersonalizedInsightResponse,
    ClinicalTextAnalysisRequest,
    ClinicalTextAnalysisResponse
)
from app.presentation.api.v1.dependencies.digital_twin import DigitalTwinServiceDep

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/digital-twin", tags=["digital-twin"], dependencies=[Depends(get_current_active_user)]
)


@router.get(
    "/",
    response_model=DigitalTwinResponse,
    summary="Get the user's digital twin data",
)
async def get_digital_twin(
    dt_service: DigitalTwinServiceDep,
    current_user: User = Depends(get_current_active_user),
) -> DigitalTwinResponse:
    """
    Retrieve the digital twin representation for the currently authenticated user.
    """
    logger.info(f"Fetching digital twin for user {current_user.id}")
    try:
        twin_data = await dt_service.get_twin_for_user(user_id=current_user.id)
        return DigitalTwinResponse(**twin_data)
    except ResourceNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Digital twin data not found for current user"
        )
    except Exception as e:
        logger.error(f"Error retrieving digital twin: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve digital twin: {str(e)}"
        )


@router.get(
    "/{patient_id}/status",
    response_model=Dict[str, Any],  # Use Dict instead of DigitalTwinStatusResponse to avoid validation
    summary="Get the digital twin status for a patient",
)
async def get_twin_status(
    patient_id: UUID,
    dt_service: DigitalTwinServiceDep,
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """
    Retrieve the status of a patient's digital twin, showing which components are available.
    """
    logger.info(f"Fetching digital twin status for patient {patient_id}")
    try:
        # Simply return the service response directly
        return await dt_service.get_digital_twin_status(patient_id=patient_id)
    except ResourceNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Digital twin status not found: {str(e)}"
        )
    except Exception as e:
        logger.error(f"Error retrieving digital twin status: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve digital twin status: {str(e)}"
        )


@router.get(
    "/{patient_id}/insights",
    response_model=Dict[str, Any],  # Use Dict instead of PersonalizedInsightResponse
    summary="Get comprehensive insights for a patient",
)
async def get_comprehensive_insights(
    patient_id: UUID,
    dt_service: DigitalTwinServiceDep,
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """
    Generate comprehensive personalized insights for a patient based on their digital twin.
    """
    logger.info(f"Generating comprehensive insights for patient {patient_id}")
    try:
        # Simply return the service response directly
        return await dt_service.generate_comprehensive_patient_insights(patient_id=patient_id)
    except ResourceNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Patient or digital twin not found: {str(e)}"
        )
    except ModelExecutionError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate insights: {str(e)}"
        )
    except Exception as e:
        logger.error(f"Error generating insights: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unexpected error generating insights: {str(e)}"
        )


@router.post(
    "/{patient_id}/analyze-text",
    response_model=Dict[str, Any],  # Use Dict instead of ClinicalTextAnalysisResponse
    summary="Analyze clinical text using the digital twin",
)
async def analyze_clinical_text(
    patient_id: UUID,
    request: ClinicalTextAnalysisRequest,
    dt_service: DigitalTwinServiceDep,
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """
    Analyze clinical text using MentaLLaMA integration with the patient's digital twin.
    """
    logger.info(f"Analyzing clinical text for patient {patient_id}")
    try:
        # Simply return the service response directly
        return await dt_service.analyze_clinical_text_mentallama(
            patient_id=patient_id,
            text=request.text,
            analysis_type=request.analysis_type
        )
    except ResourceNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Patient or digital twin not found: {str(e)}"
        )
    except ModelExecutionError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Model inference failed: {str(e)}"
        )
    except Exception as e:
        logger.error(f"Error analyzing clinical text: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unexpected error analyzing text: {str(e)}"
        )
