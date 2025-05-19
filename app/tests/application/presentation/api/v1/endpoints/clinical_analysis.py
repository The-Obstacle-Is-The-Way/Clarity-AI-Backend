"""
Clinical Analysis API Endpoints.

This module provides FastAPI routes for clinical text analysis
using the MentaLLaMA service with HIPAA compliance.
"""

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status

from app.core.exceptions.ml_exceptions import (
    AnalysisError,
    InvalidAnalysisTypeError,
    MentalLLaMAInferenceError,
    ModelLoadingError,
)
from app.infrastructure.ml.mentallama import MentaLLaMAService
from app.presentation.api.schemas.ml_schemas import (
    ClinicalAnalysisRequest,
    ClinicalAnalysisResponse,
    PHIDetectionResponse,
)
from app.presentation.api.v1.dependencies.ml import get_mentallama_service

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/clinical-analysis",
    tags=["clinical-analysis"],
    responses={
        status.HTTP_401_UNAUTHORIZED: {"description": "Authentication required"},
        status.HTTP_403_FORBIDDEN: {"description": "Insufficient permissions"},
        status.HTTP_500_INTERNAL_SERVER_ERROR: {"description": "Internal server error"},
    },
)


@router.post(
    "/analyze",
    response_model=ClinicalAnalysisResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze clinical text",
    description="""
    Analyze clinical text using advanced NLP techniques.
    
    This endpoint analyzes clinical text to extract insights such as
    diagnostic impressions, risk assessments, treatment recommendations,
    and other clinical insights. The analysis is fully HIPAA-compliant
    with PHI detection and protection.
    """,
)
async def analyze_clinical_text(
    request: ClinicalAnalysisRequest,
    mentallama_service: MentaLLaMAService = Depends(get_mentallama_service),
) -> ClinicalAnalysisResponse:
    """
    Analyze clinical text using MentaLLaMA.

    Args:
        request: Analysis request with text and parameters
        mentallama_service: MentaLLaMA service instance

    Returns:
        Analysis results

    Raises:
        HTTPException: If analysis fails
    """
    try:
        # Log operation (no PHI)
        logger.info(
            f"Clinical analysis requested, type: {request.analysis_type.value}, "
            f"text length: {len(request.text)}"
        )

        # Perform analysis
        result = await mentallama_service.analyze(
            text=request.text,
            analysis_type=request.analysis_type.value,
            patient_context=request.patient_context,
        )

        # Log completion (no PHI)
        logger.info(
            f"Clinical analysis completed, type: {request.analysis_type.value}, "
            f"confidence: {result.confidence_score:.2f}"
        )

        return result

    except InvalidAnalysisTypeError as e:
        logger.warning(f"Invalid analysis type: {e!s}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid analysis type: {e!s}",
        )

    except ModelLoadingError as e:
        logger.error(f"Model loading error: {e!s}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service temporarily unavailable. Please try again later.",
        )

    except MentalLLaMAInferenceError as e:
        logger.error(f"Inference error: {e!s}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Analysis processing error. Please try again.",
        )

    except AnalysisError as e:
        logger.error(f"Analysis error: {e!s}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Analysis failed. Please try again.",
        )

    except Exception as e:
        # Generic catch for unexpected errors - log details for debugging
        # but return a generic message to the client
        logger.error(f"Unexpected error in clinical analysis: {e!s}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred. Please try again later.",
        )


@router.post(
    "/detect-phi",
    response_model=PHIDetectionResponse,
    status_code=status.HTTP_200_OK,
    summary="Detect PHI in text",
    description="""
    Detect Protected Health Information (PHI) in text.
    
    This endpoint analyzes text to identify PHI according to HIPAA guidelines.
    It can optionally anonymize the text by redacting or replacing identified PHI.
    """,
)
async def detect_phi_in_text(
    text: str,
    anonymize: bool | None = False,
    mentallama_service: MentaLLaMAService = Depends(get_mentallama_service),
) -> dict[str, Any]:
    """
    Detect PHI in text with optional anonymization.

    Args:
        text: Text to analyze for PHI
        anonymize: Whether to anonymize detected PHI
        mentallama_service: MentaLLaMA service instance with PHI detection

    Returns:
        PHI detection results

    Raises:
        HTTPException: If PHI detection fails
    """
    try:
        # Log operation (no PHI)
        logger.info(f"PHI detection requested, text length: {len(text)}")

        if not mentallama_service.phi_detection_service:
            logger.warning("PHI detection service not available")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="PHI detection service not available",
            )

        # Detect PHI
        anonymize_method = "redact" if anonymize else None
        result = await mentallama_service.phi_detection_service.detect_phi(
            text=text, anonymize_method=anonymize_method
        )

        # Log completion (no PHI)
        phi_count = len(result.get("entities", []))
        logger.info(f"PHI detection completed, found {phi_count} PHI entities")

        return result

    except Exception as e:
        logger.error(f"Error in PHI detection: {e!s}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="PHI detection failed. Please try again.",
        )
