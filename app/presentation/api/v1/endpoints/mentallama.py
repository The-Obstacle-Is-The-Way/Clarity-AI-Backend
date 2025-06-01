"""
MentaLLaMA API Endpoints Module.

This module provides endpoints for the MentaLLaMA natural language processing API,
which is specialized for mental health text analysis and therapeutic response generation.
Following Clean Architecture principles for better maintainability and testability.
"""

import asyncio
import logging

from fastapi import APIRouter, Depends, HTTPException, status

from app.core.domain.entities.user import User
from app.core.services.ml.interface import MentaLLaMAInterface
from app.presentation.api.dependencies.auth import get_current_active_user
from app.presentation.api.v1.dependencies.digital_twin import get_mentallama_service
from app.presentation.api.schemas.mentallama import (
    AnalysisResponse,
    AnalyzeTextRequest,
    ConditionsResponse,
    DetectConditionsRequest,
    HealthCheckResponse,
    ProcessTextRequest,
    ProcessTextResponse,
    SuicideRiskRequest,
    SuicideRiskResponse,
    TherapeuticResponseRequest,
    TherapeuticResponseResponse,
    WellnessRequest,
    WellnessResponse,
)

# Configure logger
logger = logging.getLogger(__name__)

# Create router
router = APIRouter()


def _check_health(service: MentaLLaMAInterface) -> None:
    """
    Check if the MentaLLaMA service is healthy and available.

    Args:
        service: The MentaLLaMA service instance to check

    Raises:
        HTTPException: If the service is unavailable
    """
    if not service.is_healthy():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="MentaLLaMA service is not available",
        ) from None


@router.get(
    "/health",
    response_model=HealthCheckResponse,
    summary="Check MentaLLaMA service health",
    description="Verifies the health and availability of the MentaLLaMA service",
    status_code=status.HTTP_200_OK,
    tags=["MentaLLaMA"],
)
async def health_check(
    service: MentaLLaMAInterface = Depends(get_mentallama_service),
) -> HealthCheckResponse:
    """
    Check the health of the MentaLLaMA service.

    Args:
        service: MentaLLaMA service instance from dependency injection

    Returns:
        HealthCheckResponse: Service health status details
    """
    try:
        logger.info("Checking MentaLLaMA service health")
        service_status = service.is_healthy()
        
        # Get additional health information if available
        metadata = {}
        if hasattr(service, "get_health_info"):
            health_info = service.get_health_info()
            if isinstance(health_info, dict):
                metadata = health_info
        
        return HealthCheckResponse(
            status="healthy" if service_status else "unhealthy",
            service_status=service_status,
            metadata=metadata
        )
    except Exception as e:
        logger.error(f"Error checking MentaLLaMA service health: {e!s}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to check MentaLLaMA service health",
        ) from e


@router.post(
    "/process",
    response_model=ProcessTextResponse,
    summary="Process text with MentaLLaMA",
    description="Processes a text prompt through the MentaLLaMA language model",
    status_code=status.HTTP_200_OK,
    tags=["MentaLLaMA"],
)
async def process_text(
    request: ProcessTextRequest,
    service: MentaLLaMAInterface = Depends(get_mentallama_service),
    current_user: User = Depends(get_current_active_user),
) -> ProcessTextResponse:
    """
    Process a text prompt through the MentaLLaMA service.

    Args:
        request: The text processing request details
        service: MentaLLaMA service instance from dependency injection
        current_user: Current authenticated user

    Returns:
        ProcessTextResponse: Processing results
    """
    try:
        logger.info(f"Processing text with MentaLLaMA for user: {current_user.id}")
        _check_health(service)

        options = {
            "user_id": request.user_id,
            "temperature": request.temperature,
            "max_tokens": request.max_tokens
        }

        result = service.process(
            text=request.prompt,
            model_type=request.model,
            options=options
        )
        
        if asyncio.iscoroutine(result):
            result = await result
            
        logger.debug(f"MentaLLaMA process completed successfully for user: {current_user.id}")
        
        # Extract metadata if present
        metadata = {}
        if isinstance(result, dict) and "metadata" in result:
            metadata = result.get("metadata", {})
            
        return ProcessTextResponse(
            response=result.get("response", ""),
            model_used=request.model,
            metadata=metadata
        )
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        logger.error(f"Error processing text with MentaLLaMA: {e!s}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to process text with MentaLLaMA",
        ) from e


@router.post(
    "/analyze",
    response_model=AnalysisResponse,
    summary="Analyze text for mental health insights",
    description="Analyzes text to extract mental health insights and themes",
    status_code=status.HTTP_200_OK,
    tags=["MentaLLaMA"],
)
async def analyze_text(
    request: AnalyzeTextRequest,
    service: MentaLLaMAInterface = Depends(get_mentallama_service),
    current_user: User = Depends(get_current_active_user),
) -> AnalysisResponse:
    """
    Analyze text for mental health insights.

    Args:
        request: The text analysis request details
        service: MentaLLaMA service instance from dependency injection
        current_user: Current authenticated user

    Returns:
        AnalysisResponse: Analysis results
    """
    try:
        logger.info(f"Analyzing text with MentaLLaMA for user: {current_user.id}")
        _check_health(service)

        options = {
            "user_id": request.user_id,
            "analysis_type": request.analysis_type
        }

        result = service.process(
            text=request.text,
            model_type="analysis",
            options=options
        )
        
        if asyncio.iscoroutine(result):
            result = await result
            
        logger.debug(f"MentaLLaMA analysis completed successfully for user: {current_user.id}")
        
        # Ensure we have all required fields or provide defaults
        analysis = result.get("analysis", "No analysis available")
        themes = result.get("themes", [])
        emotions = result.get("emotions", {})
        metadata = result.get("metadata", {})
        
        return AnalysisResponse(
            analysis=analysis,
            themes=themes,
            emotions=emotions,
            metadata=metadata
        )
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        logger.error(f"Error analyzing text with MentaLLaMA: {e!s}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to analyze text with MentaLLaMA",
        ) from e


@router.post(
    "/detect-conditions",
    response_model=ConditionsResponse,
    summary="Detect potential mental health conditions",
    description="Analyzes text to detect potential mental health conditions with confidence scores",
    status_code=status.HTTP_200_OK,
    tags=["MentaLLaMA"],
)
async def detect_conditions(
    request: DetectConditionsRequest,
    service: MentaLLaMAInterface = Depends(get_mentallama_service),
    current_user: User = Depends(get_current_active_user),
) -> ConditionsResponse:
    """
    Detect potential mental health conditions in text.

    Args:
        request: The conditions detection request details
        service: MentaLLaMA service instance from dependency injection
        current_user: Current authenticated user

    Returns:
        ConditionsResponse: Detected conditions with confidence scores
    """
    try:
        logger.info(f"Detecting conditions with MentaLLaMA for user: {current_user.id}")
        _check_health(service)

        options = {
            "user_id": request.user_id
        }

        result = service.process(
            text=request.text,
            model_type="conditions",
            options=options
        )
        
        if asyncio.iscoroutine(result):
            result = await result
            
        logger.debug(f"MentaLLaMA condition detection completed successfully for user: {current_user.id}")
        
        # Ensure we have all required fields or provide defaults
        conditions = result.get("conditions", [])
        summary = result.get("summary", "No condition summary available")
        metadata = result.get("metadata", {})
        
        return ConditionsResponse(
            conditions=conditions,
            summary=summary,
            metadata=metadata
        )
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        logger.error(f"Error detecting conditions with MentaLLaMA: {e!s}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to detect conditions with MentaLLaMA",
        ) from e


@router.post(
    "/therapeutic-response",
    response_model=TherapeuticResponseResponse,
    summary="Generate therapeutic response",
    description="Generates a therapeutic response based on conversation history",
    status_code=status.HTTP_200_OK,
    tags=["MentaLLaMA"],
)
async def generate_therapeutic_response(
    request: TherapeuticResponseRequest,
    service: MentaLLaMAInterface = Depends(get_mentallama_service),
    current_user: User = Depends(get_current_active_user),
) -> TherapeuticResponseResponse:
    """
    Generate a therapeutic response based on conversation history.

    Args:
        request: The therapeutic response request details
        service: MentaLLaMA service instance from dependency injection
        current_user: Current authenticated user

    Returns:
        TherapeuticResponseResponse: Therapeutic response with relevant approach information
    """
    try:
        logger.info(f"Generating therapeutic response with MentaLLaMA for user: {current_user.id}")
        _check_health(service)

        # Convert conversation history to a prompt
        prompt = "\n".join(
            [f"{msg.role}: {msg.content}" for msg in request.conversation_history]
        )

        options = {
            "user_id": request.user_id,
            "conversation_history": request.conversation_history
        }

        result = service.process(
            text=prompt,
            model_type="therapeutic",
            options=options
        )
        
        if asyncio.iscoroutine(result):
            result = await result
            
        logger.debug(f"MentaLLaMA therapeutic response generation completed successfully for user: {current_user.id}")
        
        # Extract result and metadata
        response_result = result.get("result", {})
        metadata = result.get("metadata", {})
        
        return TherapeuticResponseResponse(
            result=response_result,
            metadata=metadata
        )
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        logger.error(f"Error generating therapeutic response with MentaLLaMA: {e!s}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate therapeutic response with MentaLLaMA",
        ) from e


@router.post(
    "/assess-suicide-risk",
    response_model=SuicideRiskResponse,
    summary="Assess suicide risk in text",
    description="Analyzes text to assess suicide risk level with recommendations",
    status_code=status.HTTP_200_OK,
    tags=["MentaLLaMA"],
)
async def assess_suicide_risk(
    request: SuicideRiskRequest,
    service: MentaLLaMAInterface = Depends(get_mentallama_service),
    current_user: User = Depends(get_current_active_user),
) -> SuicideRiskResponse:
    """
    Assess suicide risk in text.

    Args:
        request: The suicide risk assessment request details
        service: MentaLLaMA service instance from dependency injection
        current_user: Current authenticated user

    Returns:
        SuicideRiskResponse: Risk assessment with recommended actions
    """
    try:
        logger.info(f"Assessing suicide risk with MentaLLaMA for user: {current_user.id}")
        _check_health(service)

        options = {
            "user_id": request.user_id
        }

        result = service.process(
            text=request.text,
            model_type="suicide_risk",
            options=options
        )
        
        if asyncio.iscoroutine(result):
            result = await result
            
        logger.debug(f"MentaLLaMA suicide risk assessment completed successfully for user: {current_user.id}")
        
        # HIPAA compliance: audit log for sensitive risk assessment
        if result.get("assessment", {}).get("risk_level") in ["high", "severe", "imminent"]:
            logger.warning(
                f"High suicide risk detected for user: {current_user.id}. "
                f"Risk level: {result.get('assessment', {}).get('risk_level')}"
            )
        
        # Extract assessment and metadata
        assessment = result.get("assessment", {})
        metadata = result.get("metadata", {})
        
        return SuicideRiskResponse(
            assessment=assessment,
            metadata=metadata
        )
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        logger.error(f"Error assessing suicide risk with MentaLLaMA: {e!s}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to assess suicide risk with MentaLLaMA",
        ) from e


@router.post(
    "/assess-wellness-dimensions",
    response_model=WellnessResponse,
    summary="Assess wellness dimensions",
    description="Analyzes text to assess various dimensions of wellness",
    status_code=status.HTTP_200_OK,
    tags=["MentaLLaMA"],
)
async def assess_wellness_dimensions(
    request: WellnessRequest,
    service: MentaLLaMAInterface = Depends(get_mentallama_service),
    current_user: User = Depends(get_current_active_user),
) -> WellnessResponse:
    """
    Assess wellness dimensions in text.

    Args:
        request: The wellness assessment request details
        service: MentaLLaMA service instance from dependency injection
        current_user: Current authenticated user

    Returns:
        WellnessResponse: Wellness assessment across relevant dimensions
    """
    try:
        logger.info(f"Assessing wellness dimensions with MentaLLaMA for user: {current_user.id}")
        _check_health(service)

        options = {
            "user_id": request.user_id
        }
        
        # Add dimensions if specified
        if request.dimensions:
            options["dimensions"] = [dim.value for dim in request.dimensions]

        result = service.process(
            text=request.text,
            model_type="wellness",
            options=options
        )
        
        if asyncio.iscoroutine(result):
            result = await result
            
        logger.debug(f"MentaLLaMA wellness assessment completed successfully for user: {current_user.id}")
        
        # Extract required fields or provide defaults
        overall_wellness = result.get("overall_wellness", 0.5)
        dimensions = result.get("dimensions", [])
        summary = result.get("summary", "No wellness summary available")
        metadata = result.get("metadata", {})
        
        return WellnessResponse(
            overall_wellness=overall_wellness,
            dimensions=dimensions,
            summary=summary,
            metadata=metadata
        )
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        logger.error(f"Error assessing wellness dimensions with MentaLLaMA: {e!s}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to assess wellness dimensions with MentaLLaMA",
        ) from e
