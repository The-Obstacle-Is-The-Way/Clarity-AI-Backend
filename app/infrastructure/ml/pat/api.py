"""
Pretrained Actigraphy Transformer (PAT) API endpoints.

This module provides the FastAPI endpoints for the PAT service.
"""

import logging
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.config.settings import get_settings
from app.core.auth.jwt_handler import verify_jwt_token
from app.infrastructure.ml.pat.models import (
    AccelerometerDataRequest,
    AnalysisResult,
    HistoricalAnalysisRequest,
    ModelInfoResponse,
    PATModelSizeEnum,
)
from app.infrastructure.ml.pat.service import AnalysisType, PATService
from app.core.services.ml.pat.pat_service_abc import PATServiceABC

logger = logging.getLogger(__name__)
security = HTTPBearer()
router = APIRouter(prefix="/api/v1/pat", tags=["PAT"])


async def get_pat_service() -> PATService:
    """
    Dependency for getting the PAT service instance.
    
    Returns:
        Initialized PAT service
    """
    settings = get_settings()
    service = PATService(
        model_size=PATModelSizeEnum(settings.ml.pat.model_path.split('-')[-1]) if 'pat-' in settings.ml.pat.model_path else PATModelSizeEnum.MEDIUM, # Infer size from path or default
        model_path=settings.ml.pat.model_path, # Use nested settings
        cache_dir=settings.ml.pat.cache_dir,
        use_gpu=settings.ml.pat.use_gpu
    )
    await service.initialize()
    return service


@router.post(
    "/analyze",
    response_model=AnalysisResult,
    status_code=status.HTTP_200_OK,
    summary="Analyze actigraphy data",
    description="Analyze actigraphy data from a wearable device using the PAT model"
)
async def analyze_actigraphy_data(
    request: AccelerometerDataRequest,
    credentials: HTTPAuthorizationCredentials = Security(security),
    pat_service: PATService = Depends(get_pat_service)
) -> AnalysisResult:
    """
    Analyze actigraphy data from a wearable device.
    
    Args:
        request: Actigraphy data analysis request
        credentials: JWT credentials
        pat_service: PAT service instance
        
    Returns:
        Analysis results
    """
    # Verify JWT token and get user claims
    claims = verify_jwt_token(credentials.credentials)
    if not claims:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials"
        )
    
    # Check if user has permission to access patient data
    if request.patient_metadata and request.patient_metadata.patient_id:
        # In a real implementation, we would check if the user has permission to access this patient's data
        # This is just a placeholder for the actual permission check
        pass
    
    try:
        # Convert readings to format expected by PAT service
        readings_data = [
            {
                "timestamp": reading.timestamp.isoformat(),
                "x": reading.x,
                "y": reading.y,
                "z": reading.z
            }
            for reading in request.readings
        ]
        
        # Convert analysis type enum
        analysis_type = AnalysisType[request.analysis_type.name]
        
        # Convert patient metadata to format expected by PAT service
        patient_metadata = None
        if request.patient_metadata:
            patient_metadata = request.patient_metadata.dict()
        
        # Run analysis
        results = await pat_service.analyze(
            actigraphy_data=readings_data,
            analysis_type=analysis_type,
            patient_metadata=patient_metadata,
            cache_results=request.cache_results
        )
        
        # Create analysis result
        analysis_result = AnalysisResult(
            analysis_id=str(uuid.uuid4()),
            patient_id=request.patient_metadata.patient_id if request.patient_metadata else None,
            analysis_type=request.analysis_type,
            timestamp=datetime.now(),
            model_version=results.get("model_version", f"PAT-{request.model_size.value.upper()}"),
            confidence_score=results.get("confidence_score", 0.0),
            metrics=results.get("metrics", {}),
            insights=results.get("insights", []),
            warnings=results.get("warnings", [])
        )
        
        return analysis_result
    except Exception as e:
        logger.error(f"Error analyzing actigraphy data: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error analyzing actigraphy data: {e!s}"
        )


@router.get(
    "/model-info",
    response_model=ModelInfoResponse,
    status_code=status.HTTP_200_OK,
    summary="Get PAT model information",
    description="Get information about the loaded PAT model"
)
async def get_model_info(
    credentials: HTTPAuthorizationCredentials = Security(security),
    pat_service: PATService = Depends(get_pat_service)
) -> ModelInfoResponse:
    """
    Get information about the loaded PAT model.
    
    Args:
        credentials: JWT credentials
        pat_service: PAT service instance
        
    Returns:
        Model information
    """
    # Verify JWT token
    claims = verify_jwt_token(credentials.credentials)
    if not claims:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials"
        )
    
    try:
        model_info = await pat_service.get_model_info()
        return ModelInfoResponse(**model_info)
    except Exception as e:
        logger.error(f"Error getting model info: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting model info: {e!s}"
        )


@router.post(
    "/historical",
    response_model=list[AnalysisResult],
    status_code=status.HTTP_200_OK,
    summary="Get historical analysis results",
    description="Get historical actigraphy analysis results for a patient"
)
async def get_historical_analysis(
    request: HistoricalAnalysisRequest,
    credentials: HTTPAuthorizationCredentials = Security(security)
) -> list[AnalysisResult]:
    """
    Get historical actigraphy analysis results for a patient.
    
    This is a placeholder implementation that would typically query a database
    for historical analysis results. In a real implementation, this would
    connect to a repository to retrieve stored analysis results.
    
    Args:
        request: Historical analysis request
        credentials: JWT credentials
        
    Returns:
        List of historical analysis results
    """
    # Verify JWT token and get user claims
    claims = verify_jwt_token(credentials.credentials)
    if not claims:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials"
        )
    
    # Check if user has permission to access patient data
    # In a real implementation, we would check if the user has permission to access this patient's data
    # This is just a placeholder for the actual permission check
    
    # This is a placeholder implementation
    # In a real implementation, we would query a database for historical analysis results
    return []