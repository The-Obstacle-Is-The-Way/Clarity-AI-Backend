"""
Machine Learning API Endpoints Module.

This module provides endpoints for ML model interactions,
following Clean Architecture principles for better maintainability,
testability, and HIPAA compliance.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, status

from app.core.domain.entities.user import User
from app.presentation.api.dependencies.auth import get_current_active_user
from app.presentation.api.schemas.ml import (
    BatchPredictionRequest,
    BatchPredictionResponse,
    FeatureImportanceRequest,
    FeatureImportanceResponse,
    HealthCheckResponse,
    ModelInfoResponse,
    ModelListResponse,
    PredictionRequest,
    PredictionResponse,
)
from app.presentation.api.v1.dependencies.ml import MLServiceDep

# Configure logger
logger = logging.getLogger(__name__)

# Create router
router = APIRouter()


@router.get(
    "/health",
    response_model=HealthCheckResponse,
    summary="Check ML service health",
    description="Verifies the health and availability of the ML service",
    status_code=status.HTTP_200_OK,
    tags=["Machine Learning"],
)
async def health_check(
    ml_service: MLServiceDep,
) -> HealthCheckResponse:
    """
    Check the health of the ML service.

    Args:
        ml_service: ML service instance from dependency injection

    Returns:
        HealthCheckResponse: Service health status details
    """
    try:
        logger.info("Checking ML service health")
        service_status = ml_service.is_healthy()
        health_info = ml_service.get_health_info()
        
        return HealthCheckResponse(
            status="healthy" if service_status else "unhealthy",
            available_models=health_info.get("available_models", 0),
            version=health_info.get("version", "unknown"),
            uptime=health_info.get("uptime")
        )
    except Exception as e:
        logger.error(f"Error checking ML service health: {e!s}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to check ML service health",
        ) from e


@router.get(
    "/models",
    response_model=ModelListResponse,
    summary="List available ML models",
    description="Returns a list of all available ML models with basic information",
    status_code=status.HTTP_200_OK,
    tags=["Machine Learning"],
)
async def list_models(
    ml_service: MLServiceDep,
    current_user: User = Depends(get_current_active_user),
) -> ModelListResponse:
    """
    List all available ML models.

    Args:
        ml_service: ML service instance from dependency injection
        current_user: Current authenticated user

    Returns:
        ModelListResponse: List of available models
    """
    try:
        logger.info(f"Listing available ML models for user: {current_user.id}")
        result = await ml_service.list_models()
        
        return ModelListResponse(
            models=result.get("models", []),
            count=len(result.get("models", []))
        )
    except Exception as e:
        logger.error(f"Error listing ML models: {e!s}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list ML models",
        ) from e


@router.get(
    "/models/{model_id}",
    response_model=ModelInfoResponse,
    summary="Get ML model information",
    description="Returns detailed information about a specific ML model",
    status_code=status.HTTP_200_OK,
    tags=["Machine Learning"],
)
async def get_model_info(
    model_id: str,
    ml_service: MLServiceDep,
    current_user: User = Depends(get_current_active_user),
) -> ModelInfoResponse:
    """
    Get information about a specific ML model.

    Args:
        model_id: Identifier for the ML model
        ml_service: ML service instance from dependency injection
        current_user: Current authenticated user

    Returns:
        ModelInfoResponse: Detailed model information
    """
    try:
        logger.info(f"Getting info for ML model {model_id} for user: {current_user.id}")
        result = await ml_service.get_model_info(model_id)
        
        # Convert result to ModelInfoResponse
        return ModelInfoResponse(**result)
    except KeyError as e:
        logger.error(f"ML model not found - {model_id}: {e!s}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"ML model not found: {model_id}",
        ) from e
    except Exception as e:
        logger.error(f"Error getting ML model info: {e!s}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get ML model information",
        ) from e


@router.post(
    "/predict",
    response_model=PredictionResponse,
    summary="Make a prediction using ML model",
    description="Makes a prediction using the specified ML model with given features",
    status_code=status.HTTP_200_OK,
    tags=["Machine Learning"],
)
async def predict(
    request: PredictionRequest,
    ml_service: MLServiceDep,
    current_user: User = Depends(get_current_active_user),
) -> PredictionResponse:
    """
    Make a prediction using an ML model.

    Args:
        request: The prediction request details
        ml_service: ML service instance from dependency injection
        current_user: Current authenticated user

    Returns:
        PredictionResponse: Prediction results
    """
    try:
        logger.info(f"Making prediction with model {request.model_id} for user: {current_user.id}")
        
        # Ensure service is healthy
        if not ml_service.is_healthy():
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="ML service is not available",
            )
        
        result = await ml_service.predict(
            model_id=request.model_id,
            features=request.features,
            options=request.options
        )
        
        # HIPAA audit logging - log prediction event but not PHI
        logger.info(
            f"Prediction completed for model {request.model_id}, "
            f"user: {current_user.id}, feature count: {len(request.features)}"
        )
        
        # Convert result to PredictionResponse
        return PredictionResponse(
            prediction=result.get("prediction"),
            confidence=result.get("confidence"),
            model_id=request.model_id,
            model_version=result.get("model_version", "unknown"),
            metadata=result.get("metadata", {})
        )
    except KeyError as e:
        logger.error(f"ML model not found - {request.model_id}: {e!s}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"ML model not found: {request.model_id}",
        ) from e
    except ValueError as e:
        logger.error(f"Invalid features for prediction: {e!s}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid features for prediction: {e!s}",
        ) from e
    except Exception as e:
        logger.error(f"Error making prediction: {e!s}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to make prediction",
        ) from e


@router.post(
    "/batch-predict",
    response_model=BatchPredictionResponse,
    summary="Make batch predictions using ML model",
    description="Makes multiple predictions in batch using the specified ML model",
    status_code=status.HTTP_200_OK,
    tags=["Machine Learning"],
)
async def batch_predict(
    request: BatchPredictionRequest,
    ml_service: MLServiceDep,
    current_user: User = Depends(get_current_active_user),
) -> BatchPredictionResponse:
    """
    Make batch predictions using an ML model.

    Args:
        request: The batch prediction request details
        ml_service: ML service instance from dependency injection
        current_user: Current authenticated user

    Returns:
        BatchPredictionResponse: Batch prediction results
    """
    try:
        logger.info(
            f"Making batch prediction with model {request.model_id} "
            f"for user: {current_user.id}, batch size: {len(request.batch_features)}"
        )
        
        # Ensure service is healthy
        if not ml_service.is_healthy():
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="ML service is not available",
            )
        
        # Validate batch size
        if len(request.batch_features) > 100:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Batch size exceeds maximum limit of 100",
            )
        
        result = await ml_service.batch_predict(
            model_id=request.model_id,
            batch_features=request.batch_features,
            options=request.options
        )
        
        # HIPAA audit logging - log batch prediction event but not PHI
        logger.info(
            f"Batch prediction completed for model {request.model_id}, "
            f"user: {current_user.id}, batch size: {len(request.batch_features)}"
        )
        
        # Convert result to BatchPredictionResponse
        return BatchPredictionResponse(
            predictions=result.get("predictions", []),
            confidences=result.get("confidences"),
            model_id=request.model_id,
            model_version=result.get("model_version", "unknown"),
            metadata=result.get("metadata", {})
        )
    except KeyError as e:
        logger.error(f"ML model not found - {request.model_id}: {e!s}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"ML model not found: {request.model_id}",
        ) from e
    except ValueError as e:
        logger.error(f"Invalid features for batch prediction: {e!s}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid features for batch prediction: {e!s}",
        ) from e
    except Exception as e:
        logger.error(f"Error making batch prediction: {e!s}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to make batch prediction",
        ) from e


@router.post(
    "/feature-importance",
    response_model=FeatureImportanceResponse,
    summary="Calculate feature importance",
    description="Calculates importance scores for features in a prediction",
    status_code=status.HTTP_200_OK,
    tags=["Machine Learning"],
)
async def feature_importance(
    request: FeatureImportanceRequest,
    ml_service: MLServiceDep,
    current_user: User = Depends(get_current_active_user),
) -> FeatureImportanceResponse:
    """
    Calculate feature importance for a prediction.

    Args:
        request: The feature importance request details
        ml_service: ML service instance from dependency injection
        current_user: Current authenticated user

    Returns:
        FeatureImportanceResponse: Feature importance scores
    """
    try:
        logger.info(f"Calculating feature importance for model {request.model_id} for user: {current_user.id}")
        
        # Ensure service is healthy
        if not ml_service.is_healthy():
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="ML service is not available",
            )
        
        result = await ml_service.get_feature_importance(
            model_id=request.model_id,
            features=request.features
        )
        
        # Convert result to FeatureImportanceResponse
        return FeatureImportanceResponse(
            model_id=request.model_id,
            feature_importance=result.get("feature_importance", {}),
            prediction=result.get("prediction"),
            metadata=result.get("metadata", {})
        )
    except KeyError as e:
        logger.error(f"ML model not found - {request.model_id}: {e!s}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"ML model not found: {request.model_id}",
        ) from e
    except ValueError as e:
        logger.error(f"Invalid features for importance calculation: {e!s}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid features for importance calculation: {e!s}",
        ) from e
    except Exception as e:
        logger.error(f"Error calculating feature importance: {e!s}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to calculate feature importance",
        ) from e
