"""
XGBoost ML Service API Router.
"""

from fastapi import APIRouter, Depends, HTTPException
from uuid import UUID
from typing import Dict, Any

# Local imports
from app.core.services.ml.xgboost.factory import get_xgboost_service
from app.core.services.ml.xgboost.interface import XGBoostInterface

# Initialize router
router = APIRouter(prefix="/xgboost", tags=["XGBoost"])

def get_service() -> XGBoostInterface:
    """Dependency to get the XGBoost service instance."""
    return get_xgboost_service()

@router.post("/predict")
async def predict(
    patient_id: UUID,
    features: Dict[str, Any],
    model_type: str,
    service: XGBoostInterface = Depends(get_service)
) -> Dict[str, Any]:
    """
    Execute prediction using XGBoost model.
    
    Args:
        patient_id: Unique identifier for the patient
        features: Dictionary of input features for prediction
        model_type: Type of XGBoost model to use
        
    Returns:
        Dictionary containing prediction results and confidence scores
    """
    try:
        return await service.predict(patient_id, features, model_type)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Prediction failed: {str(e)}")

@router.get("/models/{model_type}")
async def get_model_info(
    model_type: str,
    service: XGBoostInterface = Depends(get_service)
) -> Dict[str, Any]:
    """
    Get information about available XGBoost models.
    
    Args:
        model_type: Type of model to get info for
        
    Returns:
        Dictionary containing model metadata and capabilities
    """
    try:
        return await service.get_model_info(model_type)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Model info retrieval failed: {str(e)}")

@router.get("/health")
async def healthcheck(
    service: XGBoostInterface = Depends(get_service)
) -> Dict[str, Any]:
    """
    Check health status of XGBoost service.
    
    Returns:
        Dictionary containing service health status and dependencies
    """
    try:
        return await service.healthcheck()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Health check failed: {str(e)}")