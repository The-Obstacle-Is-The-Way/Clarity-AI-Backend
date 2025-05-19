"""
XGBoost ML API Endpoints.

This module provides FastAPI endpoints for interacting with XGBoost
machine learning models for psychiatric predictions.
"""

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Path, status
from pydantic import BaseModel

from app.core.services.ml.xgboost.exceptions import (
    ConfigurationError,
    InvalidInputError,
    ModelNotFoundError,
    PredictionError,
    ServiceConnectionError,
)
from app.core.services.ml.xgboost.factory import get_xgboost_service
from app.core.services.ml.xgboost.interface import XGBoostInterface
from app.domain.entities.ml.enums import ResponseLevel
from app.presentation.api.dependencies.auth import get_current_user

# Create logger
logger = logging.getLogger(__name__)

# Create router
router = APIRouter(tags=["XGBoost ML"])


# Define request/response models
class RiskPredictionRequest(BaseModel):
    patient_id: str
    risk_type: str
    clinical_data: dict[str, Any]


class RiskFactorResponse(BaseModel):
    name: str
    contribution: float
    description: str | None = None


class RiskPredictionResponse(BaseModel):
    prediction_id: str
    patient_id: str
    prediction: dict[str, Any]
    timestamp: str
    model_version: str


class TreatmentResponseRequest(BaseModel):
    patient_id: str
    treatment_type: str
    treatment_details: dict[str, Any]
    clinical_data: dict[str, Any]


class TreatmentResponsePrediction(BaseModel):
    response_level: ResponseLevel
    confidence: float
    expected_phq9_reduction: int
    expected_response_time_weeks: int
    alternative_treatments: list[dict[str, Any]]


class TreatmentResponseResult(BaseModel):
    prediction_id: str
    patient_id: str
    prediction: TreatmentResponsePrediction
    timestamp: str
    model_version: str


class OutcomePredictionRequest(BaseModel):
    patient_id: str
    outcome_timeframe: dict[str, int]
    clinical_data: dict[str, Any]
    treatment_plan: dict[str, Any]


class OutcomePredictionResponse(BaseModel):
    prediction_id: str
    patient_id: str
    prediction: dict[str, Any]
    timestamp: str
    model_version: str


class DigitalTwinSimulationRequest(BaseModel):
    patient_id: str
    simulation_timeframe: dict[str, int]
    treatment_plan: dict[str, Any]
    baseline_metrics: dict[str, Any]


class DigitalTwinSimulationResponse(BaseModel):
    simulation_id: str
    patient_id: str
    simulation_results: list[dict[str, Any]]
    timestamp: str
    model_version: str


class ModelInfoResponse(BaseModel):
    model_type: str
    version: str
    training_date: str
    features: list[str]
    performance: dict[str, float]
    last_updated: str


class FeatureImportanceResponse(BaseModel):
    model_type: str
    features: list[dict[str, Any]]
    timestamp: str


@router.post("/risk-prediction", response_model=RiskPredictionResponse)
async def predict_risk(
    request: RiskPredictionRequest,
    xgboost_service: XGBoostInterface = Depends(get_xgboost_service),
    current_user: dict = Depends(get_current_user),
) -> RiskPredictionResponse:
    """
    Predict risk level using XGBoost models.
    """
    try:
        result = await xgboost_service.predict_risk(
            patient_id=request.patient_id,
            risk_type=request.risk_type,
            clinical_data=request.clinical_data,
        )
        return result
    except ModelNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except InvalidInputError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e)
        )
    except ConfigurationError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)
        )
    except ServiceConnectionError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Failed to connect to prediction service",
        )
    except Exception as e:
        logger.exception(f"Error in risk prediction: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred",
        )


@router.post("/treatment-response", response_model=TreatmentResponseResult)
async def predict_treatment_response(
    request: TreatmentResponseRequest,
    xgboost_service: XGBoostInterface = Depends(get_xgboost_service),
    current_user: dict = Depends(get_current_user),
) -> TreatmentResponseResult:
    """
    Predict treatment response for a given patient and treatment.
    """
    try:
        result = await xgboost_service.predict_treatment_response(
            patient_id=request.patient_id,
            treatment_type=request.treatment_type,
            treatment_details=request.treatment_details,
            clinical_data=request.clinical_data,
        )
        return result
    except ModelNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except PredictionError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e)
        )
    except ServiceConnectionError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Failed to connect to prediction service",
        )
    except Exception as e:
        logger.exception(f"Error in treatment response prediction: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred",
        )


@router.post("/outcome-prediction", response_model=OutcomePredictionResponse)
async def predict_outcome(
    request: OutcomePredictionRequest,
    xgboost_service: XGBoostInterface = Depends(get_xgboost_service),
    current_user: dict = Depends(get_current_user),
) -> OutcomePredictionResponse:
    """
    Predict treatment outcome for a patient.
    """
    try:
        result = await xgboost_service.predict_outcome(
            patient_id=request.patient_id,
            outcome_timeframe=request.outcome_timeframe,
            clinical_data=request.clinical_data,
            treatment_plan=request.treatment_plan,
        )
        return result
    except ModelNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except InvalidInputError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e)
        )
    except ServiceConnectionError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Failed to connect to prediction service",
        )
    except Exception as e:
        logger.exception(f"Error in outcome prediction: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred",
        )


@router.get(
    "/feature-importance/{model_type}", response_model=FeatureImportanceResponse
)
async def get_feature_importance(
    model_type: str = Path(
        ..., description="Type of model to get feature importance for"
    ),
    xgboost_service: XGBoostInterface = Depends(get_xgboost_service),
    current_user: dict = Depends(get_current_user),
) -> FeatureImportanceResponse:
    """
    Get feature importance for a specific model type.
    """
    try:
        result = await xgboost_service.get_feature_importance(model_type=model_type)
        return result
    except ModelNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        logger.exception(f"Error getting feature importance: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred",
        )


@router.post("/digital-twin-simulation", response_model=DigitalTwinSimulationResponse)
async def simulate_digital_twin(
    request: DigitalTwinSimulationRequest,
    xgboost_service: XGBoostInterface = Depends(get_xgboost_service),
    current_user: dict = Depends(get_current_user),
) -> DigitalTwinSimulationResponse:
    """
    Run a digital twin simulation for a patient.
    """
    try:
        result = await xgboost_service.simulate_digital_twin(
            patient_id=request.patient_id,
            simulation_timeframe=request.simulation_timeframe,
            treatment_plan=request.treatment_plan,
            baseline_metrics=request.baseline_metrics,
        )
        return result
    except ModelNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except InvalidInputError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e)
        )
    except ServiceConnectionError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Failed to connect to simulation service",
        )
    except Exception as e:
        logger.exception(f"Error in digital twin simulation: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred",
        )


@router.get("/model-info/{model_type}", response_model=ModelInfoResponse)
async def get_model_info(
    model_type: str = Path(..., description="Type of model to get info for"),
    xgboost_service: XGBoostInterface = Depends(get_xgboost_service),
    current_user: dict = Depends(get_current_user),
) -> ModelInfoResponse:
    """
    Get information about a specific model type.
    """
    try:
        result = await xgboost_service.get_model_info(model_type=model_type)
        return ModelInfoResponse(
            model_type=result.get("model_type", model_type),
            version=result.get("version", "1.0.0"),
            training_date=result.get("training_date", "2023-01-01"),
            features=result.get("features", []),
            performance=result.get("performance", {"auc": 0.85, "accuracy": 0.82}),
            last_updated=result.get("last_updated", "2023-01-01"),
        )
    except ModelNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        logger.exception(f"Error getting model info: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred",
        )
