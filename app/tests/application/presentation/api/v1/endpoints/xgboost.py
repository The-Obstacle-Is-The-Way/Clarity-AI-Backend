"""
XGBoost Service API Endpoints.

Provides API endpoints for interacting with the XGBoost prediction service.
"""

import inspect
import logging
from types import SimpleNamespace
from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, status
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse

from app.api.routes.xgboost import get_xgboost_service, validate_permissions
from app.core.services.ml.xgboost.exceptions import (
    DataPrivacyError,
    ModelNotFoundError,
    ResourceNotFoundError,
    ServiceUnavailableError,
    ValidationError,
    XGBoostServiceError,
)
from app.core.services.ml.xgboost.interface import XGBoostInterface

# Authentication and DI dependencies now via alias module
# current_user and verify_provider_access imported above
from app.presentation.api.dependencies.auth import verify_provider_access
from app.presentation.api.v1.schemas.xgboost_schemas import (
    DigitalTwinIntegrationRequest,
    FeatureImportanceRequest,
    ModelInfoRequest,
    ModelInfoResponse,
    OutcomePredictionRequest,
    RiskPredictionRequest,
    TreatmentResponseRequest,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["XGBoost ML"])


@router.post(
    "/predict/risk",
    summary="Predict Patient Risk",
    description="Predicts various risk types (e.g., relapse, suicide) using XGBoost models.",
    status_code=status.HTTP_200_OK,
    response_class=JSONResponse,
)
async def predict_risk(
    request: RiskPredictionRequest,
    # Authenticate request (overrideable in tests)
    current_user: Any = Depends(verify_provider_access),
    xgboost_service: XGBoostInterface = Depends(get_xgboost_service),
) -> JSONResponse:
    """Endpoint to predict patient risk using XGBoost."""
    # Authorization passed via dependency injection (verify_provider_access)
    try:
        # Debug: log the actual service instance class
        logger.info(
            f"XGBoostService instance in predict_risk: {xgboost_service.__class__.__name__}"
        )

        # Call the XGBoost service via injected dependency
        # The service returns either a coroutine or a direct result
        result = xgboost_service.predict_risk(
            patient_id=request.patient_id,
            risk_type=request.risk_type,
            clinical_data=request.clinical_data,
            time_frame_days=request.time_frame_days,
        )

        # Properly await the result if it's a coroutine
        if inspect.iscoroutine(result):
            result = await result

        # Handle SimpleNamespace objects for compatibility
        if isinstance(result, SimpleNamespace):
            result = result.__dict__

        # Use the result directly
        data = result

        # Debug: log prediction data
        logger.info(f"predict_risk result data: {data!r}")

        # Construct consistent response payload
        output: dict[str, Any] = {
            "prediction_id": data.get("prediction_id"),
            "patient_id": data.get("patient_id"),
            "risk_type": data.get("risk_type"),
            "risk_score": data.get("risk_score"),
            "risk_level": data.get("risk_level"),
            "confidence": data.get("confidence"),
            "factors": data.get("factors", []),
            "timestamp": data.get("timestamp"),
        }

        # Include additional details if provided
        if isinstance(data, dict) and "details" in data:
            output["details"] = data.get("details")

        # Return consistent JSONResponse format
        return JSONResponse(content=jsonable_encoder(output))
    except ValidationError as e:
        logger.warning(f"Validation error during risk prediction: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except DataPrivacyError as e:
        logger.warning(f"Data privacy error during risk prediction: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Sensitive information detected",
        )
    except ModelNotFoundError as e:
        logger.error(f"Model not found for risk prediction: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except ServiceUnavailableError as e:
        logger.error(f"Service unavailable during risk prediction: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(e)
        )
    except XGBoostServiceError as e:
        logger.error(
            f"XGBoost service error during risk prediction: {e}", exc_info=True
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(e)
        )
    except Exception:
        logger.exception(
            f"Unexpected error during risk prediction for patient {request.patient_id}"
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred during risk prediction.",
        )


@router.post(
    "/predict/treatment-response",
    summary="Predict Treatment Response",
    description="Predicts patient response to specific treatments using XGBoost models.",
    status_code=status.HTTP_200_OK,
    response_class=JSONResponse,
)
async def predict_treatment_response(
    request: TreatmentResponseRequest,
    xgboost_service: XGBoostInterface = Depends(get_xgboost_service),
) -> JSONResponse:
    """Endpoint to predict treatment response using XGBoost."""
    try:
        validate_permissions()
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    try:
        # Use injected XGBoost service with proper async handling
        raw = xgboost_service.predict_treatment_response(
            patient_id=request.patient_id,
            treatment_type=request.treatment_type,
            treatment_details=request.treatment_details,
            clinical_data=request.clinical_data,
        )
        # Ensure we properly await the result if it's a coroutine
        if inspect.iscoroutine(raw):
            raw = await raw
        # Handle various return types for compatibility
        if isinstance(raw, SimpleNamespace):
            raw = raw.__dict__
        # Ensure consistent return format
        content = jsonable_encoder(raw)
        return JSONResponse(content=content)
    except ValidationError as e:
        logger.warning(
            f"Validation error during treatment response prediction: {e}", exc_info=True
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except ModelNotFoundError as e:
        logger.error(
            f"Model not found for treatment response prediction: {e}", exc_info=True
        )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except ServiceUnavailableError as e:
        logger.error(
            f"Service unavailable during treatment response prediction: {e}",
            exc_info=True,
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(e)
        )
    except XGBoostServiceError as e:
        logger.error(
            f"XGBoost service error during treatment response prediction: {e}",
            exc_info=True,
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(e)
        )
    except Exception:
        logger.exception(
            f"Unexpected error during treatment response prediction for patient {request.patient_id}"
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred during treatment response prediction.",
        )


@router.post(
    "/predict/outcome",
    summary="Predict Clinical Outcome",
    description="Predicts clinical outcomes based on patient data and treatment plan using XGBoost models.",
    status_code=status.HTTP_200_OK,
    response_class=JSONResponse,
)
async def predict_outcome(
    request: OutcomePredictionRequest,
    xgboost_service: XGBoostInterface = Depends(get_xgboost_service),
) -> JSONResponse:
    """Endpoint to predict clinical outcome using XGBoost."""
    try:
        validate_permissions()
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    try:
        # Invoke service method which may return a coroutine or direct result
        result = xgboost_service.predict_outcome(
            patient_id=request.patient_id,
            outcome_timeframe=request.outcome_timeframe,
            clinical_data=request.clinical_data,
            treatment_plan=request.treatment_plan,
            social_determinants=request.social_determinants
            if hasattr(request, "social_determinants")
            else None,
            comorbidities=request.comorbidities
            if hasattr(request, "comorbidities")
            else None,
        )

        # Properly await if coroutine
        if inspect.iscoroutine(result):
            result = await result

        # Handle SimpleNamespace objects for compatibility
        if isinstance(result, SimpleNamespace):
            result = result.__dict__

        # Return consistent JSONResponse format
        return JSONResponse(content=jsonable_encoder(result))
    except ValidationError as e:
        logger.warning(
            f"Validation error during outcome prediction: {e}", exc_info=True
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except DataPrivacyError as e:
        logger.warning(
            f"Data privacy error during outcome prediction: {e}", exc_info=True
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except ModelNotFoundError as e:
        logger.error(f"Model not found for outcome prediction: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except ServiceUnavailableError as e:
        logger.error(
            f"Service unavailable during outcome prediction: {e}", exc_info=True
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(e)
        )
    except XGBoostServiceError as e:
        logger.error(
            f"XGBoost service error during outcome prediction: {e}", exc_info=True
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(e)
        )
    except Exception:
        logger.exception(
            f"Unexpected error during outcome prediction for patient {request.patient_id}"
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred during outcome prediction.",
        )


@router.get(
    "/model-info/{model_type}",
    summary="Get Model Information",
    description="Retrieves metadata and information about a specific XGBoost model.",
    status_code=status.HTTP_200_OK,
)
async def get_model_info(
    model_type: str,  # Or use ModelType enum if defined appropriately
    xgboost_service: XGBoostInterface = Depends(get_xgboost_service),
) -> dict:
    """Endpoint to get information about an XGBoost model."""
    try:
        # Handle sync or async service methods
        raw = xgboost_service.get_model_info(model_type=model_type)
        info = await raw if inspect.iscoroutine(raw) else raw
        return info
    except ModelNotFoundError as e:
        logger.warning(f"Model info not found for type '{model_type}': {e}")
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except XGBoostServiceError as e:
        logger.error(
            f"XGBoost service error retrieving model info for '{model_type}': {e}",
            exc_info=True,
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"XGBoost service error: {e}",
        )
    except Exception:
        logger.exception(f"Unexpected error retrieving model info for '{model_type}'")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred while retrieving model information.",
        )


@router.post(
    "/model-info",
    summary="Get Model Information",
    description="Retrieves metadata and information about a specific XGBoost model.",
    status_code=status.HTTP_200_OK,
    response_model=ModelInfoResponse,
    response_class=JSONResponse,
)
async def post_model_info(
    request: ModelInfoRequest,
    xgboost_service: XGBoostInterface = Depends(get_xgboost_service),
) -> JSONResponse:
    """Endpoint to get information about an XGBoost model."""
    try:
        # Call service which may return coroutine
        result = xgboost_service.get_model_info(model_type=request.model_type)

        # Handle async result properly
        if inspect.iscoroutine(result):
            result = await result

        # Convert SimpleNamespace to dict if needed
        if isinstance(result, SimpleNamespace):
            result = result.__dict__

        # Return consistent JSONResponse format
        return JSONResponse(content=jsonable_encoder(result))
    except ModelNotFoundError as e:
        logger.warning(f"Model info not found for type '{request.model_type}': {e}")
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except ServiceUnavailableError as e:
        logger.error(
            f"Service unavailable during model info retrieval: {e}", exc_info=True
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(e)
        )
    except XGBoostServiceError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(e)
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred while retrieving model information.",
        )


@router.get(
    "/feature-importance/{model_type}/{prediction_id}",
    summary="Get Feature Importance",
    description="Retrieves feature importance metrics for a previously generated prediction.",
    status_code=status.HTTP_200_OK,
)
async def get_feature_importance(
    model_type: str,
    prediction_id: str,
    patient_id: str | None = None,
    xgboost_service: XGBoostInterface = Depends(get_xgboost_service),
) -> dict:
    """Endpoint to get feature importance for a prediction."""
    try:
        # Handle sync or async service methods
        raw = xgboost_service.get_feature_importance(
            model_type=model_type, prediction_id=prediction_id, patient_id=patient_id
        )
        importance_data = await raw if inspect.iscoroutine(raw) else raw
        return importance_data
    except ValidationError as e:
        logger.warning(f"Validation error: {e}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except ModelNotFoundError as e:
        logger.error(f"Model not found: {e}")
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except ResourceNotFoundError as e:
        logger.error(f"Feature importance not found: {e}")
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except ServiceUnavailableError as e:
        logger.error(f"Service unavailable: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(e)
        )
    except Exception:
        logger.exception("Unexpected error during feature importance retrieval")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred during feature importance retrieval.",
        )


@router.post(
    "/feature-importance",
    summary="Get Feature Importance",
    description="Retrieves feature importance metrics for a previously generated prediction.",
    status_code=status.HTTP_200_OK,
    response_class=JSONResponse,
)
async def feature_importance_post(
    request: FeatureImportanceRequest,
    xgboost_service: XGBoostInterface = Depends(get_xgboost_service),
) -> JSONResponse:
    """Endpoint to integrate prediction with Digital Twin."""
    try:
        validate_permissions()
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    try:
        # Will raise ResourceNotFoundError if prediction doesn't exist
        # or if patient_id doesn't match (security check)
        raw_result = xgboost_service.get_feature_importance(
            patient_id=request.patient_id,
            model_type=request.model_type,
            prediction_id=request.prediction_id,
        )

        # Handle async result properly
        result = await raw_result if inspect.iscoroutine(raw_result) else raw_result

        # Handle SimpleNamespace objects for compatibility
        if isinstance(result, SimpleNamespace):
            result = result.__dict__

        # Return consistent JSONResponse format
        return JSONResponse(content=jsonable_encoder(result))
    except ResourceNotFoundError as e:
        logger.error(f"Feature importance not found: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except ValidationError as e:
        logger.warning(
            f"Validation error during feature importance retrieval: {e}", exc_info=True
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except ServiceUnavailableError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(e)
        )
    except XGBoostServiceError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(e)
        )
    except Exception:
        logger.exception(
            f"Unexpected error during feature importance retrieval for prediction {request.prediction_id}"
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred during feature importance retrieval.",
        )


@router.post(
    "/digital-twin-simulation",
    summary="Simulate Digital Twin",
    description="Simulates patient progression using digital twin concept.",
    status_code=status.HTTP_200_OK,
    response_class=JSONResponse,
)
async def digital_twin_simulation(
    request_data: dict[str, Any] = Body(...),
    xgboost_service: XGBoostInterface = Depends(get_xgboost_service),
) -> JSONResponse:
    """Endpoint to simulate a digital twin using XGBoost."""
    try:
        validate_permissions()
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))

    # More implementation would go here

    return JSONResponse(content={"status": "simulation_pending"})


@router.post(
    "/integrate-digital-twin",
    summary="Integrate Prediction with Digital Twin",
    description="Integrates a prediction with a patient's digital twin profile.",
    status_code=status.HTTP_200_OK,
    response_class=JSONResponse,
)
async def integrate_with_digital_twin(
    request: DigitalTwinIntegrationRequest,
    xgboost_service: XGBoostInterface = Depends(get_xgboost_service),
) -> JSONResponse:
    """Endpoint to integrate prediction with Digital Twin."""
    try:
        validate_permissions()
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    try:
        # Call service method which may return coroutine
        result = xgboost_service.integrate_with_digital_twin(
            patient_id=request.patient_id,
            profile_id=request.profile_id,
            prediction_id=request.prediction_id,
        )

        # Handle async result properly
        if inspect.iscoroutine(result):
            result = await result

        # Handle SimpleNamespace objects for compatibility
        if isinstance(result, SimpleNamespace):
            result = result.__dict__

        # Return consistent JSONResponse format
        return JSONResponse(content=jsonable_encoder(result))
    except ResourceNotFoundError as e:
        logger.error(f"Required resource not found: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except ValidationError as e:
        logger.warning(
            f"Validation error during digital twin integration: {e}", exc_info=True
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except ServiceUnavailableError as e:
        logger.error(
            f"Service unavailable during digital twin integration: {e}", exc_info=True
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(e)
        )
    except XGBoostServiceError as e:
        logger.error(
            f"XGBoost service error during digital twin integration: {e}", exc_info=True
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(e)
        )
    except Exception:
        logger.exception(
            f"Unexpected error during digital twin integration for patient {request.patient_id}"
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred during digital twin integration.",
        )
