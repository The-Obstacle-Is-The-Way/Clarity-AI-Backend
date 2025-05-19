"""
XGBoost ML Service API Router.
"""

from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Path, Request
from fastapi.responses import JSONResponse

from app.core.exceptions.data_privacy import DataPrivacyError

# Local imports
from app.core.services.ml.xgboost.factory import get_xgboost_service
from app.core.services.ml.xgboost.interface import XGBoostInterface

# Initialize router with v1 prefix to match the test expectations
router = APIRouter(prefix="/api/v1/xgboost", tags=["XGBoost"])


# Custom exception handler for DataPrivacyError
@router.exception_handler(DataPrivacyError)
async def data_privacy_exception_handler(request: Request, exc: DataPrivacyError):
    return JSONResponse(
        status_code=400,
        content={"message": f"PHI detected: {exc!s}", "privacy_violation": True},
    )


def get_service() -> XGBoostInterface:
    """Dependency to get the XGBoost service instance."""
    return get_xgboost_service()


@router.post("/predict/risk")
async def predict_risk(
    request: dict[str, Any] = Body(...),
    service: XGBoostInterface = Depends(get_service),
) -> dict[str, Any]:
    """
    Execute risk prediction using XGBoost model.

    Args:
        request: Dictionary containing patient_id, risk_type, clinical_data, etc.
        service: XGBoost service instance

    Returns:
        Dictionary containing risk prediction results
    """
    try:
        # Extract data from request
        patient_id = request.get("patient_id")
        risk_type = request.get("risk_type")
        clinical_data = request.get("clinical_data", {})
        time_frame_days = request.get("time_frame_days")

        # Validate required fields
        if not patient_id:
            raise HTTPException(status_code=422, detail="patient_id is required")
        if not risk_type:
            raise HTTPException(status_code=422, detail="risk_type is required")

        # Call service method
        result = await service.predict_risk(
            patient_id=patient_id,
            risk_type=risk_type,
            clinical_data=clinical_data,
            time_frame_days=time_frame_days,
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Risk prediction failed: {e!s}")


@router.post("/predict/treatment-response")
async def predict_treatment_response(
    request: dict[str, Any] = Body(...),
    service: XGBoostInterface = Depends(get_service),
) -> dict[str, Any]:
    """
    Execute treatment response prediction using XGBoost model.

    Args:
        request: Dictionary containing patient_id, treatment_type, clinical_data, etc.
        service: XGBoost service instance

    Returns:
        Dictionary containing treatment response prediction results
    """
    try:
        # Extract data from request
        patient_id = request.get("patient_id")
        treatment_type = request.get("treatment_type")
        treatment_details = request.get("treatment_details", {})
        clinical_data = request.get("clinical_data", {})

        # Validate required fields
        if not patient_id:
            raise HTTPException(status_code=422, detail="patient_id is required")
        if not treatment_type:
            raise HTTPException(status_code=422, detail="treatment_type is required")

        # Call service method
        result = await service.predict_treatment_response(
            patient_id=patient_id,
            treatment_type=treatment_type,
            treatment_details=treatment_details,
            clinical_data=clinical_data,
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Treatment response prediction failed: {e!s}")


@router.post("/predict/outcome")
async def predict_outcome(
    request: dict[str, Any] = Body(...),
    service: XGBoostInterface = Depends(get_service),
) -> dict[str, Any]:
    """
    Execute outcome prediction using XGBoost model.

    Args:
        request: Dictionary containing patient_id, outcome_timeframe, clinical_data, etc.
        service: XGBoost service instance

    Returns:
        Dictionary containing outcome prediction results
    """
    try:
        # Extract data from request
        patient_id = request.get("patient_id")
        outcome_timeframe = request.get("outcome_timeframe", {})
        clinical_data = request.get("clinical_data", {})
        treatment_plan = request.get("treatment_plan", {})
        social_determinants = request.get("social_determinants")
        comorbidities = request.get("comorbidities")

        # Validate required fields
        if not patient_id:
            raise HTTPException(status_code=422, detail="patient_id is required")

        # Call service method
        result = await service.predict_outcome(
            patient_id=patient_id,
            outcome_timeframe=outcome_timeframe,
            clinical_data=clinical_data,
            treatment_plan=treatment_plan,
            social_determinants=social_determinants,
            comorbidities=comorbidities,
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Outcome prediction failed: {e!s}")


@router.get("/models/{model_type}")
async def get_model_info(
    model_type: str, service: XGBoostInterface = Depends(get_service)
) -> dict[str, Any]:
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
        raise HTTPException(status_code=500, detail=f"Failed to get model info: {e!s}")


@router.get("/models/{model_type}/info")
async def get_model_info_alt(
    model_type: str, service: XGBoostInterface = Depends(get_service)
) -> dict[str, Any]:
    """
    Alternative endpoint for model info to match integration test paths.

    Args:
        model_type: Type of model to get info for

    Returns:
        Dictionary containing model metadata and capabilities
    """
    try:
        return await service.get_model_info(model_type)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get model info: {e!s}")


@router.get("/info/{model_type}")
async def get_model_info_v1(
    model_type: str = Path(..., description="Type of model to get info for"),
    service: XGBoostInterface = Depends(get_service),
) -> dict[str, Any]:
    """
    Get information about available XGBoost models via POST request.

    Args:
        request: Dictionary containing model_type
        service: XGBoost service instance

    Returns:
        Dictionary containing model metadata and capabilities
    """
    try:
        # Call service method
        result = await service.get_model_info(model_type)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get model info: {e!s}")


@router.get("/explain/{model_type}/{prediction_id}")
async def get_feature_importance_v1(
    model_type: str = Path(..., description="Type of model"),
    prediction_id: str = Path(..., description="ID of the prediction to explain"),
    service: XGBoostInterface = Depends(get_service),
) -> dict[str, Any]:
    """
    Get feature importance for a prediction (path format 1).

    Args:
        model_type: Type of model
        prediction_id: ID of the prediction to explain
        service: XGBoost service instance

    Returns:
        Dictionary containing feature importance data
    """
    try:
        # Get patient_id from query params if available
        patient_id = None

        # Call service method
        result = await service.get_feature_importance(
            patient_id=patient_id, model_type=model_type, prediction_id=prediction_id
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get feature importance: {e!s}")


@router.get("/predictions/{prediction_id}/feature-importance")
async def get_feature_importance_v2(
    prediction_id: str = Path(..., description="ID of the prediction to explain"),
    service: XGBoostInterface = Depends(get_service),
) -> dict[str, Any]:
    """
    Get feature importance for a prediction (path format 2).

    Args:
        prediction_id: ID of the prediction to explain
        service: XGBoost service instance

    Returns:
        Dictionary containing feature importance data
    """
    try:
        # For this endpoint pattern, we'll default to a generic model type
        model_type = "default"
        patient_id = None

        # Call service method
        result = await service.get_feature_importance(
            patient_id=patient_id, model_type=model_type, prediction_id=prediction_id
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get feature importance: {e!s}")


@router.post("/integrate/{prediction_id}")
async def integrate_with_digital_twin(
    prediction_id: str = Path(..., description="ID of the prediction to integrate"),
    request: dict[str, Any] = Body(default={}),
    service: XGBoostInterface = Depends(get_service),
) -> dict[str, Any]:
    """
    Integrate a prediction with a digital twin.

    Args:
        request: Dictionary containing patient_id, profile_id, prediction_id
        service: XGBoost service instance

    Returns:
        Dictionary containing integration results
    """
    try:
        # Extract data from request
        request = request or {}
        patient_id = request.get("patient_id")
        profile_id = request.get("profile_id")
        additional_data = request.get("additional_data")

        # Call service method with prediction_id from path
        result = await service.integrate_with_digital_twin(
            patient_id=patient_id,
            profile_id=profile_id,
            prediction_id=prediction_id,
            additional_data=additional_data,
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to integrate with digital twin: {e!s}")


@router.get("/health")
async def healthcheck(
    service: XGBoostInterface = Depends(get_service),
) -> dict[str, Any]:
    """
    Check health status of XGBoost service.

    Returns:
        Dictionary containing service health status and dependencies
    """
    try:
        return await service.healthcheck()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Health check failed: {e!s}")
