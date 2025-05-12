"""
Tests for the Symptom Forecasting Service.

This module contains tests for the Symptom Forecasting Service, which
implements psychiatric symptom forecasting using an ensemble of models,
following Clean Architecture principles and ensuring HIPAA compliance.
"""
import asyncio
import pytest
from app.tests.utils.asyncio_helpers import run_with_timeout

pytest.skip("Skipping symptom forecasting tests (torch unsupported in this environment)", allow_module_level=True)
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import numpy as np

from app.infrastructure.ml.symptom_forecasting.model_service import SymptomForecastingService


@pytest.fixture
def mock_transformer_model():
    """Create a mock transformer model."""
    model = AsyncMock()
    model.predict = AsyncMock(return_value={
        "values": np.array([[5, 4, 3, 4, 5], [3, 3, 2, 2, 3]]),
        "intervals": {
            "lower": np.array([[4, 3, 2, 3, 4], [2, 2, 1, 1, 2]]),
            "upper": np.array([[6, 5, 4, 5, 6], [4, 4, 3, 3, 4]]),
        },
        "model_type": "transformer",
    })
    return model


@pytest.fixture
def mock_xgboost_model():
    """Create a mock XGBoost model."""
    model = AsyncMock()
    model.predict = AsyncMock(return_value={
        "values": np.array([[4, 5, 3, 4, 6], [2, 3, 2, 3, 4]]),
        "feature_importance": {
            "anxiety_history": 0.3,
            "depression_history": 0.2,
            "sleep_quality": 0.15,
            "medication_adherence": 0.1,
            "social_activity": 0.05,
        },
        "model_type": "xgboost",
    })
    return model


@pytest.fixture
def forecasting_service(mock_transformer_model, mock_xgboost_model):
    """Create a Symptom Forecasting Service with mock models."""
    with patch(
        "app.infrastructure.ml.symptom_forecasting.model_service.SymptomTransformerModel",
        return_value=mock_transformer_model
    ), patch(
        "app.infrastructure.ml.symptom_forecasting.model_service.XGBoostSymptomModel",
        return_value=mock_xgboost_model
    ):
        service = SymptomForecastingService(
            model_dir="./test_models",
            feature_names=[
                "anxiety",
                "depression",
                "sleep_quality",
                "medication_adherence",
                "social_activity",
            ]
        )
        return service


@pytest.fixture
def patient_data():
    """Create sample patient data for testing."""
    return {
        "time_series": [
            {
                "date": "2023-01-01",
                "anxiety": 5,
                "depression": 3,
                "sleep_quality": 0.7,
                "medication_adherence": 0.9,
                "social_activity": 0.6,
            },
            {
                "date": "2023-01-02",
                "anxiety": 6,
                "depression": 4,
                "sleep_quality": 0.6,
                "medication_adherence": 0.8,
                "social_activity": 0.5,
            },
            {
                "date": "2023-01-03",
                "anxiety": 4,
                "depression": 3,
                "sleep_quality": 0.8,
                "medication_adherence": 0.9,
                "social_activity": 0.7,
            },
            {
                "date": "2023-01-04",
                "anxiety": 5,
                "depression": 2,
                "sleep_quality": 0.7,
                "medication_adherence": 1.0,
                "social_activity": 0.6,
            },
            {
                "date": "2023-01-05",
                "anxiety": 5,
                "depression": 3,
                "sleep_quality": 0.7,
                "medication_adherence": 0.9,
                "social_activity": 0.6,
            },
        ]
    }


@pytest.mark.asyncio()
@pytest.mark.db_required()
@pytest.mark.asyncio
async def test_preprocess_patient_data(forecasting_service, patient_data):
    """Test preprocessing of patient data."""
    patient_id = uuid4()

    # Preprocess data
    preprocessed_data = await forecasting_service.preprocess_patient_data(patient_id, patient_data)

    # Verify shape and type
    assert isinstance(preprocessed_data, np.ndarray)
    assert preprocessed_data.shape[0] == 5  # 5 time points
    assert preprocessed_data.shape[1] == 5  # 5 features

    # Verify normalization (values should be between 0 and 1)
    assert np.all(preprocessed_data >= 0)
    assert np.all(preprocessed_data <= 1)


@pytest.mark.asyncio()
async def test_preprocess_patient_data_with_missing_data(forecasting_service):
    """Test preprocessing with missing data."""
    patient_id = uuid4()

    # Create data with missing time series
    missing_data = {}

    # Verify that validation error is raised
    with pytest.raises(Exception):
        await forecasting_service.preprocess_patient_data(patient_id, missing_data)


@pytest.mark.asyncio()
async def test_forecast_symptoms_with_ensemble(forecasting_service, patient_data):
    """Test symptom forecasting with ensemble approach."""
    patient_id = uuid4()

    # Generate forecast
    forecast = await forecasting_service.forecast_symptoms(patient_id, patient_data, horizon=5, use_ensemble=True)

    # Verify forecast structure
    assert "values" in forecast
    assert "intervals" in forecast
    assert "lower" in forecast["intervals"]
    assert "upper" in forecast["intervals"]
    assert "feature_importance" in forecast
    assert "model_type" in forecast
    assert forecast["model_type"] == "ensemble"

    # Verify metadata
    assert "patient_id" in forecast
    assert forecast["patient_id"] == str(patient_id)
    assert "forecast_generated_at" in forecast
    assert "forecast_horizon" in forecast
    assert forecast["forecast_horizon"] == 5
    assert "forecast_dates" in forecast
    assert len(forecast["forecast_dates"]) == 5
    assert "target_names" in forecast


@pytest.mark.asyncio()
async def test_forecast_symptoms_without_ensemble(forecasting_service, patient_data):
    """Test symptom forecasting without ensemble approach."""
    patient_id = uuid4()

    # Generate forecast using only transformer model
    forecast = await forecasting_service.forecast_symptoms(patient_id, patient_data, horizon=5, use_ensemble=False)

    # Verify forecast structure
    assert "values" in forecast
    assert "intervals" in forecast
    assert "model_type" in forecast
    assert forecast["model_type"] == "transformer"


@pytest.mark.asyncio()
async def test_forecast_symptoms_with_insufficient_data(forecasting_service):
    """Test forecasting with insufficient data."""
    patient_id = uuid4()

    # Create data with insufficient time points
    insufficient_data = {
        "time_series": [
            {"date": "2023-01-01", "anxiety": 5, "depression": 3},
            {"date": "2023-01-02", "anxiety": 6, "depression": 4},
        ]
    }

    # Verify that validation error is raised
    with pytest.raises(Exception):
        await forecasting_service.forecast_symptoms(patient_id, insufficient_data, horizon=5)


@pytest.mark.asyncio()
async def test_analyze_symptom_patterns(forecasting_service, patient_data):
    """Test analysis of symptom patterns."""
    patient_id = uuid4()

    # Analyze symptom patterns
    patterns = await forecasting_service.analyze_symptom_patterns(patient_id, patient_data)

    # Verify patterns structure
    assert "symptom_patterns" in patterns
    assert "trend_analysis" in patterns
    assert "cyclical_patterns" in patterns
    assert "correlation_analysis" in patterns

    # Verify insights
    assert "insights" in patterns
    assert len(patterns["insights"]) > 0
    assert "insight_text" in patterns["insights"][0]
    assert "importance" in patterns["insights"][0]


@pytest.mark.asyncio()
async def test_identify_risk_periods(forecasting_service, patient_data):
    """Test identification of risk periods."""
    patient_id = uuid4()

    # First generate a forecast
    forecast = await forecasting_service.forecast_symptoms(patient_id, patient_data, horizon=14)

    # Identify risk periods
    risk_periods = await forecasting_service.identify_risk_periods(patient_id, forecast)

    # Verify risk periods structure
    assert "risk_periods" in risk_periods
    assert "high_risk_days" in risk_periods
    assert "risk_factors" in risk_periods

    # Verify alerts
    assert "alerts" in risk_periods
    for alert in risk_periods["alerts"]:
        assert "symptom" in alert
        assert "risk_level" in alert
        assert "start_date" in alert
        assert "end_date" in alert
        assert "recommendation" in alert


@pytest.mark.asyncio()
async def test_get_model_performance_metrics(forecasting_service):
    """Test retrieval of model performance metrics."""
    # Get performance metrics
    metrics = await forecasting_service.get_model_performance_metrics()

    # Verify metrics structure
    assert "transformer_model" in metrics
    assert "xgboost_model" in metrics
    assert "ensemble_model" in metrics

    # Verify metric types
    for model_type in ["transformer_model", "xgboost_model", "ensemble_model"]:
        assert "rmse" in metrics[model_type]
        assert "mae" in metrics[model_type]
        assert "r2" in metrics[model_type]
        assert "calibration_score" in metrics[model_type]


@pytest.mark.asyncio()
async def test_sanitize_patient_data(forecasting_service):
    """Test sanitization of patient data for HIPAA compliance."""
    # Create patient data with PHI
    patient_data_with_phi = {
        "patient_name": "John Doe",
        "email": "john.doe@example.com",
        "ssn": "123-45-6789",
        "time_series": [
            {
                "date": "2023-01-01",
                "anxiety": 5,
                "depression": 3,
                "notes": "Patient reported family issues",
            }
        ],
    }

    # Sanitize data using the private method
    sanitized_data = forecasting_service._sanitize_patient_data(patient_data_with_phi)

    # Verify that PHI is removed
    assert "patient_name" not in sanitized_data
    assert "email" not in sanitized_data
    assert "ssn" not in sanitized_data

    # Verify that clinical data is preserved
    assert "time_series" in sanitized_data

    # Verify that notes are redacted
    assert "notes" not in sanitized_data["time_series"][0]


@pytest.mark.asyncio()
async def test_model_failure_handling(forecasting_service, patient_data):
    """Test handling of model failures."""
    patient_id = uuid4()

    # Make transformer model fail
    forecasting_service.transformer_model.predict.side_effect = Exception("Model failure")

    # Verify that service handles the failure gracefully
    with pytest.raises(Exception):
        await forecasting_service.forecast_symptoms(patient_id, patient_data, use_ensemble=True)

    # Reset transformer model and make XGBoost model fail
    forecasting_service.transformer_model.predict.side_effect = None
    forecasting_service.xgboost_model.predict.side_effect = Exception("Model failure")

    # Verify that service falls back to transformer model only
    forecast = await forecasting_service.forecast_symptoms(patient_id, patient_data, use_ensemble=True)

    # Verify that forecast is still generated using transformer model
    assert forecast["model_type"] == "transformer"
