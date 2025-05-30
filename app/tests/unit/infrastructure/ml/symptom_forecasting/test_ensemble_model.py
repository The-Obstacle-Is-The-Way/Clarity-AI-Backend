"""Unit tests for the Ensemble Model for symptom forecasting."""

import pytest

pytest.skip("Skipping ensemble model tests (torch unsupported)", allow_module_level=True)
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import numpy as np
import pandas as pd

from app.infrastructure.ml.symptom_forecasting.ensemble_model import (
    SymptomForecastingEnsemble,
)
from app.infrastructure.ml.symptom_forecasting.transformer_model import (
    SymptomTransformerModel as TransformerModel,
)
from app.infrastructure.ml.symptom_forecasting.xgboost_model import XGBoostSymptomModel


class TestEnsembleModel:
    """Test suite for the EnsembleModel class."""

    @pytest.fixture
    def ml_settings(self):
        """Create ML settings for testing."""
        return MLSettings()

    @pytest.fixture
    def mock_transformer_model(self):
        """Create a mock transformer model."""
        model = MagicMock(spec=TransformerModel)
        model.predict = AsyncMock(return_value=np.array([4.2, 4.0, 3.8, 3.6, 3.4]))
        return model

    @pytest.fixture
    def mock_xgboost_model(self):
        """Create a mock XGBoost model."""
        model = MagicMock(spec=XGBoostSymptomModel)
        model.predict = AsyncMock(return_value=np.array([4.0, 3.9, 3.7, 3.5, 3.3]))
        return model

    @pytest.fixture
    def ensemble_model(self, ml_settings, mock_transformer_model, mock_xgboost_model):
        """Create an ensemble model with mock component models."""
        # Create an ensemble model with mock component models
        ensemble = SymptomForecastingEnsemble(settings=ml_settings)

        # Replace the actual model components with mocks
        ensemble.models = {
            "transformer": mock_transformer_model,
            "xgboost": mock_xgboost_model,
        }

        # Define ensemble weights
        ensemble.ensemble_weights = {"transformer": 0.7, "xgboost": 0.3}

        return ensemble

    @pytest.fixture
    def sample_input_data(self):
        """Create sample input data for testing."""
        # Create a DataFrame with symptom severity data
        dates = pd.date_range(start=datetime.now() - timedelta(days=10), periods=10, freq="D")
        data = {
            "date": dates,
            "symptom_severity": [7, 6, 6, 5, 5, 4, 4, 4, 3, 3],
            "sleep_hours": [5.0, 5.5, 6.0, 6.5, 7.0, 7.5, 8.0, 8.0, 8.5, 8.5],
            "heart_rate_avg": [85, 82, 80, 78, 75, 72, 70, 68, 68, 67],
        }
        return pd.DataFrame(data)

    @pytest.mark.asyncio
    async def test_initialize(self, ml_settings) -> None:
        """Test initialization of the ensemble model."""
        model = SymptomForecastingEnsemble(settings=ml_settings)

        # Verify models dictionary is initialized
        assert isinstance(model.models, dict)
        assert "transformer" in model.models
        assert "xgboost" in model.models

        # Verify ensemble weights are initialized
        assert isinstance(model.ensemble_weights, dict)
        assert model.ensemble_weights["transformer"] + model.ensemble_weights["xgboost"] == 1.0

    @pytest.mark.asyncio
    async def test_predict(self, ensemble_model, sample_input_data) -> None:
        """Test the predict method of the ensemble model."""
        # Set up
        forecast_days = 5
        symptom_type = "anxiety"

        # Execute
        result = await ensemble_model.predict(
            patient_data=sample_input_data,
            symptom_type=symptom_type,
            forecast_days=forecast_days,
        )

        # Verify
        assert "predictions" in result
        assert len(result["predictions"]) == forecast_days
        assert "std" in result
        assert len(result["std"]) == forecast_days
        assert "contributing_models" in result
        assert "transformer" in result["contributing_models"]
        assert "xgboost" in result["contributing_models"]

        # Verify the weights are correctly reported
        assert result["contributing_models"]["transformer"]["weight"] == 0.7
        assert result["contributing_models"]["xgboost"]["weight"] == 0.3

        # Verify predictions are a weighted average
        expected_predictions = 0.7 * np.array([4.2, 4.0, 3.8, 3.6, 3.4]) + 0.3 * np.array(
            [4.0, 3.9, 3.7, 3.5, 3.3]
        )
        np.testing.assert_allclose(result["predictions"], expected_predictions, rtol=1e-5)

    @pytest.mark.asyncio
    async def test_predict_with_invalid_parameters(self, ensemble_model, sample_input_data) -> None:
        """Test predict method with invalid parameters."""
        # Set up
        symptom_type = "anxiety"

        # Test with invalid forecast days
        with pytest.raises(ValueError, match="Forecast days must be a positive integer"):
            await ensemble_model.predict(
                patient_data=sample_input_data,
                symptom_type=symptom_type,
                forecast_days=-1,
            )

        # Test with missing required columns
        incomplete_data = sample_input_data.drop(columns=["symptom_severity"])
        with pytest.raises(ValueError, match="Missing required columns"):
            await ensemble_model.predict(
                patient_data=incomplete_data, symptom_type=symptom_type, forecast_days=5
            )

    @pytest.mark.asyncio
    async def test_predict_with_interventions(self, ensemble_model, sample_input_data) -> None:
        """Test prediction with interventions applied."""
        # Set up
        forecast_days = 5
        symptom_type = "anxiety"
        interventions = [
            {
                "type": "medication",
                "name": "Fluoxetine",
                "start_date": (datetime.now() + timedelta(days=1)).strftime("%Y-%m-%d"),
                "expected_effect": -0.5,  # Reduce symptom severity
            }
        ]

        # Execute
        result = await ensemble_model.predict(
            patient_data=sample_input_data,
            symptom_type=symptom_type,
            forecast_days=forecast_days,
            interventions=interventions,
        )

        # Verify
        assert "predictions" in result
        assert "baseline_predictions" in result  # Should include baseline without interventions
        assert "intervention_effects" in result

        # The intervention should reduce the symptom severity after day 1
        assert result["predictions"][0] == result["baseline_predictions"][0]  # Day 0, no effect
        assert (
            result["predictions"][1] < result["baseline_predictions"][1]
        )  # Day 1+, effect applied

        # Verify intervention details are included
        assert len(result["intervention_effects"]) == 1
        assert result["intervention_effects"][0]["type"] == "medication"
        assert result["intervention_effects"][0]["name"] == "Fluoxetine"

    @pytest.mark.asyncio
    async def test_get_confidence_intervals(self, ensemble_model) -> None:
        """Test confidence interval calculation."""
        # Set up mock predictions from component models
        predictions = np.array([4.0, 3.8, 3.6, 3.4, 3.2])
        std = np.array([0.5, 0.5, 0.4, 0.4, 0.3])

        # Execute
        lower, upper = ensemble_model.get_confidence_intervals(predictions, std)

        # Verify
        assert len(lower) == len(predictions)
        assert len(upper) == len(predictions)

        # Check that intervals make sense (lower < prediction < upper)
        for i in range(len(predictions)):
            assert lower[i] < predictions[i] < upper[i]

        # Typical 95% confidence interval is approximately ±1.96 standard deviations
        np.testing.assert_allclose(lower, predictions - 1.96 * std, rtol=1e-5)
        np.testing.assert_allclose(upper, predictions + 1.96 * std, rtol=1e-5)
