"""Unit tests for Symptom Forecasting Model Service."""

import pytest

pytest.skip(
    "Skipping symptom forecasting model service tests (torch unsupported)",
    allow_module_level=True,
)
from datetime import date, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID

import pandas as pd

# Corrected exception imports based on definitive source location
from app.domain.entities.patient import Patient

# Removed unused import for MLSettings
# Removed import for non-existent ModelRegistry
# from app.infrastructure.ml.interfaces.model_registry import ModelRegistry
from app.infrastructure.ml.symptom_forecasting.model_service import (
    SymptomForecastingService,
)

# from app.core.exceptions import ModelExecutionError, ResourceNotFoundError # Old incorrect import


class TestSymptomForecastingModelService:
    """Test suite for the SymptomForecastingModelService."""

    # Removed unused mock_model_registry fixture
    # def mock_model_registry(self):
    #     """Create a mock model registry for testing."""
    #     registry = MagicMock(spec=ModelRegistry)
    #     # Configure mock behavior if needed, e.g., registry.get_model.return_value = ...
    #     return registry

    @pytest.fixture
    def service(self):  # Removed mock_model_registry dependency
        """Create a SymptomForecastingModelService instance for testing."""
        # Correct instantiation - requires updating based on new __init__
        # TODO: Update instantiation with necessary paths/mocks
        return SymptomForecastingService(
            model_dir="/tmp/test_symptom_service",
            # model_registry=mock_model_registry, # Removed registry argument
            feature_names=["anxiety", "depression", "sleep_hours"],  # Example features
            target_names=["anxiety_forecast", "depression_forecast"],  # Example targets
        )

    @pytest.fixture
    def sample_patient(self):
        """Create a sample patient for testing."""
        # Correct instantiation
        return Patient(
            id=UUID("00000000-0000-0000-0000-000000000001"),
            first_name="John",
            last_name="Doe",
            date_of_birth=date(1980, 1, 1),  # Use date object
            email="john.doe@example.com",
            phone="555-123-4567",
            active=True,
        )

    @pytest.fixture
    def sample_patient_data(self, sample_patient):
        """Create sample patient symptom data for testing."""
        # Correct dictionary structure
        return {
            "patient_id": str(sample_patient.id),
            "demographics": {
                "age": 42,
                "gender": "male",
                "has_chronic_condition": True,
            },
            "medication_history": [
                {
                    "medication": "Sertraline",
                    "start_date": (datetime.now() - timedelta(days=60)).strftime("%Y-%m-%d"),
                    "end_date": None,
                    "dosage": "50mg",
                    "frequency": "daily",
                }
            ],
            "biometrics": [
                {
                    "date": (datetime.now() - timedelta(days=3)).strftime("%Y-%m-%d"),
                    "sleep_hours": 6.5,
                    "activity_level": "moderate",
                    "heart_rate_avg": 72,
                },
                {
                    "date": (datetime.now() - timedelta(days=2)).strftime("%Y-%m-%d"),
                    "sleep_hours": 7.2,
                    "activity_level": "high",
                    "heart_rate_avg": 68,
                },
                {
                    "date": (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d"),
                    "sleep_hours": 8.0,
                    "activity_level": "low",
                    "heart_rate_avg": 65,
                },
            ],
            "symptom_history": [
                {
                    "date": (datetime.now() - timedelta(days=3)).strftime("%Y-%m-%d"),
                    "symptom_type": "anxiety",
                    "severity": 6,
                },
                {
                    "date": (datetime.now() - timedelta(days=2)).strftime("%Y-%m-%d"),
                    "symptom_type": "anxiety",
                    "severity": 5,
                },
                {
                    "date": (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d"),
                    "symptom_type": "anxiety",
                    "severity": 4,
                },
            ],
        }

    @pytest.mark.asyncio
    async def test_preprocess_patient_data_success(self, service, sample_patient_data) -> None:
        """Test that preprocess_patient_data correctly processes valid patient data."""
        # Execute
        patient_id = UUID(sample_patient_data["patient_id"])
        df, metadata = await service.preprocess_patient_data(patient_id, sample_patient_data)

        # Verify
        assert isinstance(df, pd.DataFrame)
        assert not df.empty
        assert "symptom_severity" in df.columns
        assert "sleep_hours" in df.columns
        assert "heart_rate_avg" in df.columns
        assert metadata["symptom_type"] == "anxiety"

    @pytest.mark.asyncio
    async def test_preprocess_patient_data_missing_data(self, service) -> None:
        """Test handling of missing data during preprocessing."""
        # Setup
        incomplete_data = {
            "patient_id": "00000000-0000-0000-0000-000000000001",
            "demographics": {"age": 42, "gender": "male"},
            # Missing symptom_history
            "biometrics": [],
        }

        # Execute
        patient_id = UUID(incomplete_data["patient_id"])
        with pytest.raises(ValueError, match="Insufficient symptom data"):
            await service.preprocess_patient_data(patient_id, incomplete_data)

    @pytest.mark.asyncio
    async def test_predict_symptom_progression(self, service, sample_patient_data) -> None:
        """Test prediction of symptom progression."""
        # Setup
        patient_id = UUID(sample_patient_data["patient_id"])
        forecast_days = 3

        # Mock the preprocessing
        # Correct patch and return_value structure
        mock_df = pd.DataFrame(
            {
                "date": pd.date_range(start=datetime.now() - timedelta(days=3), periods=3),
                "symptom_severity": [6, 5, 4],
                "sleep_hours": [6.5, 7.2, 8.0],
                "heart_rate_avg": [72, 68, 65],
            }
        )
        mock_metadata = {"symptom_type": "anxiety"}

        with patch.object(
            service,
            "preprocess_patient_data",
            AsyncMock(return_value=(mock_df, mock_metadata)),
        ):
            # Execute
            # Correct function call
            result = await service.predict_symptom_progression(
                patient_id=patient_id,
                patient_data=sample_patient_data,
                forecast_days=forecast_days,
            )

            # Verify
            assert len(result["forecast"]) == forecast_days
            assert "dates" in result
            assert "values" in result["forecast"]
            assert len(result["forecast"]["values"]) == forecast_days
            assert result["symptom_type"] == "anxiety"
            assert "confidence_intervals" in result["forecast"]

    @pytest.mark.asyncio
    async def test_predict_symptom_progression_invalid_days(
        self, service, sample_patient_data
    ) -> None:
        """Test prediction with invalid forecast days."""
        # Setup
        patient_id = UUID(sample_patient_data["patient_id"])

        # Execute & Verify
        with pytest.raises(ValueError, match="Forecast days must be between 1 and 30"):
            await service.predict_symptom_progression(
                patient_id=patient_id,
                patient_data=sample_patient_data,
                forecast_days=0,  # Invalid value
            )

        with pytest.raises(ValueError, match="Forecast days must be between 1 and 30"):
            await service.predict_symptom_progression(
                patient_id=patient_id,
                patient_data=sample_patient_data,
                forecast_days=31,  # Invalid value
            )

    @pytest.mark.asyncio
    async def test_predict_symptom_with_interventions(self, service, sample_patient_data) -> None:
        """Test prediction with interventions."""
        # Setup
        patient_id = UUID(sample_patient_data["patient_id"])
        forecast_days = 7
        # Correct interventions list structure
        interventions = [
            {
                "type": "medication",
                "name": "Fluoxetine",
                "start_date": (datetime.now() + timedelta(days=1)).strftime("%Y-%m-%d"),
                "expected_effect": -0.5,  # Reduce symptom severity
            },
            {
                "type": "therapy",
                "name": "CBT",
                "start_date": datetime.now().strftime("%Y-%m-%d"),
                "expected_effect": -0.3,
            },
        ]

        # Mock the preprocessing and model
        with patch.object(service, "preprocess_patient_data", AsyncMock()):
            # Execute
            result = await service.predict_symptom_progression(
                patient_id=patient_id,
                patient_data=sample_patient_data,
                forecast_days=forecast_days,
                interventions=interventions,
            )

            # Verify
            assert len(result["forecast"]) == forecast_days
            assert "intervention_effect" in result
            assert len(result["intervention_effect"]) > 0

            # The baseline forecast should be different from the intervention
            # forecast
            assert result["forecast"] != result["baseline_forecast"]

    @pytest.mark.asyncio
    async def test_forecast_symptoms(self, service) -> None:
        """Test the forecast_symptoms method."""
        # Setup
        mock_transformer = MagicMock()
        mock_xgboost = MagicMock()
        service.transformer_model = mock_transformer
        service.xgboost_model = mock_xgboost

        # Act
        result = await service.forecast_symptoms(
            patient_id=UUID("00000000-0000-0000-0000-000000000001"),
            patient_data={
                "patient_id": "00000000-0000-0000-0000-000000000001",
                "demographics": {"age": 42, "gender": "male"},
                "medication_history": [],
                "biometrics": [],
                "symptom_history": [],
            },
            forecast_days=3,
        )

        # Verify
        assert isinstance(result, dict)
        assert "forecast" in result
        assert "dates" in result["forecast"]
        assert "values" in result["forecast"]
        assert len(result["forecast"]["values"]) == 3
        assert result["symptom_type"] == "anxiety"
        assert "confidence_intervals" in result["forecast"]
        mock_transformer.predict.assert_called_once()
        mock_xgboost.predict.assert_called_once()

    @pytest.mark.asyncio
    async def test_forecast_symptoms_with_interventions(self, service) -> None:
        """Test the forecast_symptoms method with interventions."""
        # Setup
        mock_transformer = MagicMock()
        mock_xgboost = MagicMock()
        service.transformer_model = mock_transformer
        service.xgboost_model = mock_xgboost

        # Act
        result = await service.forecast_symptoms(
            patient_id=UUID("00000000-0000-0000-0000-000000000001"),
            patient_data={
                "patient_id": "00000000-0000-0000-0000-000000000001",
                "demographics": {"age": 42, "gender": "male"},
                "medication_history": [],
                "biometrics": [],
                "symptom_history": [],
            },
            forecast_days=7,
            interventions=[
                {
                    "type": "medication",
                    "name": "Fluoxetine",
                    "start_date": (datetime.now() + timedelta(days=1)).strftime("%Y-%m-%d"),
                    "expected_effect": -0.5,
                },
                {
                    "type": "therapy",
                    "name": "CBT",
                    "start_date": datetime.now().strftime("%Y-%m-%d"),
                    "expected_effect": -0.3,
                },
            ],
        )

        # Verify
        assert isinstance(result, dict)
        assert "forecast" in result
        assert "dates" in result["forecast"]
        assert "values" in result["forecast"]
        assert len(result["forecast"]["values"]) == 7
        assert result["symptom_type"] == "anxiety"
        assert "confidence_intervals" in result["forecast"]
        assert "intervention_effect" in result
        assert len(result["intervention_effect"]) > 0
        assert result["forecast"] != result["baseline_forecast"]
        mock_transformer.predict.assert_called_once()
        mock_xgboost.predict.assert_not_called()
