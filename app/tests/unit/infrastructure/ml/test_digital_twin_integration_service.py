"""
Unit tests for the Digital Twin Integration Service.

These tests verify that the Digital Twin Integration Service correctly
coordinates between different ML microservices to generate comprehensive
patient insights.
"""

from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from app.infrastructure.ml.digital_twin_integration_service import (
    DigitalTwinIntegrationService,
)


@pytest.fixture
def mock_symptom_forecasting_service():
    """Create a mock SymptomForecastingService."""
    service = AsyncMock()
    # Corrected return value dictionary
    service.generate_forecast = AsyncMock(
        return_value={
            "patient_id": str(uuid4()),
            "forecast_type": "ensemble",
            "reliability": "high",
            "forecast_dates": ["2025-03-27", "2025-03-28", "2025-03-29", "2025-03-30"],
            "forecast": [4.2, 4.0, 3.8, 3.5],
            "confidence_intervals": {
                "80%": {"lower": [4.0, 3.8, 3.6, 3.3], "upper": [4.4, 4.2, 4.0, 3.7]},
                "95%": {"lower": [3.8, 3.6, 3.4, 3.1], "upper": [4.6, 4.4, 4.2, 3.9]},
            },
            "contributing_models": {
                "transformer": {"weight": 0.7, "metrics": {"mae": 0.42, "rmse": 0.68}},
                "xgboost": {"weight": 0.3, "metrics": {"mae": 0.47, "rmse": 0.72}},
            },
        }
    )
    return service


@pytest.fixture
def mock_biometric_correlation_service():
    """Create a mock BiometricCorrelationService."""
    service = AsyncMock()
    # Corrected return value dictionary
    service.analyze_correlations = AsyncMock(
        return_value={
            "patient_id": str(uuid4()),
            "reliability": "medium",
            "correlations": [
                {
                    "biometric_type": "heart_rate_variability",
                    "symptom_type": "anxiety",
                    "coefficient": -0.72,
                    "lag_hours": 8,
                    "confidence": 0.85,
                    "p_value": 0.002,
                },
                {
                    "biometric_type": "sleep_duration",
                    "symptom_type": "mood",
                    "coefficient": 0.65,
                    "lag_hours": 24,
                    "confidence": 0.82,
                    "p_value": 0.005,
                },
            ],
            "insights": [
                {
                    "type": "physiological_marker",
                    "message": "Decreased heart rate variability precedes anxiety symptoms by 8 hours.",
                    "action": "Consider HRV biofeedback training to improve regulation.",
                },
                {
                    "type": "sleep_pattern",
                    "message": "Reduced sleep duration is associated with mood deterioration 24 hours later.",
                    "action": "Prioritize sleep hygiene interventions.",
                },
            ],
        }
    )
    return service


@pytest.fixture
def mock_pharmacogenomics_service():
    """Create a mock PharmacogenomicsService."""
    service = AsyncMock()
    # Corrected return value dictionary
    service.analyze_medication_response = AsyncMock(
        return_value={
            "medication_predictions": {
                "fluoxetine": {
                    "efficacy": {"score": 0.72, "confidence": 0.85, "percentile": 75},
                    "side_effects": [
                        {
                            "name": "nausea",
                            "risk": 0.35,
                            "severity": "mild",
                            "onset_days": 7,
                        },
                        {
                            "name": "insomnia",
                            "risk": 0.28,
                            "severity": "mild",
                            "onset_days": 14,
                        },
                    ],
                    "genetic_factors": [
                        {
                            "gene": "CYP2D6",
                            "variant": "*1/*1",
                            "impact": "normal_metabolism",
                        }
                    ],
                    "metabolizer_status": "normal",
                    "recommendation": {
                        "action": "standard_dosing",
                        "rationale": "Standard protocol indicated based on available data.",
                        "caution_level": "low",
                    },
                },
                "sertraline": {
                    "efficacy": {"score": 0.65, "confidence": 0.80, "percentile": 65},
                    "side_effects": [
                        {
                            "name": "nausea",
                            "risk": 0.42,
                            "severity": "moderate",
                            "onset_days": 5,
                        }
                    ],
                    "metabolizer_status": "intermediate",
                    "recommendation": {
                        "action": "careful_monitoring",
                        "rationale": "Intermediate metabolizer status may affect drug levels.",
                        "caution_level": "medium",
                    },
                },
            },
            "comparative_analysis": {
                "highest_efficacy": {
                    "medication": "fluoxetine",
                    "score": 0.72,
                    "confidence": 0.85,
                },
                "lowest_side_effects": {
                    "medication": "bupropion",
                    "highest_risk": 0.25,
                },
                "optimal_balance": {
                    "medication": "fluoxetine",
                    "efficacy": 0.72,
                    "side_effect_risk": 0.35,
                },
            },
        }
    )
    return service


@pytest.fixture
def mock_recommendation_engine():
    """Create a mock RecommendationEngine."""
    engine = AsyncMock()
    engine.generate_recommendations = AsyncMock(
        return_value=[
            {
                "type": "medication",
                "recommendation": "Consider fluoxetine as first-line treatment based on predicted efficacy.",
                "confidence": 0.85,
                "supporting_evidence": [
                    "High predicted efficacy score (0.72)",
                    "Normal metabolizer status for relevant enzymes",
                    "Low side effect risk profile",
                ],
                "priority": "high",
            },
            {
                "type": "behavioral",
                "recommendation": "Implement sleep hygiene interventions to improve mood stability.",
                "confidence": 0.82,
                "supporting_evidence": [
                    "Strong correlation between sleep duration and mood (r=0.65)",
                    "24-hour lag observed between sleep disruption and mood changes",
                ],
                "priority": "medium",
            },
        ]
    )
    return engine


@pytest.fixture
def mock_patient_repository():
    """Create a mock PatientRepository."""
    repo = AsyncMock()
    # Corrected return value dictionary
    repo.get_by_id = AsyncMock(
        return_value={
            "id": str(uuid4()),
            "first_name": "John",
            "last_name": "Doe",
            "date_of_birth": "1980-01-01",
            "gender": "male",
            "conditions": ["anxiety", "depression"],
            "medications": ["fluoxetine"],
        }
    )
    return repo


@pytest.fixture
def integration_service(
    mock_symptom_forecasting_service,
    mock_biometric_correlation_service,
    mock_pharmacogenomics_service,
    mock_recommendation_engine,
    mock_patient_repository,
):
    """Create a DigitalTwinIntegrationService with mock dependencies."""
    return DigitalTwinIntegrationService(
        symptom_forecasting_service=mock_symptom_forecasting_service,
        biometric_correlation_service=mock_biometric_correlation_service,
        pharmacogenomics_service=mock_pharmacogenomics_service,
        recommendation_engine=mock_recommendation_engine,
        patient_repository=mock_patient_repository,
    )


@pytest.fixture
def sample_patient_id():
    """Create a sample patient ID."""
    return str(uuid4())


@pytest.mark.db_required()
class TestDigitalTwinIntegrationService:
    """Tests for the DigitalTwinIntegrationService."""

    @pytest.mark.asyncio
    async def test_generate_comprehensive_insights_all_services(
        self, integration_service, sample_patient_id
    ) -> None:
        """Test that generate_comprehensive_insights calls all services and combines results."""
        # Setup
        options = {
            "include_symptom_forecast": True,
            "include_biometric_correlations": True,
            "include_medication_predictions": True,
            "forecast_days": 14,
            "biometric_lookback_days": 30,
        }

        # Execute
        result = await integration_service.generate_comprehensive_insights(
            sample_patient_id, options
        )

        # Verify
        assert "patient_id" in result
        assert "generated_at" in result
        assert "symptom_forecast" in result
        assert "biometric_correlations" in result
        assert "medication_predictions" in result
        assert "integrated_recommendations" in result

        # Verify all services were called
        integration_service.symptom_forecasting_service.generate_forecast.assert_called_once()
        integration_service.biometric_correlation_service.analyze_correlations.assert_called_once()
        integration_service.pharmacogenomics_service.analyze_medication_response.assert_called_once()

    @pytest.mark.asyncio
    async def test_generate_comprehensive_insights_partial_services(
        self, integration_service, sample_patient_id
    ) -> None:
        """Test that generate_comprehensive_insights only calls requested services."""
        # Setup
        options = {
            "include_symptom_forecast": True,
            "include_biometric_correlations": False,
            "include_medication_predictions": True,
            "forecast_days": 14,
            "biometric_lookback_days": 30,
        }

        # Execute
        result = await integration_service.generate_comprehensive_insights(
            sample_patient_id, options
        )

        # Verify
        assert "patient_id" in result
        assert "generated_at" in result
        assert "symptom_forecast" in result
        assert "medication_predictions" in result
        assert "biometric_correlations" not in result
        assert "integrated_recommendations" in result

        # Verify only requested services were called
        integration_service.symptom_forecasting_service.generate_forecast.assert_called_once()
        integration_service.pharmacogenomics_service.analyze_medication_response.assert_called_once()
        integration_service.biometric_correlation_service.analyze_correlations.assert_not_called()  # Corrected assertion

    @pytest.mark.asyncio
    async def test_generate_comprehensive_insights_handles_service_errors(
        self, integration_service, sample_patient_id
    ) -> None:
        """Test that generate_comprehensive_insights handles service errors gracefully."""
        # Setup
        integration_service.symptom_forecasting_service.generate_forecast.side_effect = Exception(
            "Service error"  # Corrected exception syntax
        )

        options = {
            "include_symptom_forecast": True,
            "include_biometric_correlations": True,
            "include_medication_predictions": True,
        }

        # Execute
        result = await integration_service.generate_comprehensive_insights(
            sample_patient_id, options
        )

        # Verify
        assert "patient_id" in result
        assert "generated_at" in result
        assert "symptom_forecast" not in result  # Should not be present due to error
        assert "biometric_correlations" in result
        assert "medication_predictions" in result
        assert "integrated_recommendations" in result
        assert "errors" in result
        assert "symptom_forecast" in result["errors"]

    @pytest.mark.asyncio
    async def test_generate_integrated_recommendations(
        self, integration_service, sample_patient_id
    ) -> None:
        """Test that _generate_integrated_recommendations creates meaningful recommendations."""
        # Setup
        # Corrected insights dictionary structure
        insights = {
            "patient_id": sample_patient_id,
            "symptom_forecast": {
                "reliability": "high",
                "forecasts": {"anxiety": [4.2, 4.0, 3.8, 3.5]},
                "confidence_intervals": {
                    "95%": {
                        "anxiety": {
                            "lower": [3.8, 3.6, 3.4, 3.1],
                            "upper": [4.6, 4.4, 4.2, 3.9],
                        }
                    }
                },
            },
            "biometric_correlations": {
                "correlations": [
                    {
                        "biometric_type": "heart_rate_variability",
                        "symptom_type": "anxiety",
                        "coefficient": -0.72,
                        "lag_hours": 8,
                    }
                ],
                "insights": [
                    {
                        "type": "physiological_marker",
                        "message": "Decreased heart rate variability precedes anxiety symptoms by 8 hours.",
                        "action": "Consider HRV biofeedback training to improve regulation.",
                    }
                ],
            },
            "medication_predictions": {
                "medication_predictions": {  # Added nested level based on fixture
                    "fluoxetine": {
                        "efficacy": {"score": 0.72, "confidence": 0.85},
                        "side_effects": [{"name": "nausea", "risk": 0.35, "severity": "mild"}],
                        "recommendation": {
                            "action": "standard_dosing",
                            "rationale": "Standard protocol indicated based on available data.",
                        },
                    }
                }
            },
        }

        # Execute
        recommendations = await integration_service._generate_integrated_recommendations(insights)

        # Verify
        assert isinstance(recommendations, list)
        assert len(recommendations) > 0

        # Check recommendation structure
        for rec in recommendations:
            assert "type" in rec
            assert "recommendation" in rec
            assert "confidence" in rec
            assert "supporting_evidence" in rec
            assert isinstance(rec["supporting_evidence"], list)

        # Verify different types of recommendations are included
        rec_types = [rec["type"] for rec in recommendations]
        assert "medication" in rec_types
        assert "biometric_monitoring" in rec_types or "behavioral" in rec_types

    @pytest.mark.asyncio
    async def test_get_patient_data(
        self, integration_service, sample_patient_id, mock_patient_repository
    ) -> None:
        """Test that _get_patient_data retrieves patient data correctly."""
        # Execute
        patient_data = await integration_service._get_patient_data(sample_patient_id)

        # Verify
        assert patient_data is not None
        mock_patient_repository.get_by_id.assert_called_once_with(
            sample_patient_id  # Corrected assertion call
        )

    @pytest.mark.asyncio
    async def test_get_patient_data_handles_missing_patient(
        self, integration_service, sample_patient_id, mock_patient_repository
    ) -> None:
        """Test that _get_patient_data handles missing patient data gracefully."""
        # Setup
        mock_patient_repository.get_by_id.return_value = None

        # Execute and verify exception is raised
        with pytest.raises(ValueError) as excinfo:
            await integration_service._get_patient_data(sample_patient_id)

        assert "Patient not found" in str(excinfo.value)
