"""
Tests for the Digital Twin Integration Service.

This module contains tests for the Digital Twin Integration Service, which
coordinates all ML microservices and provides a unified interface for the
domain layer, following Clean Architecture principles and ensuring HIPAA compliance.
"""
from typing import NoReturn
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from app.infrastructure.ml.digital_twin_integration_service import (
    DigitalTwinIntegrationService,
)

# Mock missing exception classes
ModelInferenceError = MagicMock()
ValidationError = MagicMock()


@pytest.fixture
def mock_symptom_forecasting_service():
    """Create a mock symptom forecasting service."""
    service = AsyncMock()
    service.forecast_symptoms = AsyncMock()
    service.forecast_symptoms.return_value = {
        "forecasts": {"anxiety": [5, 4, 3, 4, 5], "depression": [3, 3, 2, 2, 3]},
        "risk_levels": {
            "anxiety": ["medium", "medium", "low", "medium", "medium"],
            "depression": ["low", "low", "low", "low", "low"],
        },
        "confidence_intervals": {
            "anxiety": {"lower": [4, 3, 2, 3, 4], "upper": [6, 5, 4, 5, 6]},
            "depression": {"lower": [2, 2, 1, 1, 2], "upper": [4, 4, 3, 3, 4]},
        },
        "trending_symptoms": [
            {
                "symptom": "anxiety",
                "trend": "stable",
                "insight_text": "Anxiety levels remain stable",
                "importance": 0.7,
            }
        ],
        "risk_alerts": [],
    }

    return service


@pytest.fixture
def mock_biometric_correlation_service():
    """Create a mock biometric correlation service."""
    service = AsyncMock()
    service.analyze_correlations = AsyncMock()
    service.analyze_correlations.return_value = {
        "key_indicators": [
            {
                "biometric": "heart_rate",
                "correlation": 0.75,
                "mental_health_indicator": "anxiety",
            }
        ],
        "lag_correlations": [
            {
                "biometric": "sleep_quality",
                "lag_days": 2,
                "mental_health_indicator": "depression",
                "correlation": 0.65,
            }
        ],
        "insights": [
            {
                "insight_text": "Heart rate strongly correlates with anxiety levels",
                "importance": 0.8,
            }
        ],
    }

    return service


@pytest.fixture
def mock_pharmacogenomics_service():
    """Create a mock pharmacogenomics service."""
    service = AsyncMock()
    service.analyze_medication_response = AsyncMock()
    service.analyze_medication_response.return_value = {
        "medication_efficacy": [
            {
                "medication": "fluoxetine",
                "efficacy_score": 0.85,
                "genetic_markers": ["CYP2D6*1/*1"],
                "confidence": "high",
            }
        ],
        "side_effect_risks": [
            {
                "medication": "fluoxetine",
                "side_effect": "insomnia",
                "risk_score": 0.3,
                "genetic_markers": ["ABCB1 rs1045642"],
                "confidence": "medium",
            }
        ],
        "drug_interactions": [
            {
                "medications": ["fluoxetine", "tramadol"],
                "interaction_severity": "high",
                "interaction_effect": "Increased risk of serotonin syndrome",
                "recommendation": "Avoid combination",
            }
        ],
    }

    return service


@pytest.fixture
def mock_recommendation_engine():
    """Create a mock recommendation engine."""
    service = AsyncMock()
    service.generate_recommendations = AsyncMock()
    service.generate_recommendations.return_value = {
        "lifestyle_recommendations": [
            {
                "category": "sleep",
                "recommendation": "Maintain consistent sleep schedule",
                "importance": 0.9,
                "evidence": "Correlated with improved mood stability",
            }
        ],
        "clinical_recommendations": [
            {
                "category": "medication",
                "recommendation": "Consider fluoxetine dose adjustment",
                "importance": 0.8,
                "evidence": "Based on efficacy score and recent symptom trends",
            }
        ],
        "monitoring_recommendations": [
            {
                "category": "biometrics",
                "recommendation": "Monitor heart rate variability",
                "importance": 0.7,
                "evidence": "Strong correlation with anxiety levels",
            }
        ],
    }

    return service


@pytest.fixture
def patient_data():
    """Create sample patient data for testing."""
    return {
        "patient_id": str(uuid4()),
        "symptom_history": {
            "anxiety": [4, 5, 6, 5, 4],
            "depression": [3, 3, 4, 3, 2],
            "sleep_quality": [6, 5, 4, 5, 6],
        },
        "biometric_data": {
            "heart_rate": [72, 75, 80, 78, 74],
            "sleep_duration": [6.5, 6.2, 5.8, 6.3, 6.7],
            "activity_level": [45, 40, 35, 42, 48],
        },
        "mental_health_indicators": {
            "phq9_score": 12,
            "gad7_score": 10,
            "mood_variability": 0.4,
        },
        "genetic_markers": {
            "CYP2D6": "*1/*1",
            "CYP2C19": "*1/*2",
            "ABCB1": ["rs1045642", "rs2032582"],
        },
        "medications": [
            {
                "name": "fluoxetine",
                "dosage": "20mg",
                "frequency": "daily",
                "start_date": "2023-01-15",
            }
        ],
    }


@pytest.fixture
def integration_service(
    mock_symptom_forecasting_service,
    mock_biometric_correlation_service,
    mock_pharmacogenomics_service,
    mock_recommendation_engine,
):
    """Create a digital twin integration service with mock components."""
    service = DigitalTwinIntegrationService(
        symptom_forecasting_service=mock_symptom_forecasting_service,
        biometric_correlation_service=mock_biometric_correlation_service,
        pharmacogenomics_service=mock_pharmacogenomics_service,
        recommendation_engine=mock_recommendation_engine,
    )
    return service


@pytest.mark.asyncio
async def test_generate_comprehensive_patient_insights(integration_service, patient_data) -> None:
    """Test generating comprehensive patient insights."""
    patient_id = uuid4()

    # Generate insights
    insights = await integration_service.generate_comprehensive_patient_insights(
        patient_id=patient_id, patient_data=patient_data
    )

    # Verify all components were called
    integration_service.symptom_forecasting_service.forecast_symptoms.assert_called_once()
    integration_service.biometric_correlation_service.analyze_correlations.assert_called_once()
    integration_service.pharmacogenomics_service.analyze_medication_response.assert_called_once()
    integration_service.recommendation_engine.generate_recommendations.assert_called_once()

    # Verify insights structure
    assert "symptom_forecasting" in insights
    assert "biometric_correlation" in insights
    assert "pharmacogenomics" in insights
    assert "integrated_recommendations" in insights

    # Verify symptom forecasting data
    forecasting = insights["symptom_forecasting"]
    assert "forecasts" in forecasting
    assert "risk_levels" in forecasting
    assert "confidence_intervals" in forecasting

    # Verify biometric correlation data
    correlation = insights["biometric_correlation"]
    assert "key_indicators" in correlation
    assert "lag_correlations" in correlation
    assert "insights" in correlation

    # Verify pharmacogenomics data
    pharma = insights["pharmacogenomics"]
    assert "medication_efficacy" in pharma
    assert "side_effect_risks" in pharma
    assert "drug_interactions" in pharma

    # Verify recommendations
    recommendations = insights["integrated_recommendations"]
    assert "lifestyle_recommendations" in recommendations
    assert "clinical_recommendations" in recommendations
    assert "monitoring_recommendations" in recommendations

    # Verify recommendations are sorted by importance
    lifestyle_recs = recommendations["lifestyle_recommendations"]
    assert len(lifestyle_recs) > 0
    if len(lifestyle_recs) > 1:
        assert lifestyle_recs[0]["importance"] >= lifestyle_recs[1]["importance"]

    clinical_recs = recommendations["clinical_recommendations"]
    assert len(clinical_recs) > 0
    if len(clinical_recs) > 1:
        assert clinical_recs[0]["importance"] >= clinical_recs[1]["importance"]


@pytest.mark.asyncio
async def test_handle_microservice_failure(integration_service, patient_data) -> None:
    """Test handling of microservice failures."""
    patient_id = uuid4()

    # Make symptom forecasting service fail
    original_method = integration_service.symptom_forecasting_service.forecast_symptoms

    async def failing_forecast(*args, **kwargs) -> NoReturn:
        raise ModelInferenceError("Test error")

    integration_service.symptom_forecasting_service.forecast_symptoms = failing_forecast

    try:
        # Generate insights despite the failure
        insights = await integration_service.generate_comprehensive_patient_insights(
            patient_id=patient_id, patient_data=patient_data
        )

        # Verify that other services still produced results
        assert "symptom_forecasting" not in insights
        assert "biometric_correlation" in insights
        assert "pharmacogenomics" in insights
        assert "integrated_recommendations" in insights
    finally:
        # Restore the original method
        integration_service.symptom_forecasting_service.forecast_symptoms = original_method


@pytest.mark.asyncio
async def test_sanitize_patient_data(integration_service, patient_data) -> None:
    """Test sanitization of patient data for HIPAA compliance."""
    # Add PHI to patient data
    patient_data_with_phi = patient_data.copy()
    patient_data_with_phi["name"] = "John Doe"
    patient_data_with_phi["email"] = "john.doe@example.com"
    patient_data_with_phi["ssn"] = "123-45-6789"

    # Sanitize data
    sanitized_data = integration_service._sanitize_patient_data(patient_data_with_phi)

    # Verify that PHI is removed
    assert "name" not in sanitized_data
    assert "email" not in sanitized_data
    assert "ssn" not in sanitized_data

    # Verify that non-PHI data is preserved
    assert "symptom_history" in sanitized_data
    assert "biometric_data" in sanitized_data
    assert "mental_health_indicators" in sanitized_data
    assert "genetic_markers" in sanitized_data
