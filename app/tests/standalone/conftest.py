"""
Standalone Test Configuration and Fixtures

This file contains test fixtures specific to standalone tests which do not require
external dependencies or network connections.
"""

import pytest
from typing import Any, Dict, List, Optional


@pytest.fixture
def standalone_fixture():
    """A simple standalone fixture for testing."""
    return "standalone_fixture"


@pytest.fixture
def mock_patient_data() -> Dict[str, Any]:
    """Return mock patient data for testing."""
    return {
        "id": "p-12345",
        "name": "Test Patient",
        "age": 30,
        "gender": "F",
        "medical_history": ["Anxiety", "Depression"],
        "medications": [
            {"name": "Fluoxetine", "dosage": "20mg", "frequency": "daily"}
        ],
    }


@pytest.fixture
def mock_provider_data() -> Dict[str, Any]:
    """Return mock provider data for testing."""
    return {
        "id": "prov-54321",
        "name": "Dr. Test Provider",
        "specialization": "Psychiatry",
        "license_number": "LP12345",
    }


@pytest.fixture
def mock_appointment_data() -> Dict[str, Any]:
    """Return mock appointment data for testing."""
    return {
        "id": "apt-67890",
        "patient_id": "p-12345",
        "provider_id": "prov-54321",
        "datetime": "2025-04-15T10:00:00Z",
        "status": "scheduled",
        "notes": "Initial consultation",
    }


@pytest.fixture
def mock_digital_twin_data() -> Dict[str, Any]:
    """Return mock digital twin data for testing."""
    return {
        "patient_id": "p-12345",
        "model_version": "v2.1.0",
        "neurotransmitter_levels": {
            "serotonin": 0.75,
            "dopamine": 0.65,
            "norepinephrine": 0.70,
        },
        "forecasted_symptoms": [
            {"symptom": "anxiety", "severity": 0.6, "confidence": 0.85},
            {"symptom": "insomnia", "severity": 0.4, "confidence": 0.75},
        ],
    }
