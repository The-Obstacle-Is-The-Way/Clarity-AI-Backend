"""
Standalone test for (Patient entity in the domain layer.)

This test verifies the core domain logic of the Patient entity
without any external dependencies.
"""

import uuid
from datetime import date
from unittest.mock import Mock

import pytest

# Import the domain entity class
from app.domain.entities.patient import Patient


@pytest.mark.standalone()
def test_patient_creation_with_valid_data_succeeds():
    """Test that a Patient entity can be created with valid data."""
    # Arrange
    patient_id = uuid.uuid4()
    name = "John Doe"
    date_of_birth = date(1990, 1, 1)

    # Act
    patient = Patient(
        id=patient_id,
        name=name,
        date_of_birth=date_of_birth,
        gender="male"
    )
    

    # Assert
    assert patient.id == patient_id
    assert patient.name == name
    assert patient.date_of_birth == date_of_birth


@pytest.mark.standalone()
def test_patient_age_calculation_is_correct():
    """Test that the patient age is calculated correctly."""
    # Arrange
    patient = Patient(
        id=uuid.uuid4(),
        name="John Doe",
        date_of_birth=date(1990, 1, 1),
        gender="male"
    )
    
    # Act - Use a mock for today's date to make the test deterministic
    today_mock = Mock(return_value=date(2023, 1, 1))
    patient._get_today = today_mock

    # Assert
    today = date(2023, 1, 1)
    age = today.year - patient.date_of_birth.year - ((today.month, today.day) < (patient.date_of_birth.month, patient.date_of_birth.day))
    assert age == 33


@pytest.mark.standalone()
def test_patient_equality_based_on_id():
    """Test that patients are considered equal if they have the same ID."""
    # Arrange
    id1 = uuid.uuid4()
    patient1 = Patient(
        id=id1,
        name="John Doe",
        date_of_birth=date(1990, 1, 1),
        gender="male"
    )
    
    patient2 = Patient(
        id=id1,  # Same ID
        name="Different Name",  # Different name
        date_of_birth=date(1995, 5, 5),  # Different DoB
        gender="female"
    )
    
    patient3 = Patient(
        id=uuid.uuid4(),  # Different ID
        name="John Doe",  # Same name
        date_of_birth=date(1990, 1, 1),  # Same DoB
        gender="male"
    )
    
    # Assert
    assert patient1 != patient3  # Different ID, same attributes
    assert hash(patient1) != hash(patient3)  # Different hash for different ID
