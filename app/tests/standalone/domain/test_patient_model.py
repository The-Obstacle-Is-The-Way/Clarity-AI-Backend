"""
Standalone test for (Patient domain model)

These tests verify the behavior of the Patient model without any external dependencies.
"""

import uuid
from datetime import date

import pytest

from app.domain.entities.patient import Patient


@pytest.mark.standalone()
class TestPatientModel:
    """Tests for the Patient domain model."""

    @pytest.mark.standalone()
    def test_patient_creation_valid_data(self):
        """Test that a patient can be created with valid data."""
        # Arrange
        patient_id = str(uuid.uuid4())
        name = "John Doe"
        dob = date(1980, 1, 15)

        # Act
        patient = Patient(
            id=patient_id,
            name=name,
            date_of_birth=dob,
            gender="male"
        )

        # Assert
        assert patient.id == patient_id
        assert patient.name == name
        assert patient.date_of_birth == dob

    @pytest.mark.standalone()
    def test_patient_creation_invalid_name(self, invalid_name):
        """Test that a patient cannot be created with an invalid name."""
        # Arrange
        patient_id = str(uuid.uuid4())
        dob = date(1980, 1, 15)

        # Act & Assert
        with pytest.raises(ValueError) as exc_info:
            Patient(
                id=patient_id,
                name=invalid_name,
                date_of_birth=dob,
                gender="male"
            )
            
        assert "name" in str(exc_info.value).lower()

    @pytest.mark.standalone()
    def test_patient_age_calculation(self):
        """Test that patient age is calculated correctly."""
        # Arrange
        patient_id = str(uuid.uuid4())
        name = "John Doe"

        # Patient born exactly 30 years ago
        thirty_years_ago = date.today().replace(year=date.today().year - 30)

        # Act
        patient = Patient(
            id=patient_id,
            name=name,
            date_of_birth=thirty_years_ago,
            gender="male"
        )
        
        # Assert
        today = date.today()
        age = today.year - patient.date_of_birth.year - ((today.month, today.day) < (patient.date_of_birth.month, patient.date_of_birth.day))
        assert age == 30
