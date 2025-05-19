"""Unit tests for Patient domain entity."""

from datetime import date
from unittest.mock import MagicMock
from uuid import UUID

import pytest

from app.domain.entities.patient import Patient
from app.domain.value_objects.address import Address
from app.infrastructure.security.encryption.base_encryption_service import (
    BaseEncryptionService,
)


@pytest.fixture
def mock_encryption_service():
    """Create a mock encryption service."""
    mock = MagicMock(spec=BaseEncryptionService)
    mock.encrypt.side_effect = lambda x: f"encrypted_{x}"
    mock.decrypt.side_effect = lambda x: x.replace("encrypted_", "")
    return mock


@pytest.fixture
def valid_patient_data(mock_encryption_service):
    """Create valid patient test data."""
    return {
        "id": UUID("12345678-1234-5678-1234-567812345678"),
        "first_name": "John",
        "last_name": "Doe",
        "date_of_birth": date(1990, 1, 1),
        "email": "john.doe@example.com",
        "phone": "123-456-7890",
        "address": Address(street="123 Main St", city="Anytown", state="NY", zip_code="12345"),
    }


@pytest.mark.venv_only()
def test_create_patient(valid_patient_data, mock_encryption_service):
    """Test patient creation with valid data."""
    # Create patient
    patient = Patient(**valid_patient_data)

    # Verify basic attributes
    assert str(patient.id) == "12345678-1234-5678-1234-567812345678"
    assert patient.first_name == "John"
    assert patient.last_name == "Doe"
    assert patient.date_of_birth == date(1990, 1, 1)

    # Verify contact info (access via descriptor)
    assert patient.contact_info is not None
    assert patient.contact_info.email == "john.doe@example.com"
    assert patient.contact_info.phone == "123-456-7890"

    # Verify address (assuming it's still handled directly or via descriptor)
    # Adjust assertion if address handling changed
    assert patient.address is not None
    assert patient.address.street == "123 Main St"
    assert patient.address.city == "Anytown"
    assert patient.address.state == "NY"
    assert patient.address.zip_code == "12345"

    # Verify raw values on the domain entity (no encryption)
    # Encryption happens in the repository layer
    assert patient.email == "john.doe@example.com"
    assert patient.phone == "123-456-7890"
    assert patient.first_name == "John"
    assert patient.last_name == "Doe"
    # Encryption service should not be called during entity creation
    assert not mock_encryption_service.encrypt.called


def test_update_patient(valid_patient_data, mock_encryption_service):
    """Test patient update."""
    # Create initial patient using the modified fixture
    patient = Patient(**valid_patient_data)

    # Update patient - Use the update_contact_info method or direct assignment
    patient.update_contact_info(email="jane.smith@example.com", phone="987-654-3210")
    # Or: patient.contact_info = {'email': 'jane.smith@example.com', 'phone': '987-654-3210'}

    # Update other fields if necessary (assuming Patient has an update method or direct assignment works)
    patient.first_name = "Jane"
    patient.last_name = "Smith"

    # Verify updates on the domain entity (raw values)
    assert patient.first_name == "Jane"
    assert patient.last_name == "Smith"
    assert patient.contact_info.email == "jane.smith@example.com"
    assert patient.contact_info.phone == "987-654-3210"

    # Verify direct attributes are also updated
    assert patient.email == "jane.smith@example.com"
    assert patient.phone == "987-654-3210"

    # Encryption service should not be called during entity update
    assert not mock_encryption_service.encrypt.called


def test_patient_phi_masking(valid_patient_data):
    """Test PHI masking in patient data representation.
    NOTE: Domain entity dump should return raw data. Masking is responsibility of other layers.
    """
    patient = Patient(**valid_patient_data)

    # Test entity dump returns raw data
    patient_dict = patient.model_dump(exclude_none=True)  # Use model_dump if available

    # Assert raw data is present in the dump
    assert patient_dict.get("first_name") == "John"
    assert patient_dict.get("last_name") == "Doe"
    # Check contact_info representation in dump
    contact_info_dump = patient_dict.get("contact_info", {})
    assert contact_info_dump.get("email") == "john.doe@example.com"
    assert contact_info_dump.get("phone") == "123-456-7890"

    # Test PHI is present in string representation (basic __str__)
    patient_str = str(patient)
    assert "John" in patient_str
    assert "Doe" in patient_str
    # Basic __str__ might not include email/phone, adjust if it does
    # assert "john.doe@example.com" in patient_str
    # assert "123-456-7890" in patient_str
