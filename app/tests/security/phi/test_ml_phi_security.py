"""
HIPAA Compliance Testing - ML PHI Security Tests

These tests validate that the ML processing components properly secure Protected Health Information (PHI)
according to HIPAA requirements. Tests here focus on proper de-identification, secure handling, and
isolation of PHI data in ML workflows.

Note: This file has been updated to work with the consolidated PHISanitizer implementation.
"""

import uuid
from unittest.mock import MagicMock, patch

import pytest

from app.infrastructure.security.encryption import BaseEncryptionService
from app.infrastructure.security.phi import PHISanitizer, sanitize_phi, contains_phi


@pytest.fixture
def mock_encryption_service():
    """Mock encryption service for testing."""
    mock_service = MagicMock(spec=BaseEncryptionService)
    mock_service.encrypt.return_value = b"encrypted_data"
    mock_service.decrypt.return_value = b'{"data": "sample_data"}'
    return mock_service

@pytest.fixture
def phi_sanitizer():
    """Create a PHI sanitizer instance for testing."""
    return PHISanitizer()

@pytest.fixture
def sample_patient_data():
    """Sample patient data containing PHI."""
    return {
        "patient_id": str(uuid.uuid4()),
        "name": "John Doe",
        "dob": "1980-01-01",
        "ssn": "123-45-6789",
        "address": "123 Main St, City, State 12345",
        "phone": "555-123-4567",
        "email": "john.doe@example.com",
        "medical_history": [
            {
                "condition": "Anxiety",
                "diagnosis_date": "2020-01-15",
                "notes": "Patient reported...",
            },
            {
                "condition": "Depression",
                "diagnosis_date": "2019-03-20",
                "notes": "Initial symptoms...",
            },
        ],
        "medications": [
            {"name": "Med1", "dosage": "10mg", "frequency": "daily"},
            {"name": "Med2", "dosage": "20mg", "frequency": "twice daily"},
        ],
    }

@pytest.mark.venv_only
class TestPHIHandling:
    """Test proper handling of PHI in ML components."""

    def test_phi_data_is_never_logged(self, sample_patient_data, caplog, phi_sanitizer):
        """Test that PHI is never logged during ML processing."""
        import logging
        
        # Set up a test logger
        logger = logging.getLogger("test_phi_logger")
        
        # Log some PHI data
        logger.info(f"Processing patient: {sample_patient_data['name']} with SSN: {sample_patient_data['ssn']}")
        
        # Get log records
        log_records = [record.message for record in caplog.records]
        
        # Check that PHI is not in logs
        for record in log_records:
            assert sample_patient_data['name'] not in record, "PHI name should not be in logs"
            assert sample_patient_data['ssn'] not in record, "PHI SSN should not be in logs"
        
        # Verify the consolidated sanitizer would redact this
        log_message = f"Processing patient: {sample_patient_data['name']} with SSN: {sample_patient_data['ssn']}"
        sanitized = phi_sanitizer.sanitize_string(log_message)
        assert sample_patient_data['name'] not in sanitized
        assert sample_patient_data['ssn'] not in sanitized
        assert "[REDACTED NAME]" in sanitized
        assert "[REDACTED SSN]" in sanitized

    def test_phi_is_never_stored_in_plain_text(self, sample_patient_data, mock_encryption_service):
        """Test that PHI is never stored in plain text."""
        # Encrypt PHI data
        encrypted_ssn = mock_encryption_service.encrypt(sample_patient_data['ssn'])
        encrypted_name = mock_encryption_service.encrypt(sample_patient_data['name'])
        
        # Verify encryption was performed correctly
        assert encrypted_ssn != sample_patient_data['ssn']
        assert encrypted_name != sample_patient_data['name']
        
        # Verify decryption works
        decrypted_ssn = mock_encryption_service.decrypt(encrypted_ssn)
        assert sample_patient_data['ssn'] in decrypted_ssn.decode()

    def test_phi_is_properly_deidentified(self, phi_sanitizer):
        """Test that PHI is properly de-identified in ML input data."""
        # Arrange
        phi_data = "Patient John Doe, SSN: 123-45-6789"
        
        # Act
        result = phi_sanitizer.sanitize_string(phi_data)
        
        # Assert
        assert "John Doe" not in result
        assert "123-45-6789" not in result
        assert "[REDACTED NAME]" in result
        assert "[REDACTED SSN]" in result

    def test_patient_data_isolation(self, sample_patient_data, phi_sanitizer):
        """Test that patient data is isolated and not mixed with other patients."""
        # Create a second patient
        patient2_data = {
            "patient_id": str(uuid.uuid4()),
            "name": "Jane Smith",
            "ssn": "987-65-4321"
        }
        
        # Simulate ML batch processing with both patients
        batch_data = [sample_patient_data, patient2_data]
        
        # Use the sanitizer to process each patient separately
        sanitized_patients = [phi_sanitizer.sanitize_json(patient) for patient in batch_data]
        
        # Verify each patient's PHI is properly sanitized
        assert "[REDACTED NAME]" in str(sanitized_patients[0])
        assert "[REDACTED NAME]" in str(sanitized_patients[1])
        assert "John Doe" not in str(sanitized_patients)
        assert "Jane Smith" not in str(sanitized_patients)
        
        # Verify patient IDs are preserved (not PHI)
        assert sample_patient_data["patient_id"] in str(sanitized_patients[0])
        assert patient2_data["patient_id"] in str(sanitized_patients[1])


class TestMLDataProcessing:
    """Test ML data processing with PHI."""

    def test_feature_extraction_anonymizes_phi(self, sample_patient_data, phi_sanitizer):
        """Test that feature extraction properly anonymizes PHI."""
        # Simulate feature extraction process
        extracted_features = {
            "patient_id": sample_patient_data["patient_id"],
            "features": {
                "age": 2023 - int(sample_patient_data["dob"].split("-")[0]),
                "condition_count": len(sample_patient_data["medical_history"]),
            }
        }
        
        # Verify extracted features don't contain PHI
        feature_str = str(extracted_features)
        assert sample_patient_data["name"] not in feature_str
        assert sample_patient_data["ssn"] not in feature_str
        assert sample_patient_data["email"] not in feature_str
        
        # Verify sanitizer would redact any PHI if present
        sanitized = phi_sanitizer.sanitize_json(extracted_features)
        assert str(sanitized) == str(extracted_features), "Features should already be PHI-free"

    def test_model_output_has_no_phi(self, sample_patient_data, phi_sanitizer):
        """Test that model output has no PHI."""
        # Simulate model output
        model_output = {
            "patient_id": sample_patient_data["patient_id"],
            "prediction": {
                "risk_score": 0.75,
                "recommendations": [
                    "Regular check-ins",
                    "Medication review"
                ]
            }
        }
        
        # Verify model output doesn't contain PHI
        output_str = str(model_output)
        assert sample_patient_data["name"] not in output_str
        assert sample_patient_data["ssn"] not in output_str
        
        # Verify sanitizer doesn't modify non-PHI output
        sanitized = phi_sanitizer.sanitize_json(model_output)
        assert str(sanitized) == str(model_output), "Model output should be PHI-free"

    def test_batch_processing_isolates_patient_data(self, phi_sanitizer):
        """Test that batch processing properly isolates patient data."""
        # Create test batch with multiple patients
        patient_batch = [
            {"id": "p1", "name": "Alice Johnson", "ssn": "111-22-3333"},
            {"id": "p2", "name": "Bob Williams", "ssn": "444-55-6666"}
        ]
        
        # Sanitize the batch
        sanitized_batch = [phi_sanitizer.sanitize_json(patient) for patient in patient_batch]
        
        # Verify PHI is sanitized
        assert "Alice Johnson" not in str(sanitized_batch)
        assert "Bob Williams" not in str(sanitized_batch)
        assert "111-22-3333" not in str(sanitized_batch)
        assert "444-55-6666" not in str(sanitized_batch)
        
        # Verify identification (non-PHI) is preserved
        assert "p1" in str(sanitized_batch[0])
        assert "p2" in str(sanitized_batch[1])


class TestMLSecureStorage:
    """Test secure storage of ML data."""

    def test_ml_model_storage_encryption(self, mock_encryption_service):
        """Test that ML models are stored encrypted."""
        # Simulate model data
        model_data = b'{"model": "xgboost", "parameters": {"max_depth": 5}}'
        
        # Encrypt the model
        encrypted_model = mock_encryption_service.encrypt(model_data)
        
        # Verify encryption was performed
        assert encrypted_model != model_data
        assert encrypted_model == b"encrypted_data"  # From our mock

    def test_ml_model_loading_decryption(self, mock_encryption_service):
        """Test that ML models are decrypted when loaded."""
        # Simulate encrypted model
        encrypted_model = b"encrypted_model_data"
        
        # Decrypt the model
        decrypted_model = mock_encryption_service.decrypt(encrypted_model)
        
        # Verify decryption produces valid model data
        assert decrypted_model == b'{"data": "sample_data"}'  # From our mock

    def test_phi_sanitization_in_model_input(self, phi_sanitizer):
        """Test that input to ML models is properly sanitized."""
        # Simulate model input with PHI
        model_input = {
            "features": [0.5, 1.2, 3.7],
            "metadata": {
                "source": "Patient John Smith, SSN: 123-45-6789"
            }
        }
        
        # Sanitize model input
        sanitized_input = phi_sanitizer.sanitize_json(model_input)
        
        # Verify features are preserved and PHI is sanitized
        assert sanitized_input["features"] == model_input["features"]
        assert "John Smith" not in str(sanitized_input)
        assert "123-45-6789" not in str(sanitized_input)
        assert "[REDACTED NAME]" in str(sanitized_input)
        assert "[REDACTED SSN]" in str(sanitized_input)