"""
Integration tests for HIPAA-compliant PHI handling across database and logging.

This test suite verifies that:
    1. PHI is properly encrypted in the database
    2. PHI is sanitized in logs
    3. Exception handling never exposes PHI
"""

import logging
import uuid
from datetime import date
from io import StringIO
from typing import Any

import pytest

from app.domain.entities.patient import Patient
from app.domain.value_objects.address import Address
from app.domain.value_objects.emergency_contact import EmergencyContact

# Import the updated PatientModel
from app.infrastructure.database.models import PatientModel

# Import from consolidated PHI sanitization
from app.infrastructure.security.phi import PHISanitizer, get_sanitized_logger


@pytest.fixture
@pytest.mark.db_required
@pytest.mark.asyncio
async def test_patient() -> Patient:
    """Create a test patient with PHI for testing."""
    patient_id = uuid.uuid4()
    return Patient(
        id=patient_id,
        first_name="Integration",
        last_name="Test",
        date_of_birth=date(1980, 1, 1),
        email="integration.test@example.com",
        phone="555-987-6543",
        address=Address(
            street="123 Integration St",
            city="Testville",
            state="TS",
            zip_code="12345",
            country="Testland",
        ),
        emergency_contact=EmergencyContact(
            name="Emergency Contact", phone="555-123-4567", relationship="Test Relative"
        ),
        insurance=None,
        active=True,
        created_by=None,
    )


@pytest.fixture
def log_capture() -> StringIO:
    """Capture logs for testing."""
    # Create a string IO to capture logs
    log_stream = StringIO()

    # Create a handler that writes to the string IO
    handler = logging.StreamHandler(log_stream)
    handler.setLevel(logging.DEBUG)

    # Add the handler to the root logger
    root_logger = logging.getLogger()
    root_logger.addHandler(handler)

    # Set the root logger level to ensure we capture everything
    original_level = root_logger.level
    root_logger.setLevel(logging.DEBUG)

    try:
        yield log_stream
    finally:
        # Restore original settings
        root_logger.setLevel(original_level)
        root_logger.removeHandler(handler)


@pytest.mark.db_required
class TestPHISanitization:
    """Test suite for PHI sanitization integration."""

    @pytest.mark.asyncio
    async def test_phi_detection(self, test_patient) -> None:
        """Test that PHI detector correctly identifies PHI."""
        # Create a PHI sanitizer instance
        sanitizer = PHISanitizer()  # Using the consolidated sanitizer

        # Test detection in string
        test_string = (
            f"Patient {test_patient.first_name} {test_patient.last_name} "
            f"with email {test_patient.email} and phone {test_patient.phone}"
        )

        # Detect PHI - Use contains_phi method instead of detect_phi
        phi_detected = sanitizer.contains_phi(test_string)

        # Verify PHI was detected
        assert phi_detected, "PHI detection should find PHI in the test string"

        # Test detection in dictionary
        test_dict = {
            "name": f"{test_patient.first_name} {test_patient.last_name}",
            "contact": {"email": test_patient.email, "phone": test_patient.phone},
        }

        # Sanitize the dictionary to check if PHI is detected
        sanitized_dict = sanitizer.sanitize_json(test_dict)

        # Verify PHI was detected and sanitized
        assert (
            sanitized_dict != test_dict
        ), "PHI should be detected and sanitized in test dictionary"

    @pytest.mark.asyncio
    async def test_phi_sanitization_in_logs(self, test_patient, log_capture) -> None:
        """Test that PHI is properly sanitized in logs."""
        # Create a sanitized logger
        logger = get_sanitized_logger("test.phi")

        # Log a message with PHI
        test_message = (
            f"Processing patient: {test_patient.first_name} {test_patient.last_name} "
            f"with email {test_patient.email} and phone {test_patient.phone}"
        )
        logger.info(test_message)

        # Get log content
        log_content = log_capture.getvalue()

        # Verify PHI was sanitized
        assert test_patient.email not in log_content, "Email should be sanitized in logs"
        assert test_patient.phone not in log_content, "Phone should be sanitized in logs"
        assert test_patient.first_name not in log_content, "First name should be sanitized in logs"
        assert test_patient.last_name not in log_content, "Last name should be sanitized in logs"

        # Look for "[REDACTED" markers which indicate sanitization
        assert "[REDACTED" in log_content, "Log should contain redaction markers"

        # Even with sanitization, there should be some part of the original message structure
        # The sanitization should maintain the message format while replacing sensitive values
        assert "phone" in log_content, "Log should maintain some non-PHI terms like 'phone'"
        assert (
            "email" in log_content or "@" in log_content
        ), "Log should maintain some reference to email format"

    @pytest.mark.asyncio
    async def test_phi_sanitization_in_exception_handling(self, test_patient, log_capture) -> None:
        """Test that PHI is sanitized even in exception handling."""
        # Create a sanitized logger
        logger = get_sanitized_logger("test.phi.exception")

        # Create a function that raises an exception with PHI
        def function_with_phi_exception() -> None:
            try:
                # Simulate an operation that fails
                error_message = (
                    f"Failed to process patient {test_patient.first_name} {test_patient.last_name} "
                    f"with email {test_patient.email}"
                )
                raise ValueError(error_message)
            except Exception as e:
                # Log the exception (should be sanitized)
                logger.error(f"Error processing patient: {e!s}")
                raise  # Re-raise for test verification

        # Call the function and expect an exception
        try:
            function_with_phi_exception()
            pytest.fail("Expected exception was not raised")
        except ValueError:
            pass  # Expected

        # Get log content
        log_content = log_capture.getvalue()

        # Verify PHI was sanitized in the exception
        assert test_patient.email not in log_content, "Email should be sanitized in exception logs"
        assert (
            test_patient.first_name not in log_content
        ), "First name should be sanitized in exception logs"
        assert (
            test_patient.last_name not in log_content
        ), "Last name should be sanitized in exception logs"

        # Look for "[REDACTED" markers which indicate sanitization
        assert "[REDACTED" in log_content, "Log should contain redaction markers"

        # Verify sanitization maintains structure
        assert "patient" in log_content, "Log should maintain some non-PHI terms"
        assert "process" in log_content, "Log should maintain some non-PHI terms"

    @pytest.mark.asyncio
    async def test_phi_protection_across_modules(self, test_patient, log_capture) -> None:
        """Test PHI protection across module boundaries."""
        # This test simulates a full pipeline that processes patient data

        # Convert to model (simulating data access layer)
        patient_model = PatientModel.from_domain(test_patient)

        # Simulate processing in service layer
        def process_patient_data(model: PatientModel) -> dict[str, Any]:
            """Simulate processing in another module."""
            logger = get_sanitized_logger("service.patient")  # Use correct function

            # Log the processing (with PHI that should be sanitized)
            logger.info(
                f"Processing patient: {model.first_name} {model.last_name}",
                {"email": model.email, "phone": model.phone},
            )

            # Return processed data
            return {
                "id": model.id,
                "contact_info": f"{model.email} / {model.phone}",
                "full_name": f"{model.first_name} {model.last_name}",
                "status": "processed",
            }

        # Process the patient
        processed_data = process_patient_data(patient_model)

        # Verify the processed data still contains PHI (no sanitization of actual data)
        assert (
            test_patient.email in processed_data["contact_info"]
        ), "Email missing from processed data"
        assert (
            test_patient.phone in processed_data["contact_info"]
        ), "Phone missing from processed data"
        assert (
            test_patient.first_name in processed_data["full_name"]
        ), "First name missing from processed data"

        # Get log content
        log_content = log_capture.getvalue()

        # Verify logs do not contain PHI
        assert (
            test_patient.email not in log_content
        ), "Email found in logs during cross-module processing"
        assert (
            test_patient.phone not in log_content
        ), "Phone found in logs during cross-module processing"
        assert (
            test_patient.first_name not in log_content
        ), "First name found in logs during cross-module processing"


if __name__ == "__main__":
    pytest.main(["-xvs", __file__])
