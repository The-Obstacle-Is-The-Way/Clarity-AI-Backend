"""
Unit tests for PHI Detection service.

This module tests the AWS Comprehend Medical PHI Detection service implementation.
"""

from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from app.core.exceptions import (
    InvalidConfigurationError,
    InvalidRequestError,
    ServiceUnavailableError,
)

# Corrected import path for AWSComprehendMedicalPHIDetection
from app.infrastructure.ml.phi.aws_comprehend_medical import AWSComprehendMedicalPHIDetection


@pytest.mark.db_required()  # Assuming db_required is a valid marker
class TestAWSComprehendMedicalPHIDetection:
    """Test suite for AWS Comprehend Medical PHI detection service."""
    
    @pytest.fixture
    def mock_comprehend_response_with_phi(self):
        """Create a mock AWS Comprehend Medical response with PHI."""
        return {
            "Entities": [
                {
                    "BeginOffset": 11,
                    "EndOffset": 19,
                    "Score": 0.9876,
                    "Text": "John Doe",
                    "Type": "NAME",
                    "Category": "PROTECTED_HEALTH_INFORMATION"
                },
                {
                    "BeginOffset": 30,
                    "EndOffset": 42,
                    "Score": 0.9765,
                    "Text": "555-123-4567",
                    "Type": "PHONE_OR_FAX",
                    "Category": "PROTECTED_HEALTH_INFORMATION"
                }
            ],
            "UnmappedAttributes": [],
            "ModelVersion": "0.1.0"
        }
        
    @pytest.fixture
    def mock_comprehend_response_without_phi(self):
        """Create a mock AWS Comprehend Medical response without PHI."""
        return {
            "Entities": [],
            "UnmappedAttributes": [],
            "ModelVersion": "0.1.0"
        }
        
    @pytest.fixture
    def phi_detection_service(self):
        """Create a PHI detection service instance with mocked dependencies."""
        # Create a mock AWS service factory
        mock_factory = MagicMock()
        
        # Create a mock Comprehend Medical service
        mock_comprehend_service = MagicMock()
        
        # Configure the factory to return the mock service
        mock_factory.get_comprehend_medical_service.return_value = mock_comprehend_service
        
        # Create the service with the mock factory
        service = AWSComprehendMedicalPHIDetection(aws_service_factory=mock_factory)
        
        # Initialize the service
        service.initialize({
            "aws_region": "us-east-1"
        })
        
        return service

    def test_initialization(self):
        """Test service initialization with valid configuration."""
        # Create mock factory and service
        mock_factory = MagicMock()
        mock_comprehend_service = MagicMock()
        mock_factory.get_comprehend_medical_service.return_value = mock_comprehend_service
        
        # Create and initialize the service
        service = AWSComprehendMedicalPHIDetection(aws_service_factory=mock_factory)
        service.initialize({
            "aws_region": "us-east-1",
            "aws_access_key_id": "test_key",
            "aws_secret_access_key": "test_secret"
        })

        # Verify
        assert service.is_healthy()
        mock_factory.get_comprehend_medical_service.assert_called_once()

    def test_initialization_boto_error(self):
        """Test service initialization with Boto error."""
        # Create mock factory that raises an error
        mock_factory = MagicMock()
        mock_factory.get_comprehend_medical_service.side_effect = ClientError(
            {"Error": {"Code": "InvalidClientTokenId", "Message": "Invalid token"}},
            "CreateClient"
        )
        
        # Create the service
        service = AWSComprehendMedicalPHIDetection(aws_service_factory=mock_factory)

        # Verify initialization fails with the expected error
        with pytest.raises(InvalidConfigurationError):
            service.initialize({
                "aws_region": "us-east-1"
            })

        assert not service.is_healthy()

    def test_detect_phi_with_phi(self, phi_detection_service, mock_comprehend_response_with_phi):
        """Test PHI detection with text containing PHI."""
        # Configure the mock service to return the sample response
        phi_detection_service._comprehend_medical_service.detect_phi.return_value = mock_comprehend_response_with_phi
        
        # Call the method
        result = phi_detection_service.detect_phi(
            "Patient is John Doe with phone 555-123-4567"
        )

        # Verify results
        assert len(result) == 2
        assert result[0]["type"] == "NAME"
        assert result[0]["text"] == "John Doe"
        assert result[1]["type"] == "PHONE_OR_FAX"
        assert result[1]["text"] == "555-123-4567"
        
        # Verify service was called
        phi_detection_service._comprehend_medical_service.detect_phi.assert_called_once()

    def test_detect_phi_without_phi(self, phi_detection_service, mock_comprehend_response_without_phi):
        """Test PHI detection with text not containing PHI."""
        # Configure the mock service to return the sample response
        phi_detection_service._comprehend_medical_service.detect_phi.return_value = mock_comprehend_response_without_phi
        
        # Call the method
        result = phi_detection_service.detect_phi(
            "The patient is feeling better today"
        )

        # Verify results
        assert len(result) == 0
        
        # Verify service was called
        phi_detection_service._comprehend_medical_service.detect_phi.assert_called_once()

    def test_detect_phi_empty_text(self, phi_detection_service):
        """Test PHI detection with empty text."""
        with pytest.raises(InvalidRequestError):
            phi_detection_service.detect_phi("")

    def test_detect_phi_service_not_initialized(self):
        """Test PHI detection with uninitialized service."""
        service = AWSComprehendMedicalPHIDetection()

        with pytest.raises(ServiceUnavailableError):
            service.detect_phi("Patient is John Doe")

    def test_detect_phi_aws_error(self, phi_detection_service):
        """Test PHI detection with AWS Comprehend Medical error."""
        # Configure the mock service to raise an error
        phi_detection_service._comprehend_medical_service.detect_phi.side_effect = ClientError(
            {"Error": {"Code": "InternalServerError", "Message": "Internal error"}},
            "DetectPHI"
        )
        
        # Verify the error is properly handled
        with pytest.raises(ServiceUnavailableError):
            phi_detection_service.detect_phi("Patient is John Doe")

    def test_redact_phi_with_phi(self, phi_detection_service, mock_comprehend_response_with_phi):
        """Test PHI redaction with text containing PHI."""
        # Configure the mock service to return the sample response
        phi_detection_service._comprehend_medical_service.detect_phi.return_value = mock_comprehend_response_with_phi
        
        # Call the method
        test_text = "Patient is John Doe with phone 555-123-4567"
        redacted_text = phi_detection_service.redact_phi(test_text)

        # Verify results
        assert "[REDACTED-NAME]" in redacted_text
        assert "[REDACTED-PHONE_OR_FAX]" in redacted_text
        assert "John Doe" not in redacted_text
        assert "555-123-4567" not in redacted_text
        
        # Verify service was called
        phi_detection_service._comprehend_medical_service.detect_phi.assert_called_once()

    def test_redact_phi_without_phi(self, phi_detection_service, mock_comprehend_response_without_phi):
        """Test PHI redaction with text not containing PHI."""
        # Configure the mock service to return the sample response
        phi_detection_service._comprehend_medical_service.detect_phi.return_value = mock_comprehend_response_without_phi
        
        # Call the method
        test_text = "The patient is feeling better today"
        redacted_text = phi_detection_service.redact_phi(test_text)

        # Verify results - should return the original text unchanged
        assert redacted_text == test_text
        
        # Verify service was called
        phi_detection_service._comprehend_medical_service.detect_phi.assert_called_once()

    def test_redact_phi_empty_text(self, phi_detection_service):
        """Test PHI redaction with empty text."""
        with pytest.raises(InvalidRequestError):
            phi_detection_service.redact_phi("")

    def test_redact_phi_service_not_initialized(self):
        """Test PHI redaction with uninitialized service."""
        service = AWSComprehendMedicalPHIDetection()

        with pytest.raises(ServiceUnavailableError):
            service.redact_phi("Patient is John Doe")
            
    def test_contains_phi(self, phi_detection_service, mock_comprehend_response_with_phi):
        """Test contains_phi method with text containing PHI."""
        # Configure the mock service to return the sample response
        phi_detection_service._comprehend_medical_service.detect_phi.return_value = mock_comprehend_response_with_phi
        
        # Call the method
        result = phi_detection_service.contains_phi("Patient is John Doe with phone 555-123-4567")
        
        # Verify results
        assert result is True
        
        # Verify service was called
        phi_detection_service._comprehend_medical_service.detect_phi.assert_called_once()
        
    def test_contains_phi_without_phi(self, phi_detection_service, mock_comprehend_response_without_phi):
        """Test contains_phi method with text not containing PHI."""
        # Configure the mock service to return the sample response
        phi_detection_service._comprehend_medical_service.detect_phi.return_value = mock_comprehend_response_without_phi
        
        # Call the method
        result = phi_detection_service.contains_phi("The patient is feeling better today")
        
        # Verify results
        assert result is False
        
        # Verify service was called
        phi_detection_service._comprehend_medical_service.detect_phi.assert_called_once()
    
    def test_contains_phi_empty_text(self, phi_detection_service):
        """Test contains_phi method with empty text."""
        # Call the method
        result = phi_detection_service.contains_phi("")
        
        # Verify results
        assert result is False
        
        # Verify service was not called (short circuit)
        phi_detection_service._comprehend_medical_service.detect_phi.assert_not_called()
