# -*- coding: utf-8 -*-
"""
Unit tests for PHI Detection service.

This module tests the AWS Comprehend Medical PHI Detection service implementation.
"""

import json
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

# Corrected import path for AWSComprehendMedicalPHIDetection
from app.infrastructure.ml.phi.aws_comprehend_medical import AWSComprehendMedicalPHIDetection
from app.core.exceptions import (
    InvalidConfigurationError,
    InvalidRequestError,
    ServiceUnavailableError
)



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
        service = AWSComprehendMedicalPHIDetection()
        with patch("boto3.client") as mock_boto3:
            mock_client = MagicMock()
            mock_boto3.return_value = mock_client
            service.initialize({
                "aws_region": "us-east-1"
            })
            return service

    def test_initialization(self):
        """Test service initialization with valid configuration."""
        service = AWSComprehendMedicalPHIDetection()

        with patch("boto3.client") as mock_boto3:
            mock_client = MagicMock()
            mock_boto3.return_value = mock_client

            service.initialize({
                "aws_region": "us-east-1",
                "aws_access_key_id": "test_key",
                "aws_secret_access_key": "test_secret"
            })

            assert service.is_healthy()
            mock_boto3.assert_called_once()

    def test_initialization_boto_error(self):
        """Test service initialization with Boto error."""
        service = AWSComprehendMedicalPHIDetection()

        with patch("boto3.client") as mock_boto3:
            mock_boto3.side_effect = ClientError(
                {"Error": {"Code": "InvalidClientTokenId", "Message": "Invalid token"}},
                "CreateClient"
            )

            with pytest.raises(InvalidConfigurationError):
                service.initialize({
                    "aws_region": "us-east-1"
                })

            assert not service.is_healthy()

    def test_detect_phi_with_phi(self, phi_detection_service, mock_comprehend_response_with_phi):
        """Test PHI detection with text containing PHI."""
        with patch.object(
            phi_detection_service._comprehend_medical_client,
            "detect_phi",
            return_value=mock_comprehend_response_with_phi
        ):
            result = phi_detection_service.detect_phi(
                "Patient is John Doe with phone 555-123-4567"
            )

            assert result["has_phi"] is True
            assert result["phi_count"] == 2
            assert "NAME" in result["phi_types"]
            assert "PHONE_OR_FAX" in result["phi_types"]

    def test_detect_phi_without_phi(self, phi_detection_service, mock_comprehend_response_without_phi):
        """Test PHI detection with text not containing PHI."""
        with patch.object(
            phi_detection_service._comprehend_medical_client,
            "detect_phi",
            return_value=mock_comprehend_response_without_phi
        ):
            result = phi_detection_service.detect_phi(
                "The patient is feeling better today"
            )

            assert result["has_phi"] is False
            assert result["phi_count"] == 0
            assert len(result["phi_types"]) == 0

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
        with patch.object(
            phi_detection_service._comprehend_medical_client,
            "detect_phi",
            side_effect=ClientError(
                {"Error": {"Code": "InternalServerError", "Message": "Internal error"}},
                "DetectPHI"
            )
        ):
            with pytest.raises(ServiceUnavailableError):
                phi_detection_service.detect_phi("Patient is John Doe")

    def test_redact_phi_with_phi(self, phi_detection_service, mock_comprehend_response_with_phi):
        """Test PHI redaction with text containing PHI."""
        with patch.object(
            phi_detection_service._comprehend_medical_client,
            "detect_phi",
            return_value=mock_comprehend_response_with_phi
        ):
            test_text = "Patient is John Doe with phone 555-123-4567"
            result = phi_detection_service.redact_phi(test_text)

            assert "[REDACTED-NAME]" in result["redacted_text"]
            assert "[REDACTED-PHONE_OR_FAX]" in result["redacted_text"]
            assert "John Doe" not in result["redacted_text"]
            assert "555-123-4567" not in result["redacted_text"]
            assert result["redaction_count"] == 2
            assert len(result["redaction_types"]) == 2
            assert "NAME" in result["redaction_types"]
            assert "PHONE_OR_FAX" in result["redaction_types"]

    def test_redact_phi_without_phi(self, phi_detection_service, mock_comprehend_response_without_phi):
        """Test PHI redaction with text not containing PHI."""
        with patch.object(
            phi_detection_service._comprehend_medical_client,
            "detect_phi",
            return_value=mock_comprehend_response_without_phi
        ):
            test_text = "The patient is feeling better today"
            result = phi_detection_service.redact_phi(test_text)

            assert result["redacted_text"] == test_text
            assert result["redaction_count"] == 0
            assert len(result["redaction_types"]) == 0
            assert result["original_text_length"] == len(test_text)
            assert result["redacted_text_length"] == len(test_text)

    def test_redact_phi_empty_text(self, phi_detection_service):
        """Test PHI redaction with empty text."""
        with pytest.raises(InvalidRequestError):
            phi_detection_service.redact_phi("")

    def test_redact_phi_service_not_initialized(self):
        """Test PHI redaction with uninitialized service."""
        service = AWSComprehendMedicalPHIDetection()

        with pytest.raises(ServiceUnavailableError):
            service.redact_phi("Patient is John Doe")
