"""
Unit tests for AWS PAT service implementation.

This module contains tests for the AWS implementation of the PAT service.
All AWS services are mocked to avoid making actual API calls.
"""

import os
os.environ.setdefault('AWS_REGION', 'us-east-1')
import json
import logging
import uuid
from datetime import datetime
from unittest.mock import MagicMock, patch

import boto3
import pytest
from botocore.exceptions import ClientError

from app.core.services.ml.pat.aws import AWSPATService
from app.core.services.ml.pat.exceptions import (
    AnalysisError,
    AuthorizationError,
    EmbeddingError,
    InitializationError,
    IntegrationError,
    ResourceNotFoundError,
    ValidationError,
)


@pytest.fixture
def aws_config():
    """Fixture for AWS configuration."""
    return {
        "aws_region": "us-east-1",
        "endpoint_name": "test-pat-endpoint",
        "bucket_name": "test-pat-bucket",
        "analyses_table": "test-pat-analyses",
        "embeddings_table": "test-pat-embeddings",
        "integrations_table": "test-pat-integrations",
    }


@pytest.fixture
def mock_boto3():
    """Fixture for mocking boto3."""
    # Create mock clients without patching boto3 yet
    sagemaker_runtime = MagicMock()
    s3_client = MagicMock()
    dynamodb = MagicMock()
    comprehend_medical = MagicMock()
    
    # Create a table method for dynamodb
    table = MagicMock()
    dynamodb.Table.return_value = table
    
    # Return the mocks - we'll manage the patching in the fixture that uses these
    return {
        "sagemaker-runtime": sagemaker_runtime,
        "s3": s3_client,
        "dynamodb_resource": dynamodb,
        "comprehendmedical": comprehend_medical,
    }


@pytest.fixture
def aws_pat_service(mock_boto3, aws_config):
    """Fixture for AWS PAT service, injecting mock clients."""
    service = AWSPATService()
    
    # Inject mock clients directly using the updated initialize method
    service.initialize(
        config=aws_config,
        sagemaker_runtime_client=mock_boto3.get("sagemaker-runtime"), # Use .get for safety
        s3_client=mock_boto3.get("s3"),
        comprehend_medical_client=mock_boto3.get("comprehendmedical"),
        dynamodb_resource=mock_boto3.get("dynamodb_resource") 
    )
    
    yield service


class TestAWSPATService:
    """Test the AWS PAT service implementation."""

    def test_initialization(self, aws_config, mock_boto3):
        """Test service initialization."""
        service = AWSPATService()
        service.initialize(aws_config)

        assert service._initialized is True
        assert service._endpoint_name == aws_config["endpoint_name"]
        assert service._bucket_name == aws_config["bucket_name"]
        assert service._analyses_table == aws_config["analyses_table"]
        assert service._embeddings_table == aws_config["embeddings_table"]
        assert service._integrations_table == aws_config["integrations_table"]
        # Assert that AWS clients were initialized
        assert service._sagemaker_runtime is not None
        assert service._s3_client is not None
        assert service._dynamodb_resource is not None
        assert service._comprehend_medical is not None

    def test_initialization_failure(self, aws_config):
        """Test initialization failure."""
        # Use a more targeted patch that only affects the specific client we want to fail
        original_client = boto3.client
        
        def mock_client_factory(*args, **kwargs):
            if args[0] == 'sagemaker-runtime':
                raise ClientError(
                    {"Error": {"Code": "InvalidParameterValue", "Message": "Test error"}},
                    "CreateEndpoint"
                )
            return original_client(*args, **kwargs)
        
        # Apply the patch
        with patch("boto3.client", side_effect=mock_client_factory):
            service = AWSPATService()
            with pytest.raises(InitializationError):
                service.initialize(aws_config)

    def test_sanitize_phi(self, mocker): 
        """Test PHI sanitization logic by manually instantiating after patching boto3.client."""
        text = "Patient is John Doe, lives at 123 Main St."
        
        # 1. Create and configure the mock comprehend client
        mock_comprehend_medical = MagicMock(spec=['detect_phi'])
        mock_response_dict = {
            "Entities": [
                {"Type": "NAME", "BeginOffset": 11, "EndOffset": 15, "Score": 0.99},
                {"Type": "ADDRESS", "BeginOffset": 28, "EndOffset": 38, "Score": 0.95}
            ]
        }
        mock_comprehend_medical.detect_phi.return_value = mock_response_dict

        # 3. Manually instantiate the service 
        service_instance = AWSPATService()
        
        #    Use a dummy config matching what the fixture provided, with correct keys
        dummy_config = {
            "aws_region": "us-east-1",
            "endpoint_name": "test-pat-endpoint",
            "bucket_name": "test-pat-bucket",
            "analyses_table": "test-pat-analyses",
            "embeddings_table": "test-pat-embeddings",
            "integrations_table": "test-pat-integrations",
        }
        #    Inject the mock client directly during initialization
        service_instance.initialize(
            config=dummy_config, 
            comprehend_medical_client=mock_comprehend_medical
        )

        # 4. Call the method under test using the manual instance
        sanitized = service_instance._sanitize_phi(text)

        # 5. Assertions
        mock_comprehend_medical.detect_phi.assert_called_once_with(Text=text)
        assert sanitized == "Patient is [NAME], lives at [ADDRESS]."

    def test_sanitize_phi_error(self, aws_pat_service, mock_boto3):
        """Test PHI sanitization with error."""
        # Create a direct patch for the _sanitize_phi method to test it independently
        with patch.object(aws_pat_service, '_comprehend_medical') as mock_cm:
            # Configure the mock to raise an exception
            mock_cm.detect_phi.side_effect = ClientError(
                {"Error": {"Code": "InternalServerError", "Message": "Test error"}},
                "DetectPHI"
            )

            text = "Patient is John Smith, a 45-year-old male."
            sanitized = aws_pat_service._sanitize_phi(text)

            # Verify that a placeholder is returned to avoid leaking PHI
            assert sanitized == "[PHI SANITIZATION ERROR]"

    def test_analyze_actigraphy(self, aws_pat_service):
        """Test actigraphy analysis."""
        # Mock data
        patient_id = "patient123"
        readings = [{"x": 0.1, "y": 0.2, "z": 0.3, "timestamp": "2025-03-28T12:00:00Z"}]
        start_time = "2025-03-28T12:00:00Z"
        end_time = "2025-03-28T13:00:00Z"
        sampling_rate_hz = 50.0
        device_info = {"name": "ActiGraph GT9X", "firmware": "1.7.0"}
        analysis_types = ["activity_levels", "sleep_analysis"]

        # Call method (implementation is stubbed)
        result = aws_pat_service.analyze_actigraphy(
            patient_id,
            readings,
            start_time,
            end_time,
            sampling_rate_hz,
            device_info,
            analysis_types,
        )

        # Basic validation of stub implementation
        assert "analysis_id" in result
        assert "patient_id" in result
        assert "timestamp" in result
        assert "analysis_types" in result
        assert result["patient_id"] == patient_id
        assert result["analysis_types"] == analysis_types

    def test_get_actigraphy_embeddings(self, aws_pat_service):
        """Test actigraphy embeddings generation."""
        # Mock data
        patient_id = "patient123"
        readings = [{"x": 0.1, "y": 0.2, "z": 0.3, "timestamp": "2025-03-28T12:00:00Z"}]
        start_time = "2025-03-28T12:00:00Z"
        end_time = "2025-03-28T13:00:00Z"
        sampling_rate_hz = 50.0

        # Call method (implementation is stubbed)
        result = aws_pat_service.get_actigraphy_embeddings(
            patient_id, readings, start_time, end_time, sampling_rate_hz
        )

        # Basic validation of stub implementation
        assert "embedding_id" in result
        assert "patient_id" in result
        assert "timestamp" in result
        assert "embedding" in result
        assert result["patient_id"] == patient_id

    def test_get_analysis_by_id(self, aws_pat_service):
        """Test retrieving analysis by ID."""
        # This will raise ResourceNotFoundError as the stub implementation
        # doesn't actually store or retrieve real data
        with pytest.raises(ResourceNotFoundError):
            aws_pat_service.get_analysis_by_id("test-analysis-id")

    def test_get_model_info(self, aws_pat_service, aws_config):
        """Test getting model information."""
        model_info = aws_pat_service.get_model_info()

        assert model_info["name"] == "AWS-PAT"
        assert "version" in model_info
        assert "capabilities" in model_info
        assert aws_config["endpoint_name"] == model_info["endpoint_name"]
        assert model_info["active"] is True

    def test_integrate_with_digital_twin(self, aws_pat_service):
        """Test integrating analysis with digital twin."""
        # Mock data
        patient_id = "patient123"
        profile_id = "profile456"
        analysis_id = "analysis789"

        # Call method (implementation is stubbed)
        result = aws_pat_service.integrate_with_digital_twin(
            patient_id, profile_id, analysis_id
        )

        # Basic validation of stub implementation
        assert "integration_id" in result
        assert "patient_id" in result
        assert "profile_id" in result
        assert "analysis_id" in result
        assert result["patient_id"] == patient_id
        assert result["profile_id"] == profile_id
        assert result["analysis_id"] == analysis_id
        assert result["status"] == "success"
