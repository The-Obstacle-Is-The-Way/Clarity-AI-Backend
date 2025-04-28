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
    
    # Configure comprehend_medical mock for PHI detection
    comprehend_medical.detect_phi.return_value = {
        "Entities": [
            {
                "BeginOffset": 11,
                "EndOffset": 22,
                "Type": "NAME",
                "Score": 0.95,
            }
        ]
    }
    
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
    """Fixture for AWS PAT service."""
    # Use patch to override boto3.client and boto3.resource for this test
    with patch('boto3.client') as mock_client, patch('boto3.resource') as mock_resource:
        # Configure the mock to return our prepared mock objects
        def get_mock_client(service_name, **kwargs):
            if service_name in mock_boto3:
                return mock_boto3[service_name]
            return MagicMock()
            
        def get_mock_resource(service_name, **kwargs):
            resource_key = f"{service_name}_resource"
            if resource_key in mock_boto3:
                return mock_boto3[resource_key]
            return MagicMock()
            
        mock_client.side_effect = get_mock_client
        mock_resource.side_effect = get_mock_resource
        
        # Initialize the service
        service = AWSPATService()
        service.initialize(aws_config)
        
        return service


@pytest.mark.db_required()
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

    def test_sanitize_phi(self, aws_pat_service, mock_boto3):
        """Test PHI sanitization."""
        # Create a direct patch for the _sanitize_phi method to test it independently
        with patch.object(aws_pat_service, '_comprehend_medical') as mock_cm:
            # Configure the mock to return PHI entities
            mock_cm.detect_phi.return_value = {
                "Entities": [
                    {
                        "BeginOffset": 11,
                        "EndOffset": 22,
                        "Type": "NAME",
                        "Score": 0.95,
                    }
                ]
            }
            
            text = "Patient is John Smith, a 45-year-old male."
            sanitized = aws_pat_service._sanitize_phi(text)

            # Verify that PHI is replaced with redacted marker
            assert "John Smith" not in sanitized
            assert "[REDACTED-NAME]" in sanitized
            assert mock_cm.detect_phi.called

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
