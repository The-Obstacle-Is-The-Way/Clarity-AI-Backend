# -*- coding: utf-8 -*-
"""
Unit tests for the PAT service.

This module contains tests for both the mock and AWS Bedrock implementations
of the Pretrained Actigraphy Transformer (PAT) service.
"""

from app.core.services.ml.pat.mock import MockPATService as MockPAT
from app.core.services.ml.pat.interface import PATInterface
from app.core.services.ml.pat.factory import PATServiceFactory
from app.core.services.ml.pat.bedrock import BedrockPAT
import json
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from app.core.exceptions import (
    InvalidConfigurationError,
    InvalidRequestError,
    ResourceNotFoundError,
    ServiceUnavailableError,
)


# Helper function to create sample readings
def create_sample_readings(num_readings: int = 10) -> List[Dict[str, Any]]:
    """Create sample accelerometer readings for testing."""
    start_time = datetime.now() - timedelta(hours=1)
    readings = []
    for i in range(num_readings):
        timestamp = start_time + timedelta(seconds=i * 6)  # 10Hz
        reading = {
            "timestamp": timestamp.isoformat(),
            "x": 0.1 * i,
            "y": 0.2 * i,
            "z": 0.3 * i,
        }
        readings.append(reading)
    return readings


# Test fixture for a configured MockPAT instance
@pytest.fixture
def mock_pat_service() -> MockPAT:
    """Fixture providing a configured MockPAT instance."""
    service = MockPAT()
    service.initialize({})
    return service


# Test fixture for a mock-configured BedrockPAT instance
@pytest.fixture
def bedrock_pat_service() -> BedrockPAT:
    """Fixture providing a BedrockPAT instance with mocked AWS clients."""
    service = BedrockPAT()

    # Create mock AWS clients
    service.bedrock_runtime = MagicMock()
    service.s3_client = MagicMock()
    service.dynamodb_client = MagicMock()

    # Configure service
    service.initialized = True
    service.bucket_name = "test-bucket"
    service.table_name = "test-table"
    service.kms_key_id = "test-key-id"
    service.model_mapping = {
        "sleep": "test-sleep-model",
        "activity": "test-activity-model",
        "mood": "test-mood-model"
    }
    return service


class TestMockPAT:
    """Test suite for the MockPAT implementation."""

    def test_initialization(self) -> None:
        """Test that the MockPAT service initializes correctly."""
        service = MockPAT()
        assert not service.initialized

        service.initialize({})
        assert service.initialized

    def test_analyze_actigraphy(self, mock_pat_service: MockPAT) -> None:
        """Test analyzing actigraphy data with the mock service."""
        # Prepare test data
        patient_id = "test-patient-1"
        readings = create_sample_readings(20)
        start_time = datetime.now() - timedelta(hours=1)
        end_time = datetime.now()

        # Call the service
        result = mock_pat_service.analyze_actigraphy(
            patient_id=patient_id,
            readings=readings,
            start_time=start_time.isoformat(),
            end_time=end_time.isoformat(),
            sampling_rate_hz=10.0,
            device_info={"device_type": "fitbit", "manufacturer": "Fitbit", "model": "versa-3"},
            analysis_types=["sleep_quality", "activity_levels"]
        )

        # Verify results
        assert isinstance(result, dict)
        assert "analysis_id" in result
        assert "patient_id" in result
        assert result["patient_id"] == patient_id
        assert "timestamp" in result

        # Check for sleep metrics
        assert "sleep_metrics" in result
        sleep_metrics = result["sleep_metrics"]
        assert 0 <= sleep_metrics["sleep_efficiency"] <= 1

        # Check for activity levels
        assert "activity_levels" in result
        activity_levels = result["activity_levels"]
        assert "sedentary" in activity_levels
        assert "light" in activity_levels
        assert "moderate" in activity_levels
        assert "vigorous" in activity_levels

    def test_get_embeddings(self, mock_pat_service: MockPAT) -> None:
        """Test generating embeddings with the mock service."""
        # Prepare test data
        patient_id = "test-patient-1"
        readings = create_sample_readings(20)
        start_time = datetime.now() - timedelta(hours=1)
        end_time = datetime.now()

        # Call the service
        result = mock_pat_service.get_actigraphy_embeddings(
            patient_id=patient_id,
            readings=readings,
            start_time=start_time.isoformat(),
            end_time=end_time.isoformat(),
            sampling_rate_hz=10.0
        )

        # Verify results
        assert isinstance(result, dict)
        assert "embedding_id" in result
        assert "patient_id" in result
        assert result["patient_id"] == patient_id
        assert "timestamp" in result
        assert "embeddings" in result
        assert isinstance(result["embeddings"], list)
        assert len(result["embeddings"]) == result["embedding_size"]

    def test_get_analysis_by_id(self, mock_pat_service: MockPAT) -> None:
        """Test retrieving an analysis by ID with the mock service."""
        # First create an analysis
        patient_id = "test-patient-1"
        readings = create_sample_readings(20)
        start_time = datetime.now() - timedelta(hours=1)
        end_time = datetime.now()

        analysis = mock_pat_service.analyze_actigraphy(
            patient_id=patient_id,
            readings=readings,
            start_time=start_time.isoformat(),
            end_time=end_time.isoformat(),
            sampling_rate_hz=10.0,
            device_info={"device_type": "fitbit", "manufacturer": "Fitbit", "model": "versa-3"},
            analysis_types=["sleep_quality"]
        )

        analysis_id = analysis["analysis_id"]

        # Now retrieve it
        result = mock_pat_service.get_analysis_by_id(analysis_id)

        # Verify results
        assert isinstance(result, dict)
        assert result["analysis_id"] == analysis_id
        assert result["patient_id"] == patient_id
        assert "sleep_metrics" in result

    def test_get_patient_analyses(self, mock_pat_service: MockPAT) -> None:
        """Test retrieving analyses for a patient with the mock service."""
        # First create multiple analyses for the same patient
        patient_id = "test-patient-2"
        readings = create_sample_readings(20)
        start_time1 = datetime.now() - timedelta(hours=2)
        end_time1 = datetime.now() - timedelta(hours=1)
        start_time2 = datetime.now() - timedelta(hours=1)
        end_time2 = datetime.now()

        analysis1 = mock_pat_service.analyze_actigraphy(
            patient_id=patient_id,
            readings=readings,
            start_time=start_time1.isoformat(),
            end_time=end_time1.isoformat(),
            sampling_rate_hz=10.0,
            device_info={"device_type": "fitbit", "manufacturer": "Fitbit", "model": "versa-3"},
            analysis_types=["sleep_quality"]
        )

        analysis2 = mock_pat_service.analyze_actigraphy(
            patient_id=patient_id,
            readings=readings,
            start_time=start_time2.isoformat(),
            end_time=end_time2.isoformat(),
            sampling_rate_hz=10.0,
            device_info={"device_type": "fitbit", "manufacturer": "Fitbit", "model": "versa-3"},
            analysis_types=["activity_levels"]
        )

        # Retrieve analyses for the patient
        results = mock_pat_service.get_patient_analyses(patient_id)

        # Verify results
        assert isinstance(results, list)
        assert len(results) == 2
        analysis_ids = {result["analysis_id"] for result in results}
        assert analysis1["analysis_id"] in analysis_ids
        assert analysis2["analysis_id"] in analysis_ids


class TestBedrockPAT:
    """Test suite for the BedrockPAT implementation."""

    def test_initialization(self) -> None:
        """Test initialization with invalid configuration."""
        service = BedrockPAT()

        # Test with missing bucket name
        with pytest.raises(InvalidConfigurationError):
            service.initialize({})

        # Test with missing table name
        with pytest.raises(InvalidConfigurationError):
            service.initialize({"bucket_name": "test-bucket"})

        # Test with missing KMS key
        with pytest.raises(InvalidConfigurationError):
            service.initialize({
                "bucket_name": "test-bucket",
                "table_name": "test-table"
            })

        # Test with complete configuration
        with patch("boto3.client") as mock_boto:
            service.initialize({
                "bucket_name": "test-bucket",
                "table_name": "test-table",
                "kms_key_id": "test-key-id"
            })
            assert service.initialized
            assert service.bucket_name == "test-bucket"
            assert service.table_name == "test-table"
            assert service.kms_key_id == "test-key-id"

    def test_analyze_actigraphy(self, bedrock_pat_service: BedrockPAT) -> None:
        """Test analyzing actigraphy data with the Bedrock service."""
        # Prepare test data
        patient_id = "test-patient-1"
        readings = create_sample_readings(20)
        start_time = datetime.now() - timedelta(hours=1)
        end_time = datetime.now()

        # Mock Bedrock response
        mock_response_body = json.dumps({
            "sleep_metrics": {
                "sleep_efficiency": 0.85,
                "sleep_duration_hours": 7.5,
                "wake_after_sleep_onset_minutes": 12.3,
                "sleep_latency_minutes": 8.2
            }
        })
        mock_response = {
            "body": MagicMock()
        }
        mock_response["body"].read.return_value = mock_response_body.encode("utf-8")

        bedrock_pat_service.bedrock_runtime.invoke_model.return_value = mock_response

        # Mock DynamoDB response
        bedrock_pat_service.dynamodb_client.put_item.return_value = {}

        # Call the service
        result = bedrock_pat_service.analyze_actigraphy(
            patient_id=patient_id,
            readings=readings,
            start_time=start_time.isoformat(),
            end_time=end_time.isoformat(),
            sampling_rate_hz=10.0,
            device_info={"device_type": "fitbit", "manufacturer": "Fitbit", "model": "versa-3"},
            analysis_types=["sleep_quality"]
        )

        # Verify results
        assert isinstance(result, dict)
        assert "analysis_id" in result
        assert "patient_id" in result
        assert result["patient_id"] == patient_id
        assert "timestamp" in result
        assert "sleep_metrics" in result
        assert result["sleep_metrics"]["sleep_efficiency"] == 0.85

        # Verify Bedrock was called correctly
        bedrock_pat_service.bedrock_runtime.invoke_model.assert_called_once()
        args, kwargs = bedrock_pat_service.bedrock_runtime.invoke_model.call_args
        assert kwargs["contentType"] == "application/json"
        assert kwargs["accept"] == "application/json"

        # Verify DynamoDB was called correctly
        bedrock_pat_service.dynamodb_client.put_item.assert_called_once()
        args, kwargs = bedrock_pat_service.dynamodb_client.put_item.call_args
        assert kwargs["TableName"] == "test-table"

    def test_get_embeddings(self, bedrock_pat_service: BedrockPAT) -> None:
        """Test generating embeddings with the Bedrock service."""
        # Prepare test data
        patient_id = "test-patient-1"
        readings = create_sample_readings(20)
        start_time = datetime.now() - timedelta(hours=1)
        end_time = datetime.now()

        # Mock Bedrock response
        mock_embeddings = [0.1, 0.2, 0.3, 0.4, 0.5]
        mock_response_body = json.dumps({
            "embeddings": mock_embeddings,
            "model_version": "PAT-1.0"
        })
        mock_response = {
            "body": MagicMock()
        }
        mock_response["body"].read.return_value = mock_response_body.encode("utf-8")

        bedrock_pat_service.bedrock_runtime.invoke_model.return_value = mock_response

        # Call the service
        result = bedrock_pat_service.get_actigraphy_embeddings(
            patient_id=patient_id,
            readings=readings,
            start_time=start_time.isoformat(),
            end_time=end_time.isoformat(),
            sampling_rate_hz=10.0
        )

        # Verify results
        assert isinstance(result, dict)
        assert "embedding_id" in result
        assert "patient_id" in result
        assert result["patient_id"] == patient_id
        assert "timestamp" in result
        assert "embeddings" in result
        assert result["embeddings"] == mock_embeddings
        assert "embedding_size" in result
        assert result["embedding_size"] == len(mock_embeddings)
        assert result["model_version"] == "PAT-1.0"

        # Verify Bedrock was called correctly
        bedrock_pat_service.bedrock_runtime.invoke_model.assert_called_once()

    def test_get_analysis_by_id(self, bedrock_pat_service: BedrockPAT) -> None:
        """Test retrieving an analysis by ID with the Bedrock service."""
        analysis_id = str(uuid.uuid4())

        # Mock DynamoDB response
        mock_result = {
            "analysis_id": analysis_id,
            "patient_id": "test-patient-1",
            "timestamp": datetime.now().isoformat(),
            "sleep_metrics": {
                "sleep_efficiency": 0.85
            }
        }
        mock_dynamodb_response = {
            "Item": {
                "AnalysisId": {"S": analysis_id},
                "Result": {"S": json.dumps(mock_result)}
            }
        }

        bedrock_pat_service.dynamodb_client.get_item.return_value = mock_dynamodb_response

        # Call the service
        result = bedrock_pat_service.get_analysis_by_id(analysis_id)

        # Verify results
        assert isinstance(result, dict)
        assert result["analysis_id"] == analysis_id
        assert "sleep_metrics" in result
        assert result["sleep_metrics"]["sleep_efficiency"] == 0.85

        # Verify DynamoDB was called correctly
        bedrock_pat_service.dynamodb_client.get_item.assert_called_once()
        args, kwargs = bedrock_pat_service.dynamodb_client.get_item.call_args
        assert kwargs["TableName"] == "test-table"
        assert kwargs["Key"]["AnalysisId"]["S"] == analysis_id

    def test_get_analysis_by_id_not_found(self, bedrock_pat_service: BedrockPAT) -> None:
        """Test retrieving a non-existent analysis by ID."""
        analysis_id = str(uuid.uuid4())

        # Mock DynamoDB response (no item found)
        mock_dynamodb_response = {}

        bedrock_pat_service.dynamodb_client.get_item.return_value = mock_dynamodb_response

        # Call the service
        with pytest.raises(ResourceNotFoundError):
            bedrock_pat_service.get_analysis_by_id(analysis_id)

    def test_get_patient_analyses(self, bedrock_pat_service: BedrockPAT) -> None:
        """Test retrieving analyses for a patient with the Bedrock service."""
        patient_id = "test-patient-1"

        # Mock DynamoDB response
        analysis_id_1 = str(uuid.uuid4())
        analysis_id_2 = str(uuid.uuid4())

        mock_result_1 = {
            "analysis_id": analysis_id_1,
            "patient_id": patient_id,
            "timestamp": datetime.now().isoformat(),
            "sleep_metrics": {
                "sleep_efficiency": 0.85
            }
        }

        mock_result_2 = {
            "analysis_id": analysis_id_2,
            "patient_id": patient_id,
            "timestamp": datetime.now().isoformat(),
            "activity_levels": {
                "sedentary": 0.6,
                "light": 0.3,
                "moderate": 0.1,
                "vigorous": 0.0
            }
        }

        mock_dynamodb_response = {
            "Items": [
                {
                    "AnalysisId": {"S": analysis_id_1},
                    "Timestamp": {"S": datetime.now().isoformat()},
                    "Result": {"S": json.dumps(mock_result_1)}
                },
                {
                    "AnalysisId": {"S": analysis_id_2},
                    "Timestamp": {"S": datetime.now().isoformat()},
                    "Result": {"S": json.dumps(mock_result_2)}
                }
            ]
        }

        bedrock_pat_service.dynamodb_client.query.return_value = mock_dynamodb_response

        # Call the service
        result = bedrock_pat_service.get_patient_analyses(
            patient_id=patient_id,
            limit=10,
            offset=0
        )

        # Verify results
        assert isinstance(result, dict)
        assert result["patient_id"] == patient_id
        assert "analyses" in result
        assert isinstance(result["analyses"], list)
        assert len(result["analyses"]) == 2
        assert result["total"] == 2

        # Verify DynamoDB was called correctly
        bedrock_pat_service.dynamodb_client.query.assert_called_once()
        args, kwargs = bedrock_pat_service.dynamodb_client.query.call_args
        assert kwargs["TableName"] == "test-table"
        assert kwargs["IndexName"] == "PatientIdIndex"

    def test_get_patient_analyses_not_found(self, bedrock_pat_service: BedrockPAT) -> None:
        """Test retrieving analyses for a patient with no results."""
        patient_id = "test-patient-not-found"

        # Mock DynamoDB response (no items found)
        mock_dynamodb_response = {
            "Items": []
        }

        bedrock_pat_service.dynamodb_client.query.return_value = mock_dynamodb_response

        # Call the service
        with pytest.raises(ResourceNotFoundError):
            bedrock_pat_service.get_patient_analyses(
                patient_id=patient_id,
                limit=10,
                offset=0
            )

    def test_integrate_with_digital_twin(self, bedrock_pat_service: BedrockPAT) -> None:
        """Test integrating actigraphy analysis with a digital twin with the Bedrock service."""
        # Prepare test data
        patient_id = "test-patient-1"
        profile_id = "test-profile-1"

        actigraphy_analysis = {
            "analysis_id": str(uuid.uuid4()),
            "patient_id": patient_id,
            "timestamp": datetime.now().isoformat(),
            "sleep_metrics": {
                "sleep_efficiency": 0.85
            }
        }

        # Mock Bedrock response
        mock_response_body = json.dumps({
            "profile_id": profile_id,
            "patient_id": patient_id,
            "timestamp": datetime.now().isoformat(),
            "integrated_profile": {
                "sleep_patterns": {
                    "efficiency": 0.85,
                    "consistency": 0.7
                },
                "mental_health_indicators": {
                    "depression_risk": 0.2,
                    "anxiety_level": 0.3
                }
            }
        })
        mock_response = {
            "body": MagicMock()
        }
        mock_response["body"].read.return_value = mock_response_body.encode("utf-8")

        bedrock_pat_service.bedrock_runtime.invoke_model.return_value = mock_response

        # Call the service
        result = bedrock_pat_service.integrate_with_digital_twin(
            patient_id=patient_id,
            profile_id=profile_id,
            actigraphy_analysis=actigraphy_analysis
        )

        # Verify results
        assert isinstance(result, dict)
        assert "profile_id" in result
        assert result["profile_id"] == profile_id
        assert "patient_id" in result
        assert result["patient_id"] == patient_id
        assert "timestamp" in result
        assert "integrated_profile" in result
        assert "sleep_patterns" in result["integrated_profile"]
        assert "mental_health_indicators" in result["integrated_profile"]

        # Verify Bedrock was called correctly
        bedrock_pat_service.bedrock_runtime.invoke_model.assert_called_once()


class TestPATFactory:
    """Test suite for the PAT factory."""

    def test_create_pat_service_mock(self) -> None:
        """Test creating a mock PAT service."""
        with patch("app.core.services.ml.pat.factory.settings") as mock_settings:
            # Set up mock settings
            mock_settings.ml_config = {
                "pat": {
                    "provider": "mock"
                }
            }

            # Create service
            service = PATServiceFactory.create_pat_service()

            # Verify result
            assert isinstance(service, MockPAT)
            assert service.initialized

    def test_create_pat_service_bedrock(self) -> None:
        """Test creating a Bedrock PAT service."""
        with patch("app.core.services.ml.pat.factory.settings") as mock_settings, \
                patch("boto3.client") as mock_boto:
            # Set up mock settings
            mock_settings.ml_config = {
                "pat": {
                    "provider": "bedrock",
                    "bucket_name": "test-bucket",
                    "table_name": "test-table",
                    "kms_key_id": "test-key-id"
                }
            }

            # Create service
            service = PATServiceFactory.create_pat_service()

            # Verify result
            assert isinstance(service, BedrockPAT)
            assert service.initialized

    def test_create_pat_service_invalid_provider(self) -> None:
        """Test creating a PAT service with an invalid provider."""
        with patch("app.core.services.ml.pat.factory.settings") as mock_settings:
            # Set up mock settings
            mock_settings.ml_config = {
                "pat": {
                    "provider": "invalid-provider"
                }
            }

            # Attempt to create service
            with pytest.raises(InvalidConfigurationError):
                PATServiceFactory.create_pat_service()

    def test_create_pat_service_missing_provider(self) -> None:
        """Test creating a PAT service with a missing provider."""
        with patch("app.core.services.ml.pat.factory.settings") as mock_settings:
            # Set up mock settings
            mock_settings.ml_config = {
                "pat": {}
            }

            # Attempt to create service
            with pytest.raises(InvalidConfigurationError):
                PATServiceFactory.create_pat_service()

    def test_create_pat_service_with_config(self) -> None:
        """Test creating a PAT service with explicit config."""
        # Create config
        config = {
            "provider": "mock"
        }

        # Create service
        service = PATServiceFactory.create_pat_service(config)

        # Verify result
        assert isinstance(service, MockPAT)
        assert service.initialized
