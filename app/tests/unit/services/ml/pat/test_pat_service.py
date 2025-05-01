# -*- coding: utf-8 -*-
"""Unit tests for the Bedrock PAT service."""

import io
import json
from datetime import datetime, timedelta, timezone
from typing import Any
from io import BytesIO
import uuid
import boto3
import pytest
from pytest_mock import MockerFixture
from unittest.mock import patch

from app.core.services.ml.pat.bedrock import BedrockPAT
from app.core.services.ml.pat.exceptions import (
    InvalidConfigurationError,
)
from app.infrastructure.ml.pat.models import AnalysisResult
from app.core.exceptions import (
    ResourceNotFoundError,
)

# Helper function to create sample readings
def create_sample_readings(num_readings: int = 10) -> list[dict[str, Any]]:
    """Create sample accelerometer readings."""
    start_time = datetime.now(timezone.utc) - timedelta(hours=1)
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

# --- Helper Functions ---
def create_mock_response(body_content: dict[str, Any]) -> dict[str, Any]:
    """Creates a mock dictionary mimicking Bedrock's response structure."""
    # Encode the body dictionary as JSON bytes
    mock_stream = BytesIO(json.dumps(body_content).encode('utf-8'))
    # Return the BytesIO stream directly, as it has a .read() method
    return {"body": mock_stream}

class TestBedrockPAT:
    """Test suite for the BedrockPAT implementation."""

    def test_initialization(self, mocker: MockerFixture) -> None:
        """Test service initialization with various configurations."""
        # Use a fresh service instance for isolation
        service = BedrockPAT()

        # Test invalid configurations
        # Check empty config first
        with pytest.raises(InvalidConfigurationError, match="Configuration cannot be empty"):
            service.initialize(None) # or {} should also work

        # Check missing bucket name
        with pytest.raises(InvalidConfigurationError, match="S3 bucket name is required"):
            service.initialize({"dynamodb_table_name": "test-table", "kms_key_id": "test-key-id"})

        # Check missing table name
        with pytest.raises(InvalidConfigurationError, match="DynamoDB table name is required"):
            service.initialize({"bucket_name": "test-bucket", "kms_key_id": "test-key-id"})

        # Test with missing KMS key
        with pytest.raises(InvalidConfigurationError, match="KMS key ID is required"):
            service.initialize({
                "bucket_name": "test-bucket",
                "dynamodb_table_name": "test-table"
            })

        # Test with complete configuration
        with patch("boto3.client") as mock_boto:
            valid_config = {"bucket_name": "test-bucket", "dynamodb_table_name": "test-table", "kms_key_id": "test-key-id"}
            service.initialize(valid_config)
            assert service.initialized
            assert service.bucket_name == "test-bucket"
            assert service.dynamodb_table_name == "test-table"
            assert service.kms_key_id == "test-key-id"

    def test_analyze_actigraphy(self, bedrock_pat_service: BedrockPAT, mocker: MockerFixture) -> None:
        """Test successful analysis of actigraphy data."""
        # --- Arrange ---
        # Test data
        patient_id = str(uuid.uuid4())
        readings = create_sample_readings(5)
        start_time = datetime.now(timezone.utc).isoformat()
        end_time = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
        sampling_rate_hz = 1.0

        # --- Mock Configuration --- 
        # 1. Mock the Bedrock response (using the mock set up in the fixture)
        expected_response_json = json.dumps({
            "sleep_metrics": {
                "sleep_efficiency": 0.9, 
                "sleep_duration_hours": 8.0, 
                "wake_after_sleep_onset_minutes": 10.0, 
                "sleep_latency_minutes": 5.0
            }
        })
        mock_response_body_stream = io.BytesIO(expected_response_json.encode('utf-8'))
        mock_invoke_model_response = {
            "body": mock_response_body_stream, 
            "contentType": "application/json" 
        }
        
        # --- DEBUG: Check the runtime object BEFORE patching --- 
        print(f"\nDEBUG: Type of bedrock_pat_service.bedrock_runtime BEFORE patch: {type(bedrock_pat_service.bedrock_runtime)}")
        # --- END DEBUG ---

        # Prepare expected response structure
        bedrock_pat_service.bedrock_runtime.invoke_model.return_value = mock_invoke_model_response

        # Call the method under test
        analysis_result = bedrock_pat_service.analyze_actigraphy(
            patient_id=patient_id,
            readings=readings,
            start_time=start_time,
            end_time=end_time,
            sampling_rate_hz=sampling_rate_hz
        )

        # --- DEBUG: Check mock call count AFTER execution ---
        # --- END DEBUG ---

        # Assertions
        # Assert that invoke_model was called correctly on the mock object
        bedrock_pat_service.bedrock_runtime.invoke_model.assert_called_once()

        # Retrieve the arguments invoke_model was called with
        call_args, call_kwargs = bedrock_pat_service.bedrock_runtime.invoke_model.call_args
        # assert call_args[0] == "test-sleep-model"
        # assert call_kwargs["input_data"] == ...

        # 2. Check the result content (should now use the parsed mock response)
        assert isinstance(analysis_result, AnalysisResult)
        assert analysis_result.analysis_id is not None # Should be generated internally
        assert analysis_result.status == "COMPLETED" # Assuming success path now works
        assert analysis_result.results["sleep_metrics"]["sleep_efficiency"] == 0.9 # Value from mocked response
        # TODO: Update assertion once parsing works correctly
        # assert result.results["sleep_metrics"]["sleep_efficiency"] == mock_bedrock_response_body["results"]["sleep_metrics"]["sleep_efficiency"]

        # Optional: Assert calls to other patched methods (DynamoDB, audit log)
        # bedrock_pat_service.dynamodb_client.put_item.assert_called_once()
        # bedrock_pat_service._record_audit_log.assert_called_once()

    def test_get_embeddings(self, bedrock_pat_service: BedrockPAT, mocker: MockerFixture) -> None:
        """Test generating embeddings with the Bedrock service."""
        # Prepare test data
        patient_id = "test-patient-1"
        readings = create_sample_readings(20)
        start_time = datetime.now(timezone.utc) - timedelta(hours=1)
        end_time = datetime.now(timezone.utc)

        # Mock Bedrock response
        mock_embeddings = [0.1, 0.2, 0.3, 0.4, 0.5]
        mock_response_body = {
            "embeddings": mock_embeddings,
            "model_version": "PAT-1.0"
        }
        mock_response = create_mock_response(mock_response_body)

        bedrock_pat_service.bedrock_runtime = mocker.patch.object(
            bedrock_pat_service, 
            'bedrock_runtime' 
        )
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

    def test_get_analysis_by_id(self, bedrock_pat_service: BedrockPAT, mocker: MockerFixture) -> None:
        """Test retrieving an analysis by ID with the Bedrock service."""
        analysis_id = str(uuid.uuid4())

        # Mock DynamoDB response
        mock_result = {
            "analysis_id": analysis_id,
            "patient_id": "test-patient-1",
            "timestamp": datetime.now(timezone.utc).isoformat(),
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

        bedrock_pat_service.dynamodb_client = mocker.patch.object(
            bedrock_pat_service, 
            'dynamodb_client' 
        )
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

    def test_get_analysis_by_id_not_found(self, bedrock_pat_service: BedrockPAT, mocker: MockerFixture) -> None:
        """Test retrieving a non-existent analysis by ID."""
        analysis_id = str(uuid.uuid4())

        # Mock DynamoDB response (no item found)
        mock_dynamodb_response = {}

        bedrock_pat_service.dynamodb_client = mocker.patch.object(
            bedrock_pat_service, 
            'dynamodb_client' 
        )
        bedrock_pat_service.dynamodb_client.get_item.return_value = mock_dynamodb_response

        # Call the service
        with pytest.raises(ResourceNotFoundError):
            bedrock_pat_service.get_analysis_by_id(analysis_id)

    def test_get_patient_analyses(self, bedrock_pat_service: BedrockPAT, mocker: MockerFixture) -> None:
        """Test retrieving analyses for a patient with the Bedrock service."""
        patient_id = "test-patient-1"

        # Mock DynamoDB response
        analysis_id_1 = str(uuid.uuid4())
        analysis_id_2 = str(uuid.uuid4())

        mock_result_1 = {
            "analysis_id": analysis_id_1,
            "patient_id": patient_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "sleep_metrics": {
                "sleep_efficiency": 0.85
            }
        }

        mock_result_2 = {
            "analysis_id": analysis_id_2,
            "patient_id": patient_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
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
                    "Timestamp": {"S": datetime.now(timezone.utc).isoformat()},
                    "Result": {"S": json.dumps(mock_result_1)}
                },
                {
                    "AnalysisId": {"S": analysis_id_2},
                    "Timestamp": {"S": datetime.now(timezone.utc).isoformat()},
                    "Result": {"S": json.dumps(mock_result_2)}
                }
            ]
        }

        bedrock_pat_service.dynamodb_client = mocker.patch.object(
            bedrock_pat_service, 
            'dynamodb_client' 
        )
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

    def test_get_patient_analyses_not_found(self, bedrock_pat_service: BedrockPAT, mocker: MockerFixture) -> None:
        """Test retrieving analyses for a patient with no results."""
        patient_id = "test-patient-not-found"

        # Mock DynamoDB response (no items found)
        mock_dynamodb_response = {
            "Items": []
        }

        bedrock_pat_service.dynamodb_client = mocker.patch.object(
            bedrock_pat_service, 
            'dynamodb_client' 
        )
        bedrock_pat_service.dynamodb_client.query.return_value = mock_dynamodb_response

        # Call the service
        with pytest.raises(ResourceNotFoundError):
            bedrock_pat_service.get_patient_analyses(
                patient_id=patient_id,
                limit=10,
                offset=0
            )

    def test_integrate_with_digital_twin(self, bedrock_pat_service: BedrockPAT, mocker: MockerFixture) -> None:
        """Test integrating actigraphy analysis with a digital twin with the Bedrock service."""
        # Prepare test data
        patient_id = "test-patient-1"
        profile_id = "test-profile-1"

        actigraphy_analysis = {
            "analysis_id": str(uuid.uuid4()),
            "patient_id": patient_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "sleep_metrics": {
                "sleep_efficiency": 0.85
            }
        }

        # Mock Bedrock response
        mock_response_body = {
            "profile_id": profile_id,
            "patient_id": patient_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
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
        }
        mock_response = create_mock_response(mock_response_body)

        bedrock_pat_service.bedrock_runtime = mocker.patch.object(
            bedrock_pat_service, 
            'bedrock_runtime' 
        )
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

class TestHelperFunctions:
    """Tests for helper functions used within the test suite."""

    def test_create_mock_response_structure(self) -> None:
        """Verify the structure of the mocked response dictionary."""
        body_dict = {"key": "value"}
        response = create_mock_response(body_dict)

        assert isinstance(response, dict)
        assert "body" in response
        assert isinstance(response['body'], io.BytesIO)

    def test_create_mock_response_content(self) -> None:
        """Verify the content of the mocked response body."""
        body_dict = {"key": "value", "number": 123}
        response = create_mock_response(body_dict)

        # Read the content from the BytesIO stream
        response_body_bytes = response['body'].read()
        response_body_dict = json.loads(response_body_bytes.decode('utf-8'))

        assert response_body_dict == body_dict

    def test_create_sample_readings_structure(self) -> None:
        """Verify the structure of sample readings."""
        readings = create_sample_readings(5)

        assert isinstance(readings, list)
        assert len(readings) == 5
        assert isinstance(readings[0], dict)
        assert "timestamp" in readings[0]
        assert "x" in readings[0]
        assert "y" in readings[0]
        assert "z" in readings[0]

    def test_create_sample_readings_content(self) -> None:
        """Verify the content types within sample readings."""
        readings = create_sample_readings(1)

        assert isinstance(readings[0]["timestamp"], str)
        # Attempt to parse the timestamp to ensure it's a valid ISO format
        try:
            datetime.fromisoformat(readings[0]["timestamp"].replace('Z', '+00:00'))
        except ValueError:
            pytest.fail("Timestamp is not in valid ISO format")
        assert isinstance(readings[0]["x"], float)
        assert isinstance(readings[0]["y"], float)
        assert isinstance(readings[0]["z"], float)

# --- Fixtures ---
# Fixture providing a BedrockPAT instance configured for testing
@pytest.fixture
def bedrock_pat_service(mocker: MockerFixture) -> BedrockPAT:
    """Provides an initialized BedrockPAT service with mocked AWS dependencies using boto3 patching."""
    # 1. Create mock AWS client instances (no spec needed with direct boto3 patch)
    mock_bedrock_runtime_client = mocker.MagicMock()
    mock_dynamodb_client = mocker.MagicMock()
    mock_s3_client = mocker.MagicMock()
    mock_bedrock_client = mocker.MagicMock() # For foundation model access if needed
    # mock_session_client = MagicMock() # Add if session service is used

    # Mock boto3.client to return the correct mock based on the service name
    def mock_boto3_client(service_name: str, *args: tuple[Any, ...], **kwargs: dict[str, Any]) -> mocker.MagicMock:
        if service_name == 'bedrock-runtime':
            return mock_bedrock_runtime_client
        elif service_name == 'dynamodb':
            return mock_dynamodb_client
        elif service_name == 's3':
            return mock_s3_client
        elif service_name == 'bedrock':
            return mock_bedrock_client
        # Add handling for 'sts' or others if session_service uses them
        else:
            print(f"WARN: Unmocked boto3.client requested: {service_name}")
            return mocker.MagicMock() # Return default mock

    mocker.patch('boto3.client', side_effect=mock_boto3_client)

    # 3. Create BedrockPAT instance (uses default factory, which uses patched boto3)
    service = BedrockPAT() # No factory injection needed

    # 4. Initialize the service (this uses the patched boto3 via the default factory)
    # Provide a minimal valid configuration for initialization
    service.initialize({
        "bucket_name": "test-bucket", 
        "dynamodb_table_name": "test-table", 
        "kms_key_id": "test-key-id"
    })

    # 5. Assign mocks to attributes that might be checked directly in tests
    # (Though initialize should handle this internally via the factory)
    service.bedrock_runtime = mock_bedrock_runtime_client
    service._dynamodb_service = mock_dynamodb_client # Assuming internal access
    service._s3_service = mock_s3_client           # Assuming internal access

    return service

@pytest.fixture
def valid_actigraphy_data() -> tuple:
    """Provides valid sample data for actigraphy analysis tests."""
    patient_id = f"patient_{uuid.uuid4()}"
    start_time = datetime.now(timezone.utc) - timedelta(hours=1)
    end_time = datetime.now(timezone.utc)
    readings = create_sample_readings(50) # Use helper to generate readings
    sampling_rate_hz = 10.0 # Example sampling rate
    device_info = {"model": "TestDevice", "manufacturer": "TestCorp"}
    return (
        patient_id,
        start_time.isoformat().replace("+00:00", "Z"),
        end_time.isoformat().replace("+00:00", "Z"),
        readings,
        sampling_rate_hz,
        device_info
    )
