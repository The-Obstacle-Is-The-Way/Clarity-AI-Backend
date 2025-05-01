# -*- coding: utf-8 -*-
"""Unit tests for the Bedrock PAT service."""

import io
import json
import uuid
from datetime import datetime, timedelta, timezone, UTC 
from typing import Any
from unittest.mock import patch
from io import BytesIO
import pytest
from pytest_mock import MockerFixture

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

    @pytest.mark.asyncio
    async def test_initialization(self, bedrock_pat_service):
        """Test service initialization with various configurations."""
        service, _ = bedrock_pat_service # Unpack, mocks not needed here

        # Test invalid configurations
        # Test None config
        with pytest.raises(InvalidConfigurationError, match="Configuration cannot be empty"):
            service.initialize(None)

        # Test empty dict config
        with pytest.raises(InvalidConfigurationError, match="Configuration cannot be empty"):
            service.initialize({})

        # Test missing keys (using the new combined error message)
        with pytest.raises(InvalidConfigurationError, match="Missing required configuration keys: bucket_name, kms_key_id"):
            service.initialize({
                "dynamodb_table_name": "test-table", 
                "bedrock_embedding_model_id": "embed-id", 
                "bedrock_analysis_model_id": "analysis-id"
            })

        with pytest.raises(InvalidConfigurationError, match="Missing required configuration keys: dynamodb_table_name"):
            service.initialize({
                "bucket_name": "test-bucket", 
                "kms_key_id": "test-key",
                "bedrock_embedding_model_id": "embed-id", 
                "bedrock_analysis_model_id": "analysis-id"
            })
    
        with pytest.raises(InvalidConfigurationError, match="Missing required configuration keys: bedrock_embedding_model_id"):
            service.initialize({
                "bucket_name": "test-bucket", 
                "dynamodb_table_name": "test-table",
                "kms_key_id": "test-key",
                "bedrock_analysis_model_id": "analysis-id"
            })

        with pytest.raises(InvalidConfigurationError, match="Missing required configuration keys: bedrock_analysis_model_id"):
            service.initialize({
                "bucket_name": "test-bucket", 
                "dynamodb_table_name": "test-table",
                "kms_key_id": "test-key",
                "bedrock_embedding_model_id": "embed-id"
            })
        
        # Test with complete configuration
        valid_config = {
            "bucket_name": "test-bucket", # Correct key
            "dynamodb_table_name": "test-table", 
            "kms_key_id": "test-key-id", # Correct key
            "bedrock_embedding_model_id": "amazon.titan-embed-text-v1", 
            "bedrock_analysis_model_id": "anthropic.claude-v2"
        }
        service.initialize(valid_config)
        assert service.initialized
        # Use attribute names as defined in initialize
        assert service._s3_bucket == "test-bucket"
        assert service._dynamodb_table == "test-table"
        assert service._kms_key_id == "test-key-id"
        assert service._embedding_model_id == "amazon.titan-embed-text-v1"
        assert service._analysis_model_id == "anthropic.claude-v2"

    @pytest.mark.asyncio
    async def test_analyze_actigraphy(self, bedrock_pat_service, mocker: MockerFixture) -> None:
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
        service, mocks = bedrock_pat_service
        mocks["bedrock"].invoke_model.return_value = mock_invoke_model_response

        # Call the method under test
        analysis_result = await service.analyze_actigraphy(
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
        mocks["bedrock"].invoke_model.assert_called_once()

        # Retrieve the arguments invoke_model was called with
        call_args, call_kwargs = mocks["bedrock"].invoke_model.call_args
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

    @pytest.mark.asyncio
    async def test_get_embeddings(self, bedrock_pat_service, mocker: MockerFixture) -> None:
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

        service, mocks = bedrock_pat_service
        mocks["bedrock"].invoke_model.return_value = mock_response

        # Call the service
        result = await service.get_actigraphy_embeddings(
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
        mocks["bedrock"].invoke_model.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_analysis_by_id(self, bedrock_pat_service, mocker: MockerFixture) -> None:
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

        service, mocks = bedrock_pat_service
        mocks["dynamodb"].get_item.return_value = mock_dynamodb_response

        # Call the service
        result = await service.get_analysis_by_id(analysis_id)

        # Verify results
        assert isinstance(result, dict)
        assert result["analysis_id"] == analysis_id
        assert "sleep_metrics" in result
        assert result["sleep_metrics"]["sleep_efficiency"] == 0.85

        # Verify DynamoDB was called correctly
        mocks["dynamodb"].get_item.assert_called_once()
        args, kwargs = mocks["dynamodb"].get_item.call_args
        assert kwargs["TableName"] == "mock-test-table"
        assert kwargs["Key"]["AnalysisId"]["S"] == analysis_id

    @pytest.mark.asyncio
    async def test_get_analysis_by_id_not_found(self, bedrock_pat_service, mocker: MockerFixture) -> None:
        """Test retrieving a non-existent analysis by ID."""
        analysis_id = str(uuid.uuid4())

        # Mock DynamoDB response (no item found)
        mock_dynamodb_response = {}

        service, mocks = bedrock_pat_service
        mocks["dynamodb"].get_item.return_value = mock_dynamodb_response

        # Call the service
        with pytest.raises(ResourceNotFoundError):
            await service.get_analysis_by_id(analysis_id)

    @pytest.mark.asyncio
    async def test_get_patient_analyses(self, bedrock_pat_service, mocker: MockerFixture) -> None:
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

        service, mocks = bedrock_pat_service
        mocks["dynamodb"].query.return_value = mock_dynamodb_response

        # Call the service
        result = await service.get_patient_analyses(
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
        mocks["dynamodb"].query.assert_called_once()
        args, kwargs = mocks["dynamodb"].query.call_args
        assert kwargs["TableName"] == "mock-test-table"
        assert kwargs["IndexName"] == "PatientIdIndex"

    @pytest.mark.asyncio
    async def test_get_patient_analyses_not_found(self, bedrock_pat_service, mocker: MockerFixture) -> None:
        """Test retrieving analyses for a patient with no results."""
        patient_id = "test-patient-not-found"

        # Mock DynamoDB response (no items found)
        mock_dynamodb_response = {
            "Items": []
        }

        service, mocks = bedrock_pat_service
        mocks["dynamodb"].query.return_value = mock_dynamodb_response

        # Call the service
        with pytest.raises(ResourceNotFoundError):
            await service.get_patient_analyses(
                patient_id=patient_id,
                limit=10,
                offset=0
            )

    @pytest.mark.asyncio
    async def test_integrate_with_digital_twin(self, bedrock_pat_service, mocker: MockerFixture) -> None:
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

        service, mocks = bedrock_pat_service
        mocks["bedrock"].invoke_model.return_value = mock_response

        # Call the service
        result = await service.integrate_with_digital_twin(
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
        mocks["bedrock"].invoke_model.assert_called_once()

# --- Fixtures ---
# Fixture providing a BedrockPAT instance configured for testing
@pytest.fixture
def bedrock_pat_service():
    """Provides a BedrockPAT service instance with mocked AWS dependencies for unit testing."""
    # Create mocks for the AWS service interfaces
    mock_s3_client = MagicMock(spec=S3ServiceInterface)
    mock_dynamodb_client = MagicMock(spec=DynamoDBServiceInterface)
    # Ensure async methods return awaitables (AsyncMock)
    mock_dynamodb_client.get_item = AsyncMock()
    mock_dynamodb_client.put_item = AsyncMock()
    mock_dynamodb_client.query = AsyncMock()

    mock_bedrock_runtime_client = MagicMock(spec=BedrockRuntimeServiceInterface)
    mock_bedrock_runtime_client.invoke_model = AsyncMock()

    # Create the BedrockPAT instance (without the factory)
    service = BedrockPAT()

    # Manually inject the mocks into the service instance's private attributes
    service._s3_client = mock_s3_client
    service._dynamodb_client = mock_dynamodb_client
    service._bedrock_runtime = mock_bedrock_runtime_client

    # Set default table name required by some internal methods, tests can override if needed
    service._dynamodb_table = "mock-test-table" 
    service._s3_bucket = "mock-test-bucket"
    service._kms_key_id = "mock-kms-key"
    service._bedrock_embedding_model_id = "mock-embed-model"
    service._bedrock_analysis_model_id = "mock-analysis-model"

    # Yield the service and the mocks for tests to use
    mocks = {
        "s3": mock_s3_client,
        "dynamodb": mock_dynamodb_client,
        "bedrock": mock_bedrock_runtime_client
    }
    yield service, mocks
