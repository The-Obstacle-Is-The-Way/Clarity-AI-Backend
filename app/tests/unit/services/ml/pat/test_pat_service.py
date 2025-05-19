"""Unit tests for the Bedrock PAT service."""

import json
import random
import uuid
from datetime import datetime, timedelta, timezone
from io import BytesIO
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from freezegun import freeze_time
from pytest_mock import MockerFixture

from app.core.interfaces.aws_service_interface import (
    AWSServiceFactory,
    BedrockRuntimeServiceInterface,
    DynamoDBServiceInterface,
    S3ServiceInterface,
)
from app.core.services.ml.pat.bedrock import BedrockPAT

# Corrected import for PAT-specific exceptions
from app.core.services.ml.pat.exceptions import ResourceNotFoundError

# Corrected import for DigitalTwin from domain layer
from app.domain.entities.digital_twin import DigitalTwin
from app.infrastructure.ml.pat.models import (
    AccelerometerReading,
    AnalysisResult,
    AnalysisTypeEnum,
)


# Helper function to create sample readings
def create_sample_readings(num_readings: int = 10) -> list[AccelerometerReading]:
    """Generate sample accelerometer readings for testing."""
    readings = []
    start_time = datetime.now(timezone.utc) - timedelta(minutes=num_readings)
    for i in range(num_readings):
        timestamp = start_time + timedelta(minutes=i)
        reading_data = AccelerometerReading(
            timestamp=timestamp,
            x=random.uniform(-2, 2),
            y=random.uniform(-2, 2),
            z=random.uniform(-2, 2),
        )
        readings.append(reading_data)
    return readings


# --- Helper Functions ---
def create_mock_response(body_content: dict[str, Any]) -> dict[str, Any]:
    """Creates a mock dictionary mimicking Bedrock's response structure."""
    # Encode the body dictionary as JSON bytes
    mock_stream = BytesIO(json.dumps(body_content).encode("utf-8"))
    # Return the BytesIO stream directly, as it has a .read() method
    return {"body": mock_stream}


class TestBedrockPAT:
    """Test suite for the BedrockPAT implementation."""

    @pytest.mark.asyncio
    async def test_initialization(self, bedrock_pat_service: BedrockPAT) -> None:
        """Test service initialization."""
        service = bedrock_pat_service
        assert service.initialized
        # Assert against internal attribute names used in initialize()
        assert service._s3_bucket == "test-bucket"
        assert service._dynamodb_table == "test-table"

    @pytest.mark.asyncio
    async def test_analyze_actigraphy(self, bedrock_pat_service: BedrockPAT, mocker: MockerFixture):
        """Test analyzing actigraphy data."""
        service = bedrock_pat_service
        patient_id = f"patient-{uuid.uuid4()}"
        # Generate realistic-looking readings
        readings = [
            {
                "timestamp": (datetime.now(timezone.utc) - timedelta(minutes=i)).isoformat(),
                "x": random.uniform(-2, 2),
                "y": random.uniform(-2, 2),
                "z": random.uniform(-2, 2),
            }
            for i in range(60)  # Simulate 1 minute of data
        ]
        start_time_iso = (datetime.now(timezone.utc) - timedelta(minutes=60)).isoformat()
        end_time_iso = datetime.now(timezone.utc).isoformat()
        sampling_rate = 1.0  # Hz

        # Expected result structure based on AnalysisResult
        expected_analysis_id_uuid = uuid.uuid4()
        expected_analysis_id = str(expected_analysis_id_uuid)
        # Use a fixed timestamp for predictability
        fixed_timestamp = datetime.now(timezone.utc)
        # Mock Bedrock response (ensure structure matches what service expects)
        analysis_data = {
            "analysis_type": "sleep_quality",
            "model_version": "test-sleep-model-v1",
            "confidence_score": 0.95,
            "metrics": {
                "sleep_efficiency": 0.85,
                "total_sleep_time": 420,
                "efficiency": 0.85,  # Fixed duplicate key
                "duration": 420,
                "latency": 15,
                "rem_percentage": 0.20,
                "deep_percentage": 0.15,
            },
            "insights": ["Good sleep quality detected"],  # Use List[str]
            # Include other fields AnalysisResult might expect
            "warnings": [],
        }
        # Configure the MOCK read method to return the test-specific data
        mock_stream = AsyncMock()
        # Return the *parsed* dictionary directly for this test's purpose
        mock_stream.read = AsyncMock(return_value=analysis_data)
        # Mock invoke_model on the runtime instance within the service's mocks
        service.mocks["bedrock"].invoke_model = AsyncMock(return_value={"body": mock_stream})
        # Re-configure mocks on the specific instance if needed after factory call
        service.mocks["dynamodb"].put_item = AsyncMock(return_value={})

        # Use mocker to patch uuid.uuid4 if needed for predictable ID
        mocker.patch("uuid.uuid4", return_value=expected_analysis_id_uuid)

        # Use freezegun to control the timestamp within the service call
        with freeze_time(fixed_timestamp):
            # Call the service method with *all* required arguments
            analysis_result = await service.analyze_actigraphy(
                patient_id=patient_id,
                readings=readings,
                start_time=start_time_iso,  # ADDED
                end_time=end_time_iso,  # ADDED
                sampling_rate_hz=sampling_rate,  # ADDED
            )

        # Assertions
        assert isinstance(analysis_result, AnalysisResult)
        assert analysis_result.analysis_id == expected_analysis_id
        assert analysis_result.patient_id == patient_id
        # Compare ISO strings or datetime objects consistently
        assert analysis_result.timestamp == fixed_timestamp  # Now comparison should work
        assert analysis_result.analysis_type == "sleep_quality"
        assert analysis_result.model_version == "test-sleep-model-v1"
        assert analysis_result.confidence_score == 0.95
        assert analysis_result.metrics == {
            "sleep_efficiency": 0.85,
            "total_sleep_time": 420,
            "efficiency": 0.85,
            "duration": 420,
            "latency": 15,
            "rem_percentage": 0.20,
            "deep_percentage": 0.15,
        }
        assert analysis_result.insights == ["Good sleep quality detected"]
        assert analysis_result.warnings == []

        # Verify mocks were called correctly
        service.mocks["bedrock"].invoke_model.assert_called_once()
        service.mocks["dynamodb"].put_item.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_embeddings(
        self, bedrock_pat_service: BedrockPAT, mocker: MockerFixture
    ) -> None:
        """Test generating embeddings with the Bedrock service."""
        service = bedrock_pat_service
        patient_id = "test-patient-embed-456"
        readings_models = create_sample_readings(5)
        readings_data = [r.model_dump() for r in readings_models]

        # Configure mock response for embeddings (access mocks via service.mocks)
        mock_embeddings = [random.random() for _ in range(768)]  # nosec B311
        mock_bedrock_response = {
            "embedding": mock_embeddings,
            "inputTextTokenCount": 100,
            "analysis_id": "mock_analysis_id",
            "patient_id": patient_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "analysis_type": "sleep_quality",
            "model_version": "titan-0.1",
            "confidence_score": 0.95,
            "metrics": {"sleep_efficiency": 0.85},
            "insights": [{"text": "Good sleep quality detected"}],
        }
        mock_stream = AsyncMock()
        mock_stream.read = AsyncMock(return_value=json.dumps(mock_bedrock_response).encode("utf-8"))
        service.mocks["bedrock"].invoke_model = AsyncMock(return_value={"body": mock_stream})

        # Call the service method
        result = await service.get_actigraphy_embeddings(
            patient_id=patient_id,
            data=readings_data,
        )

        # Assertions
        assert isinstance(result, list)  # Check if it's a list
        assert len(result) > 0  # Check if the list is not empty (using placeholder return)
        assert all(isinstance(item, float) for item in result)  # Check if all items are floats

        # Verify interaction on the client mock
        service.mocks["bedrock"].invoke_model.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_analysis_by_id(
        self, bedrock_pat_service: BedrockPAT, mocker: MockerFixture
    ) -> None:
        """Test retrieving a specific analysis by its ID successfully."""
        service = bedrock_pat_service
        analysis_id = "existing-analysis-abc"
        patient_id_hash = service._hash_identifier("patient-123")
        timestamp = datetime.now(timezone.utc)
        timestamp_str = timestamp.isoformat()

        # Mock data for the specific analysis item (flat structure)
        mock_dynamodb_item = {
            "AnalysisId": {"S": analysis_id},
            "PatientIdHash": {"S": patient_id_hash},
            "Timestamp": {"S": timestamp_str},
            "AnalysisType": {"S": AnalysisTypeEnum.SLEEP_QUALITY.value},
            "ModelVersion": {"S": "titan-0.1"},
            "ConfidenceScore": {"N": "0.85"},
            "Metrics": {
                "M": {
                    "total_sleep_time": {"N": "8.2"},
                    "sleep_efficiency": {"N": "0.91"},
                    "efficiency": {"N": "0.91"},
                    "duration": {"N": "8.2"},
                    "latency": {"N": "10"},
                    "rem_percentage": {"N": "0.22"},
                    "deep_percentage": {"N": "0.18"},
                }
            },
            "Insights": {"L": [{"S": "Consistent sleep pattern detected."}]},
        }

        # Configure the mock DynamoDB client's get_item response
        service.dynamodb_client.get_item = AsyncMock(return_value={"Item": mock_dynamodb_item})

        # Call the service method
        retrieved_analysis = await service.get_analysis_by_id(analysis_id)

        # Assertions
        assert retrieved_analysis is not None
        assert retrieved_analysis.analysis_id == analysis_id  # Check if parser added this correctly
        assert retrieved_analysis.patient_id == patient_id_hash
        assert retrieved_analysis.timestamp == timestamp  # Compare datetime objects
        assert retrieved_analysis.analysis_type == AnalysisTypeEnum.SLEEP_QUALITY
        assert retrieved_analysis.model_version == "titan-0.1"
        assert retrieved_analysis.confidence_score == 0.85
        assert retrieved_analysis.metrics == {
            "total_sleep_time": 8.2,
            "sleep_efficiency": 0.91,
            "efficiency": 0.91,
            "duration": 8.2,
            "latency": 10,
            "rem_percentage": 0.22,
            "deep_percentage": 0.18,
        }
        assert retrieved_analysis.insights == ["Consistent sleep pattern detected."]

        # Verify interaction
        service.dynamodb_client.get_item.assert_called_once_with(
            TableName=service.table_name, Key={"AnalysisId": {"S": analysis_id}}
        )

    @pytest.mark.asyncio
    async def test_get_analysis_by_id_not_found(
        self, bedrock_pat_service: BedrockPAT, mocker: MockerFixture
    ) -> None:
        """Test retrieving a specific analysis by its ID when it does not exist."""
        service = bedrock_pat_service
        analysis_id = "non-existent-analysis-xyz"

        # Configure the mock client's get_item to return an empty dict (item not found)
        service.dynamodb_client.get_item = AsyncMock(return_value={})

        # Assert that the correct exception is raised
        with pytest.raises(ResourceNotFoundError) as excinfo:
            await service.get_analysis_by_id(analysis_id)

        assert analysis_id in str(excinfo.value)
        # Verify interaction on the client mock
        service.dynamodb_client.get_item.assert_awaited_once_with(
            TableName=service.table_name, Key={"AnalysisId": {"S": analysis_id}}
        )

    @pytest.mark.asyncio
    async def test_get_patient_analyses(
        self, bedrock_pat_service: BedrockPAT, mocker: MockerFixture
    ):
        """Test retrieving analysis results for a specific patient."""
        service = bedrock_pat_service
        patient_id = f"patient-{uuid.uuid4()}"
        patient_hash = service._hash_identifier(patient_id)
        limit = 2
        timestamp_now = datetime.now(timezone.utc)

        # --- Mocking Setup ---
        # 1. Mock `query` to return summary items
        mock_summary_items = [
            {
                "analysis_id": f"analysis-{i+1}",
                "patient_id_hash": patient_hash,
                "timestamp": (timestamp_now - timedelta(days=i)).isoformat(),
                "analysis_type": "sleep_quality",
                "model_version": f"model-v{i+1}",
                # Note: 'data' is NOT included in summary query results typically
            }
            for i in range(limit)
        ]
        service.mocks["dynamodb"].query = AsyncMock(
            return_value={"Items": mock_summary_items, "LastEvaluatedKey": None}
        )

        # 2. Define full data for `get_item` calls
        mock_full_item_1 = {
            "analysis_id": "analysis-1",
            "patient_id_hash": patient_hash,
            "timestamp": (timestamp_now - timedelta(days=0)).isoformat(),
            "analysis_type": "sleep_quality",
            "model_version": "model-v1",
            "data": json.dumps(
                {  # Store the actual data as a JSON string
                    "confidence_score": 0.91,
                    "metrics": {"efficiency": 0.81, "duration": 410},
                    "insights": ["Insight 1"],
                    "warnings": [],
                }
            ),
        }
        mock_full_item_2 = {
            "analysis_id": "analysis-2",
            "patient_id_hash": patient_hash,
            "timestamp": (timestamp_now - timedelta(days=1)).isoformat(),
            "analysis_type": "sleep_quality",
            "model_version": "model-v2",
            "data": json.dumps(
                {
                    "confidence_score": 0.92,
                    "metrics": {"efficiency": 0.82, "duration": 420},
                    "insights": ["Insight 2"],
                    "warnings": [],
                }
            ),
        }

        # 3. Create a side effect for `get_item`
        async def get_item_side_effect(*args, **kwargs):
            key = kwargs.get("Key", {})
            # Corrected: DynamoDB keys are typically CamelCase
            analysis_id = key.get("AnalysisId")
            if analysis_id == "analysis-1":
                return {"Item": mock_full_item_1}
            elif analysis_id == "analysis-2":
                return {"Item": mock_full_item_2}
            else:
                # Return empty or raise error for unexpected calls
                return {"Item": None}  # Simulate item not found

        # 4. Patch `get_item` within this test to use the side effect
        service.mocks["dynamodb"].get_item = AsyncMock(side_effect=get_item_side_effect)
        # --- End Mocking Setup ---

        # Call the service method
        result = await service.get_patient_analyses(patient_id=patient_id, limit=limit)

        # Assertions
        assert isinstance(result, list)
        assert len(result) == limit  # Check if we got the expected number back
        # Check content (assuming order is preserved or sort if needed)
        assert result[0].analysis_id == "analysis-1"
        assert result[0].confidence_score == 0.91
        assert result[1].analysis_id == "analysis-2"
        assert result[1].confidence_score == 0.92

        # Verify mocks
        service.mocks["dynamodb"].query.assert_called_once()
        # Verify get_item was called for each summary item
        assert service.mocks["dynamodb"].get_item.call_count == limit
        # Verify calls with CamelCase keys as expected by Boto3 mock
        service.mocks["dynamodb"].get_item.assert_any_call(
            Key={"AnalysisId": "analysis-1", "PatientIdHash": patient_hash}
        )
        service.mocks["dynamodb"].get_item.assert_any_call(
            Key={"AnalysisId": "analysis-2", "PatientIdHash": patient_hash}
        )

    @pytest.mark.asyncio
    async def test_get_patient_analyses_not_found(
        self, bedrock_pat_service: BedrockPAT, mocker: MockerFixture
    ):
        """Test retrieving analysis results for a patient with no results."""
        service = bedrock_pat_service
        patient_id = "patient-without-analyses-222"
        patient_hash = service._hash_identifier(patient_id)  # Get expected hash for message

        # Mock DynamoDB query response to return no items
        # Using direct client access since it's set in the fixture
        service.mocks["dynamodb"].query = AsyncMock(return_value={"Items": [], "Count": 0})

        # Mock get_item as well, although it shouldn't be called
        service.mocks["dynamodb"].get_item = AsyncMock()

        # Expect ResourceNotFoundError when no items are returned by the query
        with pytest.raises(ResourceNotFoundError) as exc_info:
            await service.get_patient_analyses(patient_id=patient_id)

        # Optionally, check the exception message
        assert f"No analyses found for patient {patient_hash}" in str(exc_info.value)

        # Verify interaction
        service.mocks["dynamodb"].query.assert_called_once()
        # get_item should not be called if query returns no items
        service.mocks["dynamodb"].get_item.assert_not_called()

    @pytest.mark.asyncio
    async def test_integrate_with_digital_twin(
        self, bedrock_pat_service: BedrockPAT, mocker: MockerFixture
    ) -> None:
        """Test integrating PAT analysis results with the digital twin service."""
        service = bedrock_pat_service
        patient_id_uuid = uuid.uuid4()  # Generate a valid UUID
        patient_id = str(patient_id_uuid)  # Use its string representation
        analysis_id = "analysis-for-integration-xyz"
        timestamp_now_iso = datetime.now(timezone.utc).isoformat()

        # 1. Create the AnalysisResult object expected by the method
        analysis_result_data = {
            "analysis_id": analysis_id,
            "patient_id": patient_id,  # Use the generated UUID string
            "timestamp": timestamp_now_iso,  # Use ISO string as Pydantic can parse it
            "analysis_type": "sleep_quality",
            "model_version": "claude-v1",
            "confidence_score": 0.88,
            "metrics": {
                "sleep_duration": 8.5,
                "sleep_efficiency": 0.85,
                "efficiency": 0.85,
                "duration": 8.5 * 60,
                "latency": 20,
                "rem_percentage": 0.18,
                "deep_percentage": 0.22,
            },
            "insights": ["Good sleep quality detected"],  # Changed to List[str]
            "warnings": ["Slightly high sleep latency."]  # Added warnings
            # Removed raw_results as it's not in the base AnalysisResult model definition
            # raw_results: {'raw': 'data'}
        }
        mock_analysis_result = AnalysisResult(**analysis_result_data)

        # 2. Create a mock DigitalTwin object or use None
        # For simplicity, let's use None for now. We might need a proper mock later.
        mock_digital_twin_profile = None

        # Mock DynamoDB item data using DynamoDB types (still needed if service fetches it)
        mock_analysis_data_dynamodb = {
            "AnalysisId": {"S": analysis_id},
            "PatientIdHash": {
                "S": service._hash_identifier(patient_id)
            },  # Hash the generated UUID string
            "Timestamp": {"S": timestamp_now_iso},
            "AnalysisType": {"S": "sleep_quality"},
            "ModelVersion": {"S": "claude-v1"},
            "ConfidenceScore": {"N": "0.88"},
            "Metrics": {
                "M": {
                    "sleep_duration": {"N": "8.5"},
                    "sleep_efficiency": {"N": "0.85"},
                    "efficiency": {"N": "0.85"},
                    "duration": {"N": "8.5"},
                    "latency": {"N": "20"},
                    "rem_percentage": {"N": "0.18"},
                    "deep_percentage": {"N": "0.22"},
                }
            },
            "Insights": {"L": [{"S": "Good sleep quality detected"}]},  # Changed to List[String]
            "Warnings": {"L": [{"S": "Slightly high sleep latency."}]},  # Added warnings
        }
        # Configure get_item mock on the client (might still be needed by internal logic)
        service.dynamodb_client.get_item = AsyncMock(
            return_value={"Item": mock_analysis_data_dynamodb}
        )

        # Configure invoke_model mock for integration summary
        mock_integration_summary = "Integrated sleep patterns show moderate consistency."
        mock_bedrock_response = {"results": [{"outputText": mock_integration_summary}]}
        mock_stream = MagicMock()
        mock_stream.read = AsyncMock(return_value=json.dumps(mock_bedrock_response).encode("utf-8"))
        service.mocks["bedrock"].invoke_model = AsyncMock(return_value={"body": mock_stream})

        # Call the service method with the correct arguments and types
        result = await service.integrate_with_digital_twin(
            patient_id=patient_id,  # Pass the generated UUID string
            analysis_result=mock_analysis_result,  # Pass the AnalysisResult object
            twin_profile=mock_digital_twin_profile  # Pass the DigitalTwin object or None
            # Removed analysis_id and integration_types
        )

        # Assertions (adjust based on expected return type DigitalTwin)
        assert isinstance(result, DigitalTwin)  # Expecting a DigitalTwin object back
        # Add more specific assertions about the content of the returned DigitalTwin
        # For example, check if insights were added or profile was updated.
        # assert mock_integration_summary in result.integration_summary # Example
        assert result.integration_summary == mock_integration_summary

        # Verify mocks were called correctly (client for dynamodb might not be called now)
        # service.dynamodb_client.get_item.assert_called_once_with(...) # May not be called
        service.mocks["bedrock"].invoke_model.assert_called_once()  # Bedrock should be called


# --- Fixtures ---
# Fixture providing a factory function for BedrockPAT instance
@pytest_asyncio.fixture
@freeze_time("2025-05-01 09:40:00")
async def bedrock_pat_service() -> BedrockPAT:
    """Fixture providing a BedrockPAT service instance with mocked dependencies."""

    # Mock AWS service interfaces
    mock_s3 = MagicMock(spec=S3ServiceInterface)
    mock_dynamodb = MagicMock(spec=DynamoDBServiceInterface)
    mock_bedrock_runtime = MagicMock(spec=BedrockRuntimeServiceInterface)

    # Configure DynamoDB mocks to be async and return awaitable defaults
    mock_dynamodb.get_item = AsyncMock(
        return_value={"Item": {"analysis_id": "default-id", "data": "{}"}}
    )  # Default mock
    mock_dynamodb.put_item = AsyncMock(return_value=None)
    mock_dynamodb.query = AsyncMock(
        return_value={"Items": [], "LastEvaluatedKey": None}
    )  # Default mock

    # Configure Bedrock mock correctly (Default mock)
    mock_bedrock_response = {
        "results": [{"metric": "value"}],  # Keep example structure
        # "analysis_id": "mock_analysis_id", # Let the service generate this
        # "patient_id": "patient_123", # Let the service pass this
        # "timestamp": datetime.now(timezone.utc).isoformat(), # Let the service generate this
        "analysis_type": "sleep_quality",  # Use a valid enum value
        "model_version": "titan-custom-v1.0",  # Provide a valid model version
        "confidence_score": 0.92,  # Provide a valid score
        "metrics": {
            "sleep_efficiency": 0.88,
            "total_sleep_time": 450,
            "efficiency": 0.88,
            "duration": 450,
            "latency": 15,
            "rem_percentage": 0.20,
            "deep_percentage": 0.15,
        },
        "insights": [
            "Generally good sleep pattern detected.",
            "Slightly elevated WASO.",
        ],  # Use List[str]
        "warnings": [],  # Added warnings
    }
    mock_stream = AsyncMock()
    # Configure read() to return the PARSED DICT directly for this test
    mock_stream.read = AsyncMock(return_value=mock_bedrock_response)

    # Mock the overall invoke_model response structure
    mock_bedrock_runtime.invoke_model = AsyncMock(return_value={"body": mock_stream})

    # Create a mock factory that returns these mocks
    mock_factory = MagicMock(spec=AWSServiceFactory)
    mock_factory.get_s3_service.return_value = mock_s3
    mock_factory.get_dynamodb_service.return_value = mock_dynamodb
    mock_factory.get_bedrock_runtime_service.return_value = mock_bedrock_runtime

    # Instantiate the service with the mock factory
    service_instance = BedrockPAT(aws_service_factory=mock_factory)

    # Set the mock clients directly (optional, but mirrors original logic)
    service_instance.s3_client = mock_s3
    service_instance.dynamodb_client = mock_dynamodb
    service_instance.bedrock_runtime = mock_bedrock_runtime

    # Initialize the service with minimal config
    await service_instance.initialize(
        config={
            "bucket_name": "test-bucket",  # Await the async initialize
            "dynamodb_table_name": "test-table",
            "kms_key_id": "test-key-id",
            "bedrock_embedding_model_id": "test-embed-model",
            "bedrock_analysis_model_id": "test-analysis-model",
        }
    )

    # Attach mocks to service instance
    mocks = {"s3": mock_s3, "dynamodb": mock_dynamodb, "bedrock": mock_bedrock_runtime}
    service_instance.mocks = mocks
    return service_instance  # Return the fully configured instance
