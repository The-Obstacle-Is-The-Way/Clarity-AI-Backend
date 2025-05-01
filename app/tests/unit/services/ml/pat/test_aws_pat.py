"""
Unit tests for AWS PAT service implementation.

This module contains tests for the AWS implementation of the PAT service.
All AWS services are mocked to avoid making actual API calls.
"""

import pytest
import sys
from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError
from pytest_mock import mocker

# Application-specific imports
from app.core.services.ml.pat.aws import AWSPATService
from app.core.services.ml.pat.exceptions import InitializationError, ResourceNotFoundError

# Constants for testing
TEST_REGION = "us-east-1"


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


@pytest.fixture(scope="function", autouse=True)
def mock_boto3(mocker, request):
    """Autouse fixture to mock boto3 clients and resources for all tests."""

    # --- Mock boto3.client to return specific mocks per service --- 
    mock_s3_instance = MagicMock()
    mock_s3_instance.list_buckets.return_value = {"Buckets": [{"Name": "test-pat-bucket"}]}
    # Add other S3 mocks as needed...

    mock_sagemaker_instance = MagicMock()
    # Add SageMaker mocks as needed...

    mock_comprehend_instance = MagicMock()
    # Add Comprehend Medical mocks as needed...

    # Central mock for boto3.client
    mock_client = mocker.patch("boto3.client", autospec=True)

    # Side effect function to return the correct mock based on service name
    def client_side_effect(service_name, *args, **kwargs):
        if service_name == 's3':
            return mock_s3_instance
        elif service_name == 'sagemaker-runtime':
            return mock_sagemaker_instance
        elif service_name == 'comprehendmedical':
            return mock_comprehend_instance
        # Return a default mock if service name is unexpected
        return MagicMock()

    mock_client.side_effect = client_side_effect

    yield # Allow tests to run with mocks


@pytest.fixture
def mock_dynamodb_resource(mocker, request):
    """Fixture to create and configure a mock boto3.resource('dynamodb')."""
    sys.stderr.write(f"\nDEBUG: Fixture - mock_dynamodb_resource called (Fixture ID: {id(mocker)})\n")
    sys.stderr.flush()

    mock_table = MagicMock(name="MockDynamoDBTable")
    mock_resource = MagicMock(name="MockDynamoDBResource")

    # Default behavior: Simulate successful load
    mock_table.load.return_value = None
    sys.stderr.write(f"\nDEBUG: Fixture: Default mock_table.load (ID: {id(mock_table.load)}) configured for success.\n")

    # Check if the 'simulate_load_failure' marker is present
    if hasattr(request, "param") and request.param == "simulate_load_failure":
        # Simulate ClientError on table.load()
        error_response = {'Error': {'Code': 'ResourceNotFoundException', 'Message': 'Table not found'}}
        operation_name = 'DescribeTable'
        mock_table.load.side_effect = ClientError(error_response, operation_name)
        sys.stderr.write(f"\nDEBUG: Fixture: mock_table.load (ID: {id(mock_table.load)}) configured to raise ClientError.\n")

    # Configure the mock resource's Table method to return the mock table
    mock_resource.Table.return_value = mock_table
    sys.stderr.write(f"\nDEBUG: Fixture: Configured mock_resource.Table (ID: {id(mock_resource.Table)}) to return mock_table (ID: {id(mock_table)})\n")
    sys.stderr.flush()

    return mock_resource  # Return the configured mock resource


@pytest.fixture
def aws_pat_service(mock_dynamodb_resource, aws_config):
    """Fixture for AWS PAT service. Relies on autouse mock_boto3 for patching."""
    service = AWSPATService()

    # Initialize the service. The autouse mock_boto3 fixture ensures that
    # calls to boto3.client/resource within initialize() get the mocks.
    service.initialize(config=aws_config)
    yield service


@pytest.mark.parametrize("mock_dynamodb_resource", ["simulate_load_failure"], indirect=True)
@patch('app.core.services.ml.pat.aws.boto3') # Patch the whole boto3 module in aws.py
def test_initialization_failure(
    self, 
    mock_boto3_module, # Mock for the 'boto3' module itself
    aws_config, 
    mock_dynamodb_resource # Result from the fixture (via indirect=True)
):
    """Test initialization failure when a DynamoDB table load fails."""
    sys.stderr.write(f"\nDEBUG: TEST - Entered test_initialization_failure. mock_boto3_module ID: {id(mock_boto3_module)}, fixture mock_resource ID: {id(mock_dynamodb_resource)}\n")
    
    # Configure the mocked module's 'resource' attribute to return the fixture's mock
    mock_boto3_module.resource.return_value = mock_dynamodb_resource
    sys.stderr.write(f"\nDEBUG: TEST - Configured mock_boto3_module.resource.return_value = mock_dynamodb_resource\n")
    sys.stderr.flush()

    service = AWSPATService() # Instantiate directly

    sys.stderr.write(f"\nDEBUG: TEST - Calling service.initialize() inside pytest.raises()\n")
    sys.stderr.flush()
    with pytest.raises(InitializationError) as excinfo:
        service.initialize(config=aws_config) # Call initialize here

    sys.stderr.write(f"\nDEBUG: TEST - Exception caught: {excinfo.value}\n")
    sys.stderr.write(f"\nDEBUG: TEST - Exception type: {type(excinfo.value)}\n")
    sys.stderr.flush()

    # Check that the specific error message from _verify_resources is present
    expected_error_part = f"Resource verification failed for table '{aws_config['analyses_table']}'"
    sys.stderr.write(f"\nDEBUG: TEST - Asserting '{expected_error_part}' in '{str(excinfo.value)}'\n")
    sys.stderr.flush()
    assert expected_error_part in str(excinfo.value)

    # Verify that the mock resource's Table method was called
    mock_dynamodb_resource.Table.assert_called_once_with(aws_config['analyses_table'])
    # Verify that the mock table's load method was called
    mock_table = mock_dynamodb_resource.Table.return_value
    mock_table.load.assert_called_once()


def test_sanitize_phi(mocker):
    """Test PHI sanitization logic by manually instantiating after patching boto3.client."""
    text = "Patient is John Doe, lives at 123 Main St."

    mock_comprehend_medical = Mock(spec=["detect_phi"])
    mock_response_dict = {
        "Entities": [
            {"Type": "NAME", "BeginOffset": 11, "EndOffset": 15, "Score": 0.99},
            {"Type": "ADDRESS", "BeginOffset": 28, "EndOffset": 38, "Score": 0.95},
        ]
    }
    mock_comprehend_medical.configure_mock(**{"detect_phi.return_value": mock_response_dict})

    service_instance = AWSPATService()

    dummy_config = {
        "aws_region": "us-east-1",
        "endpoint_name": "test-pat-endpoint",
        "bucket_name": "test-pat-bucket",
        "analyses_table": "test-pat-analyses",
        "embeddings_table": "test-pat-embeddings",
        "integrations_table": "test-pat-integrations",
    }
    service_instance.initialize(
        config=dummy_config, comprehend_medical_client=mock_comprehend_medical
    )

    sanitized = service_instance._sanitize_phi(text)

    mock_comprehend_medical.detect_phi.assert_called_once_with(Text=text)
    expected_sanitized = "Patient is [REDACTED-NAME] Doe, lives a[REDACTED-ADDRESS] St."
    assert sanitized == expected_sanitized


def test_sanitize_phi_error(aws_pat_service):
    """Test PHI sanitization when Comprehend Medical returns an error."""
    text = "Patient is John Smith, a 45-year-old male."
    mock_comprehend_medical = aws_pat_service._comprehend_medical

    mock_comprehend_medical.detect_phi.side_effect = ClientError(
        {"Error": {"Code": "InternalServerError", "Message": "Test error"}}, "DetectPHI"
    )

    sanitized = aws_pat_service._sanitize_phi(text)

    mock_comprehend_medical.detect_phi.assert_called_once_with(Text=text)
    assert sanitized == "[PHI SANITIZATION ERROR]"


def test_analyze_actigraphy(aws_pat_service):
    """Test actigraphy analysis."""
    patient_id = "patient123"
    readings = [{"x": 0.1, "y": 0.2, "z": 0.3, "timestamp": "2025-03-28T12:00:00Z"}]
    start_time = "2025-03-28T12:00:00Z"
    end_time = "2025-03-28T13:00:00Z"
    sampling_rate_hz = 50.0
    device_info = {"name": "ActiGraph GT9X", "firmware": "1.7.0"}
    analysis_types = ["activity_levels", "sleep_analysis"]

    result = aws_pat_service.analyze_actigraphy(
        patient_id,
        readings,
        start_time,
        end_time,
        sampling_rate_hz,
        device_info,
        analysis_types,
    )

    assert "analysis_id" in result
    assert "patient_id" in result
    assert "timestamp" in result
    assert "analysis_types" in result
    assert result["patient_id"] == patient_id
    assert result["analysis_types"] == analysis_types


def test_get_actigraphy_embeddings(aws_pat_service):
    """Test actigraphy embeddings generation."""
    patient_id = "patient123"
    readings = [{"x": 0.1, "y": 0.2, "z": 0.3, "timestamp": "2025-03-28T12:00:00Z"}]
    start_time = "2025-03-28T12:00:00Z"
    end_time = "2025-03-28T13:00:00Z"
    sampling_rate_hz = 50.0

    result = aws_pat_service.get_actigraphy_embeddings(
        patient_id, readings, start_time, end_time, sampling_rate_hz
    )

    assert "embedding_id" in result
    assert "patient_id" in result
    assert "timestamp" in result
    assert "embedding" in result
    assert result["patient_id"] == patient_id


def test_get_analysis_by_id(aws_pat_service):
    """Test retrieving analysis by ID."""
    with pytest.raises(ResourceNotFoundError):
        aws_pat_service.get_analysis_by_id("test-analysis-id")


def test_get_model_info(aws_pat_service, aws_config):
    """Test getting model information."""
    model_info = aws_pat_service.get_model_info()

    assert model_info["name"] == "AWS-PAT"
    assert "version" in model_info
    assert "capabilities" in model_info
    assert aws_config["endpoint_name"] == model_info["endpoint_name"]
    assert model_info["active"] is True


def test_integrate_with_digital_twin(aws_pat_service):
    """Test integrating analysis with digital twin."""
    patient_id = "patient123"
    profile_id = "profile456"
    analysis_id = "analysis789"

    result = aws_pat_service.integrate_with_digital_twin(patient_id, profile_id, analysis_id)

    assert "integration_id" in result
    assert "patient_id" in result
    assert "profile_id" in result
    assert "analysis_id" in result
    assert result["patient_id"] == patient_id
    assert result["profile_id"] == profile_id
    assert result["analysis_id"] == analysis_id
    assert result["status"] == "success"
