"""
Unit tests for AWS PAT service implementation.

This module contains tests for the AWS implementation of the PAT service.
All AWS services are mocked to avoid making actual API calls.
"""

import pytest
from unittest.mock import MagicMock, Mock
from botocore.exceptions import ClientError

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


@pytest.fixture(scope="function")
def mock_boto3(mocker, request):
    """Fixture to mock boto3 clients and resources for tests that need it."""

    # --- Mock boto3.client to return specific mocks per service --- 
    mock_s3_instance = MagicMock()
    mock_s3_instance.list_buckets.return_value = {"Buckets": [{"Name": "test-pat-bucket"}]}
    # Add other S3 mocks as needed...

    mock_sagemaker_instance = MagicMock()
    # Add SageMaker mocks as needed...

    mock_comprehend_instance = MagicMock(name="GenericMockComprehendMedicalClient")
    # No specific config here anymore - will be handled by dedicated fixture
    # Add other Comprehend Medical mocks as needed...

    # Central mock for boto3.client, targeting where it's imported in the service module
    mock_client = mocker.patch("app.core.services.ml.pat.aws.boto3.client")

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
    mock_table = MagicMock(name="MockDynamoDBTable")
    mock_resource = MagicMock(name="MockDynamoDBResource")

    # Default behavior: Simulate successful load
    mock_table.load.return_value = None

    # Check if the 'simulate_load_failure' marker is present
    if hasattr(request, "param") and request.param == "simulate_load_failure":
        # Simulate ClientError on table.load()
        error_response = {'Error': {'Code': 'ResourceNotFoundException', 'Message': 'Table not found'}}
        operation_name = 'DescribeTable'
        mock_table.load.side_effect = ClientError(error_response, operation_name)

    # Configure the mock resource's Table method to return the mock table
    mock_resource.Table.return_value = mock_table

    return mock_resource  # Return the configured mock resource


# Restore the dedicated fixture for the Comprehend Medical client mock
@pytest.fixture
def mock_comprehend_medical_client():
    """Fixture for a mock comprehendmedical client."""
    client = MagicMock(name="MockComprehendMedicalClient")
    # Explicitly mock the detect_phi method itself using Mock instead of MagicMock
    client.detect_phi = Mock(name="MockDetectPhiMethod")
    # Set the return value on the mock method
    client.detect_phi.return_value = {
        'Entities': [
            {
                'Text': 'John Doe', 'Type': 'NAME', 'Score': 0.99, 
                'BeginOffset': 14, 'EndOffset': 22
            },
            {
                'Text': '123 Main St', 'Type': 'ADDRESS', 'Score': 0.98, 
                'BeginOffset': 34, 'EndOffset': 45
            }
        ]
    }
    return client


@pytest.fixture
def mock_s3_client(mocker):
    """Fixture for a mock S3 client."""
    client = MagicMock(name="MockS3Client")
    return client


@pytest.fixture
def aws_pat_service(mock_dynamodb_resource, mock_comprehend_medical_client, mock_s3_client, aws_config):
    """Provides an AWSPATService instance initialized with mock resources."""
    service = AWSPATService()
    # Pass the mock resource fixtures into initialize for proper DI
    # Inject both mock DynamoDB and the dedicated Comprehend Medical client
    service.initialize(
        config=aws_config, 
        dynamodb_resource=mock_dynamodb_resource,
        comprehend_medical_client=mock_comprehend_medical_client, # Inject the dedicated mock
        s3_client=mock_s3_client # Pass the S3 mock
    )
    return service


@pytest.mark.parametrize("mock_dynamodb_resource", ["simulate_load_failure"], indirect=True)
def test_initialization_failure(
    aws_config, 
    mock_dynamodb_resource, # Result from the fixture (via indirect=True)
    mocker # Add mocker fixture
):
    """Test initialization failure when a DynamoDB table load fails."""
    # Patch boto3.resource within the service's module scope to return the fixture's mock resource
    mock_b3_resource = mocker.patch("app.core.services.ml.pat.aws.boto3.resource")
    mock_b3_resource.return_value = mock_dynamodb_resource

    service = AWSPATService() # Instantiate directly

    with pytest.raises(InitializationError) as excinfo:
        service.initialize(config=aws_config) # Call initialize here

    # Check that the specific error message from _verify_resources is present
    expected_error_part = f"Resource verification failed for table '{aws_config['analyses_table']}'"
    assert expected_error_part in str(excinfo.value)

    # Verify that the mock resource's Table method was called
    # Also verify that boto3.resource was called correctly by the initialize method
    mock_b3_resource.assert_called_once_with('dynamodb', region_name=aws_config['aws_region'])
    mock_dynamodb_resource.Table.assert_called_once_with(aws_config['analyses_table'])
    # Verify that the mock table's load method was called
    mock_table = mock_dynamodb_resource.Table.return_value
    mock_table.load.assert_called_once()


def test_sanitize_phi(mock_comprehend_medical_client, mock_dynamodb_resource, mock_s3_client, aws_config):
    """Test PHI sanitization works correctly."""
    # Initialize service manually with all required mock clients
    service = AWSPATService()
    service.initialize(
        config=aws_config, 
        comprehend_medical_client=mock_comprehend_medical_client,
        dynamodb_resource=mock_dynamodb_resource, 
        s3_client=mock_s3_client # Pass the S3 mock
    )

    text_with_phi = "Patient name: John Doe, lives at 123 Main St."
    expected_sanitized_text = "Patient name: [NAME], lives at [ADDRESS]."

    # Call the method under test
    sanitized = service._sanitize_phi(text_with_phi)

    # Assertions
    assert sanitized == expected_sanitized_text
    # Assert mock was called correctly
    mock_comprehend_medical_client.detect_phi.assert_called_once_with(Text=text_with_phi)


def test_sanitize_phi_error(aws_pat_service):
    """Test PHI sanitization when Comprehend Medical returns an error."""
    text = "Patient is John Smith, a 45-year-old male."

    # Ensure the service has been initialized and has the comprehend client
    assert hasattr(aws_pat_service, '_comprehend_medical') and aws_pat_service._comprehend_medical is not None
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
