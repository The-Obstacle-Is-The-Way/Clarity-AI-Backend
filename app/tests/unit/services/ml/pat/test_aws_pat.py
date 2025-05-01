"""
Unit tests for AWS PAT service implementation.

This module contains tests for the AWS implementation of the PAT service.
All AWS services are mocked to avoid making actual API calls.
"""

import pytest
from unittest.mock import Mock, MagicMock

# Third-party imports
from botocore.exceptions import ClientError

# First-party imports
from app.core.services.ml.pat.aws import AWSPATService
from app.core.services.ml.pat.exceptions import InitializationError, ResourceNotFoundError


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

    # --- Conditionally mock DynamoDB resource --- 
    if not request.node.get_closest_marker("no_mock_dynamodb_resource"):
        mock_dynamodb_resource_instance = MagicMock()
        # Add DynamoDB table mocks as needed...
        mocker.patch("boto3.resource", return_value=mock_dynamodb_resource_instance)

    yield # Allow tests to run with mocks


@pytest.fixture
def aws_pat_service(mock_boto3, aws_config):
    """Fixture for AWS PAT service. Relies on autouse mock_boto3 for patching."""
    service = AWSPATService()

    # Initialize the service. The autouse mock_boto3 fixture ensures that
    # calls to boto3.client/resource within initialize() get the mocks.
    service.initialize(config=aws_config)
    yield service


@pytest.mark.no_mock_dynamodb_resource
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
        assert service._sagemaker_runtime is not None
        assert service._s3_client is not None
        assert service._dynamodb_resource is not None
        assert service._comprehend_medical is not None

    @pytest.mark.no_mock_dynamodb_resource
    def test_initialization_failure(self, aws_config, mocker):
        """Test initialization failure when accessing a table fails during check."""
        # Mock boto3.resource factory
        mock_resource_factory = mocker.patch("boto3.resource")

        # Create a mock for the resource instance
        mock_dynamodb_instance = MagicMock()

        # Create a mock for the table instance
        mock_table_instance = MagicMock()

        # Configure the mock table's load() method to raise a suitable ClientError
        # Use an error code OTHER than 'ResourceNotFoundException' to trigger InitializationError
        mock_table_instance.load.side_effect = ClientError(
            error_response={'Error': {'Code': 'ProvisionedThroughputExceededException', 'Message': 'Mock load error'}},
            operation_name='DescribeTable' # Example operation name
        )

        # Configure the mock resource's Table() method to return the mock table instance
        mock_dynamodb_instance.Table.return_value = mock_table_instance

        # Make the patched boto3.resource return the configured mock resource instance
        mock_resource_factory.return_value = mock_dynamodb_instance

        # --- Debug Prints ---
        print("\n[TEST DEBUG] Mock Setup Complete:")
        print(f"[TEST DEBUG] boto3.resource patched: {mocker.patch.call_args_list}") # Crude check
        print(f"[TEST DEBUG] mock_dynamodb_instance.Table returns: {mock_dynamodb_instance.Table.return_value}")
        print(f"[TEST DEBUG] mock_table_instance.load side_effect: {mock_table_instance.load.side_effect}\n")

        # --- Act & Assert ---
        service = AWSPATService()
        # Expect InitializationError because mock_table_instance.load() will raise a ClientError
        # which is caught by _check_table_exists and re-raised as InitializationError.
        with pytest.raises(InitializationError) as excinfo:
            service.initialize(aws_config)

        # Assert on the exception message
        assert "ClientError accessing table" in str(excinfo.value) 
        assert "Mock load error" in str(excinfo.value)

    def test_sanitize_phi(self, mocker):
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

    def test_sanitize_phi_error(self, aws_pat_service):
        """Test PHI sanitization when Comprehend Medical returns an error."""
        text = "Patient is John Smith, a 45-year-old male."
        mock_comprehend_medical = aws_pat_service._comprehend_medical

        mock_comprehend_medical.detect_phi.side_effect = ClientError(
            {"Error": {"Code": "InternalServerError", "Message": "Test error"}}, "DetectPHI"
        )

        sanitized = aws_pat_service._sanitize_phi(text)

        mock_comprehend_medical.detect_phi.assert_called_once_with(Text=text)
        assert sanitized == "[PHI SANITIZATION ERROR]"

    def test_analyze_actigraphy(self, aws_pat_service):
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

    def test_get_actigraphy_embeddings(self, aws_pat_service):
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

    def test_get_analysis_by_id(self, aws_pat_service):
        """Test retrieving analysis by ID."""
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
