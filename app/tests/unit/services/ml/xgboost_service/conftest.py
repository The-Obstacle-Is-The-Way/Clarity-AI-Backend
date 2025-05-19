"""
Shared fixtures for AWS XGBoost service testing.

This module provides pytest fixtures that can be used across all test modules
for the AWS XGBoost service, ensuring consistent test setup and teardown.
"""

import asyncio
import sys
from datetime import datetime

import pytest

# Apply YAML mocking directly in conftest.py
from .mock_yaml import dump, safe_load


# Create a mock YAML module
class MockYamlModule:
    safe_load = safe_load
    dump = dump
    _is_mocked = True


# Install the mock when this module is imported
sys.modules["yaml"] = MockYamlModule

from app.core.services.ml.xgboost.aws_service import AWSXGBoostService, PrivacyLevel
from app.tests.unit.services.ml.xgboost_service.mocks import (
    MockAWSServiceFactory,
    MockDynamoDBService,
    MockS3Service,
    MockSageMakerService,
)


@pytest.fixture
def sample_patient_id():
    """Sample patient ID for testing."""
    return "patient-456"


@pytest.fixture
def sample_clinical_data():
    """Sample clinical data for testing."""
    return {
        "feature1": 1.0,
        "feature2": "value",
        "assessment_scores": {"phq9": 15, "gad7": 10},
        "demographics": {"age": 45, "gender": "F"},
        "medical_history": ["depression", "anxiety"],
    }


@pytest.fixture
def sample_clinical_data_with_phi():
    """Sample clinical data containing PHI for testing privacy features."""
    return {
        "feature1": 1.0,
        "feature2": "value",
        "patient_name": "John Doe",  # PHI element
        "ssn": "123-45-6789",  # PHI element
        "assessment_scores": {"phq9": 15, "gad7": 10},
    }


@pytest.fixture
def sample_treatment_details():
    """Sample treatment details for testing."""
    return {"treatment_type": "cbt", "duration_weeks": 12}


@pytest.fixture
def sample_outcome_timeframe():
    """Sample outcome timeframe for testing."""
    return {"weeks": 8}


@pytest.fixture
def sample_treatment_plan():
    """Sample treatment plan for testing."""
    return {
        "plan_id": "plan-123",
        "treatments": [{"type": "cbt", "frequency": "weekly"}],
    }


@pytest.fixture
def mock_settings_base():
    """Base settings for testing."""
    return {
        "region_name": "us-east-1",
        "endpoint_prefix": "test-prefix",
        "bucket_name": "test-bucket",
        "dynamodb_table_name": "test-predictions-table",
        "audit_table_name": "test-audit-table",
        "log_level": "INFO",
        "privacy_level": PrivacyLevel.STANDARD,
        "model_mappings": {
            "risk-relapse": "risk-relapse-endpoint",
            "risk-suicide": "risk-suicide-endpoint",
            "feature-importance": "feature-importance-endpoint",
            "digital-twin": "digital-twin-endpoint",
        },
    }


@pytest.fixture
def mock_aws_factory():
    """Create a mock AWS service factory for testing."""
    # Default mock sagemaker endpoints
    endpoints = [
        {
            "EndpointName": "test-prefix-risk-relapse-endpoint",
            "EndpointStatus": "InService",
            "CreationTime": datetime.now(),
            "LastModifiedTime": datetime.now(),
            "EndpointArn": "arn:aws:sagemaker:us-east-1:123456789012:endpoint/test-prefix-risk-relapse-endpoint",
        },
        {
            "EndpointName": "test-prefix-risk-suicide-endpoint",
            "EndpointStatus": "InService",
            "CreationTime": datetime.now(),
            "LastModifiedTime": datetime.now(),
            "EndpointArn": "arn:aws:sagemaker:us-east-1:123456789012:endpoint/test-prefix-risk-suicide-endpoint",
        },
        {
            "EndpointName": "test-prefix-feature-importance-endpoint",
            "EndpointStatus": "InService",
            "CreationTime": datetime.now(),
            "LastModifiedTime": datetime.now(),
            "EndpointArn": "arn:aws:sagemaker:us-east-1:123456789012:endpoint/test-prefix-feature-importance-endpoint",
        },
    ]

    # Create factory with preconfigured services
    factory = MockAWSServiceFactory(
        sagemaker_service=MockSageMakerService(endpoints),
        s3_service=MockS3Service(bucket_exists=True),
        dynamodb_service=MockDynamoDBService(),
    )

    return factory


@pytest.fixture
async def aws_xgboost_service(mock_aws_factory, mock_settings_base):
    """
    Fixture to provide an initialized AWSXGBoostService for testing.

    This fixture handles full initialization of the service, including
    patching appropriate methods to avoid actual AWS calls.
    """
    # Create the service
    service = AWSXGBoostService(aws_service_factory=mock_aws_factory)

    # Initialize the service with settings
    await service.initialize(mock_settings_base)

    # Return the initialized service
    return service


@pytest.fixture
def run_async():
    """Helper fixture to run async code in sync tests."""

    def _run_async(coro):
        return asyncio.run(coro)

    return _run_async
