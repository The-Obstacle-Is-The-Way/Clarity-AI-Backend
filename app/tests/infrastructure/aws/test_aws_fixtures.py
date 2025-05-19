"""
Test for AWS fixture functionality after reorganization.

This file tests that the AWS fixtures are working correctly
in their new location.
"""

from app.core.interfaces.aws_service_interface import AWSServiceFactory
from app.infrastructure.aws.in_memory_aws_services import (
    InMemoryAWSServiceFactory,
    InMemoryDynamoDBService,
    InMemoryS3Service,
    InMemorySageMakerService,
)


def test_aws_service_factory(aws_service_factory):
    """Test that the aws_service_factory fixture returns the expected type."""
    assert isinstance(aws_service_factory, AWSServiceFactory)
    assert isinstance(aws_service_factory, InMemoryAWSServiceFactory)


def test_dynamodb_service(dynamodb_service):
    """Test that the dynamodb_service fixture returns the expected type."""
    assert isinstance(dynamodb_service, InMemoryDynamoDBService)
    # Verify we can perform operations
    dynamodb_service.tables = {"test_table": {}}
    assert "test_table" in dynamodb_service.tables


def test_s3_service(s3_service):
    """Test that the s3_service fixture returns the expected type."""
    assert isinstance(s3_service, InMemoryS3Service)
    # Verify we can perform operations
    test_key = "test/file.txt"
    test_content = b"test content"
    s3_service.put_object(bucket_name="novamind-test-bucket", key=test_key, body=test_content)
    # Check that the object was stored - need to access the internal structure since there's no direct accessor
    assert "novamind-test-bucket" in s3_service._buckets
    assert test_key in s3_service._buckets["novamind-test-bucket"]


def test_sagemaker_service(sagemaker_service):
    """Test that the sagemaker_service fixture returns the expected type."""
    assert isinstance(sagemaker_service, InMemorySageMakerService)
    # Verify the test endpoints were set up
    assert "xgboost-suicide-risk" in sagemaker_service._endpoints
    assert sagemaker_service._endpoints["xgboost-suicide-risk"]["status"] == "InService"


def test_aws_config(test_aws_config):
    """Test that the test_aws_config fixture returns the expected configuration."""
    assert isinstance(test_aws_config, dict)
    assert test_aws_config["aws_region"] == "us-east-1"
    assert test_aws_config["bucket_name"] == "novamind-test-bucket"
    assert "model_mappings" in test_aws_config
