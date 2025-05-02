"""
AWS service testing fixtures.

This module provides pytest fixtures for testing with AWS services
that automatically use the in-memory implementations for hermetic tests.
"""

import os
from typing import Any

import pytest

from app.core.interfaces.aws_service_interface import AWSServiceFactory
from app.infrastructure.aws.in_memory_aws_services import (
    InMemoryAWSServiceFactory,
    InMemoryDynamoDBService,
    InMemoryS3Service,
    InMemorySageMakerService,
)
from app.infrastructure.aws.service_factory_provider import AWSServiceFactoryProvider


@pytest.fixture(scope="session", autouse=True)
def aws_test_environment() -> None:
    """Set up the test environment for AWS service testing."""
    # Force testing mode
    os.environ["TESTING"] = "1"
    
    # Initialize AWS service factory provider with in-memory implementation
    AWSServiceFactoryProvider.initialize(use_in_memory=True)
    
    # Verify initialization was successful
    factory = AWSServiceFactoryProvider.get_instance().get_service_factory()
    assert isinstance(factory, InMemoryAWSServiceFactory), "AWS factory not properly initialized for testing"


@pytest.fixture
def aws_service_factory() -> AWSServiceFactory:
    """Provide the configured AWS service factory for tests."""
    return AWSServiceFactoryProvider.get_instance().get_service_factory()


@pytest.fixture
def dynamodb_service(aws_service_factory) -> InMemoryDynamoDBService:
    """Provide a clean DynamoDB service for each test."""
    dynamodb = aws_service_factory.get_dynamodb_service()
    # Reset the tables before each test
    if isinstance(dynamodb, InMemoryDynamoDBService):
        dynamodb.tables = {}
    return dynamodb


@pytest.fixture
def s3_service(aws_service_factory) -> InMemoryS3Service:
    """Provide a clean S3 service for each test."""
    s3 = aws_service_factory.get_s3_service()
    # Reset the buckets before each test
    if isinstance(s3, InMemoryS3Service):
        s3.objects = {}
        # Ensure standard test bucket exists
        s3.bucket_exists = True
    return s3


@pytest.fixture
def sagemaker_service(aws_service_factory) -> InMemorySageMakerService:
    """Provide a SageMaker service with standard test endpoints."""
    sagemaker = aws_service_factory.get_sagemaker_service()
    # Set up standard test endpoints
    if isinstance(sagemaker, InMemorySageMakerService):
        sagemaker._endpoints = {
            "xgboost-suicide-risk": {"status": "InService"},
            "xgboost-readmission-risk": {"status": "InService"},
            "xgboost-medication-adherence": {"status": "InService"}
        }
    return sagemaker


@pytest.fixture
def test_aws_config() -> dict[str, Any]:
    """Provide standard AWS configuration for tests."""
    return {
        "aws_region": "us-east-1",
        "endpoint_prefix": "xgboost-",
        "bucket_name": "novamind-test-bucket",
        "dynamodb_table_name": "novamind-test-predictions",
        "audit_table_name": "novamind-test-audit-log",
        "kms_key_id": "test-kms-key", 
        "model_mappings": {
            "suicide": "suicide-risk",
            "readmission": "readmission-risk",
            "medication_adherence": "medication-adherence"
        }
    } 