"""
AWS Service Interface definitions.

This module defines interfaces for AWS services used throughout the application,
providing a clear abstraction boundary for testing and implementation swapping.
"""

from abc import ABC, abstractmethod
from typing import Any


class DynamoDBServiceInterface(ABC):
    """Interface for DynamoDB operations."""

    @abstractmethod
    def scan_table(self, table_name: str) -> dict[str, list[dict[str, Any]]]:
        """Scan a DynamoDB table and return all items."""
        pass

    @abstractmethod
    def put_item(self, table_name: str, item: dict[str, Any]) -> dict[str, Any]:
        """Put an item into a DynamoDB table."""
        pass

    @abstractmethod
    def get_item(self, table_name: str, key: dict[str, Any]) -> dict[str, Any]:
        """Get an item from a DynamoDB table."""
        pass

    @abstractmethod
    def query(
        self,
        table_name: str,
        key_condition_expression: str,
        expression_attribute_values: dict[str, Any],
    ) -> dict[str, Any]:
        """Query items from a DynamoDB table."""
        pass


class S3ServiceInterface(ABC):
    """Interface for S3 operations."""

    @abstractmethod
    def check_bucket_exists(self, bucket_name: str) -> bool:
        """Check if an S3 bucket exists."""
        pass

    @abstractmethod
    def put_object(self, bucket_name: str, key: str, body: bytes) -> dict[str, Any]:
        """Upload an object to S3."""
        pass

    @abstractmethod
    def get_object(self, bucket_name: str, key: str) -> dict[str, Any]:
        """Get an object from S3."""
        pass

    @abstractmethod
    def list_objects(
        self, bucket_name: str, prefix: str | None = None
    ) -> dict[str, Any]:
        """List objects in an S3 bucket with optional prefix."""
        pass

    @abstractmethod
    def download_file(self, bucket_name: str, key: str, filename: str) -> None:
        """Download a file from S3 to local filesystem."""
        pass


class SageMakerServiceInterface(ABC):
    """Interface for SageMaker control plane operations."""

    @abstractmethod
    def list_endpoints(self) -> list[dict[str, Any]]:
        """List all SageMaker endpoints."""
        pass

    @abstractmethod
    def describe_endpoint(self, endpoint_name: str) -> dict[str, Any]:
        """Get information about a SageMaker endpoint."""
        pass


class SageMakerRuntimeServiceInterface(ABC):
    """Interface for SageMaker runtime operations."""

    @abstractmethod
    def invoke_endpoint(
        self, endpoint_name: str, content_type: str, body: bytes, **kwargs
    ) -> dict[str, Any]:
        """Invoke a SageMaker endpoint."""
        pass


class ComprehendMedicalServiceInterface(ABC):
    """Interface for AWS Comprehend Medical operations."""

    @abstractmethod
    def detect_entities(self, text: str) -> dict[str, Any]:
        """Detect medical entities in text."""
        pass

    @abstractmethod
    def detect_phi(self, text: str) -> dict[str, Any]:
        """Detect PHI (Protected Health Information) in text."""
        pass

    @abstractmethod
    def infer_icd10_cm(self, text: str) -> dict[str, Any]:
        """Infer ICD-10-CM codes from medical text."""
        pass


class BedrockServiceInterface(ABC):
    """Interface for AWS Bedrock operations."""

    @abstractmethod
    def list_foundation_models(self) -> dict[str, Any]:
        """List available foundation models."""
        pass

    @abstractmethod
    def invoke_model(
        self, model_id: str, body: dict[str, Any], **kwargs
    ) -> dict[str, Any]:
        """Invoke a foundation model."""
        pass


class BedrockRuntimeServiceInterface(ABC):
    """Interface for AWS Bedrock runtime operations."""

    @abstractmethod
    def invoke_model(
        self,
        model_id: str,
        body: str | dict[str, Any] | bytes,
        content_type: str | None = None,
        accept: str | None = None,
        **kwargs,
    ) -> dict[str, Any]:
        """Invoke a foundation model."""
        pass

    @abstractmethod
    def invoke_model_with_response_stream(
        self,
        model_id: str,
        body: str | dict[str, Any] | bytes,
        content_type: str | None = None,
        accept: str | None = None,
        **kwargs,
    ) -> dict[str, Any]:
        """Invoke a foundation model with streaming response."""
        pass


class AWSSessionServiceInterface(ABC):
    """Interface for AWS session and credential management."""

    @abstractmethod
    def get_caller_identity(self) -> dict[str, Any]:
        """Get the AWS identity information for the caller."""
        pass

    @abstractmethod
    def get_available_regions(self, service_name: str) -> list[str]:
        """Get available regions for a specific AWS service."""
        pass

    @abstractmethod
    def get_current_region_name(self) -> str:
        """Get the current AWS region name."""
        pass


class AWSServiceFactory(ABC):
    """Factory interface for creating AWS service clients."""

    @abstractmethod
    def get_dynamodb_service(self) -> DynamoDBServiceInterface:
        """Get a DynamoDB service implementation."""
        pass

    @abstractmethod
    def get_s3_service(self) -> S3ServiceInterface:
        """Get an S3 service implementation."""
        pass

    @abstractmethod
    def get_sagemaker_service(self) -> SageMakerServiceInterface:
        """Get a SageMaker service implementation."""
        pass

    @abstractmethod
    def get_sagemaker_runtime_service(self) -> SageMakerRuntimeServiceInterface:
        """Get a SageMaker runtime service implementation."""
        pass

    @abstractmethod
    def get_comprehend_medical_service(self) -> ComprehendMedicalServiceInterface:
        """Get a Comprehend Medical service implementation."""
        pass

    @abstractmethod
    def get_bedrock_service(self) -> BedrockServiceInterface:
        """Get a Bedrock service implementation."""
        pass

    @abstractmethod
    def get_bedrock_runtime_service(self) -> BedrockRuntimeServiceInterface:
        """Get a Bedrock runtime service implementation."""
        pass

    @abstractmethod
    def get_session_service(self) -> AWSSessionServiceInterface:
        """Get an AWS session service implementation."""
        pass
