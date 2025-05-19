"""
Real AWS services implementation using boto3.

This module provides implementations of the AWS service interfaces
using the real boto3 library for production use.
"""

from typing import Any

import boto3
import botocore.exceptions

json_module = __import__("json")

from app.core.interfaces.aws_service_interface import (
    AWSServiceFactory,
    AWSSessionServiceInterface,
    BedrockRuntimeServiceInterface,
    BedrockServiceInterface,
    ComprehendMedicalServiceInterface,
    DynamoDBServiceInterface,
    S3ServiceInterface,
    SageMakerRuntimeServiceInterface,
    SageMakerServiceInterface,
)


class RealDynamoDBService(DynamoDBServiceInterface):
    """Real DynamoDB service implementation using boto3."""

    def __init__(self, region_name: str | None = None):
        """Initialize with optional region name."""
        self.region_name = region_name
        self._resource = boto3.resource("dynamodb", region_name=region_name)

    def scan_table(self, table_name: str) -> dict[str, list[dict[str, Any]]]:
        """Scan a DynamoDB table and return all items."""
        table = self._resource.Table(table_name)
        return table.scan()

    def put_item(self, table_name: str, item: dict[str, Any]) -> dict[str, Any]:
        """Put an item into a DynamoDB table."""
        table = self._resource.Table(table_name)
        return table.put_item(Item=item)

    def get_item(self, table_name: str, key: dict[str, Any]) -> dict[str, Any]:
        """Get an item from a DynamoDB table."""
        table = self._resource.Table(table_name)
        return table.get_item(Key=key)

    def query(
        self,
        table_name: str,
        key_condition_expression: str,
        expression_attribute_values: dict[str, Any],
    ) -> dict[str, Any]:
        """Query items from a DynamoDB table."""
        table = self._resource.Table(table_name)
        return table.query(
            KeyConditionExpression=key_condition_expression,
            ExpressionAttributeValues=expression_attribute_values,
        )


class RealS3Service(S3ServiceInterface):
    """Real S3 service implementation using boto3."""

    def __init__(self, region_name: str | None = None):
        """Initialize with optional region name."""
        self.region_name = region_name
        self._client = boto3.client("s3", region_name=region_name)

    def check_bucket_exists(self, bucket_name: str) -> bool:
        """Check if an S3 bucket exists."""
        try:
            self._client.head_bucket(Bucket=bucket_name)
            return True
        except botocore.exceptions.ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code in ["404", "403", "NoSuchBucket"]:
                return False
            # Re-raise for unexpected errors
            raise

    def put_object(self, bucket_name: str, key: str, body: bytes) -> dict[str, Any]:
        """Upload an object to S3."""
        return self._client.put_object(Bucket=bucket_name, Key=key, Body=body)

    def get_object(self, bucket_name: str, key: str) -> dict[str, Any]:
        """Get an object from S3."""
        return self._client.get_object(Bucket=bucket_name, Key=key)

    def list_objects(
        self, bucket_name: str, prefix: str | None = None
    ) -> dict[str, Any]:
        """List objects in an S3 bucket with optional prefix."""
        params = {"Bucket": bucket_name}
        if prefix is not None:
            params["Prefix"] = prefix
        return self._client.list_objects_v2(**params)

    def download_file(self, bucket_name: str, key: str, filename: str) -> None:
        """Download a file from S3 to local filesystem."""
        self._client.download_file(bucket_name, key, filename)


class RealSageMakerService(SageMakerServiceInterface):
    """Real SageMaker service implementation using boto3."""

    def __init__(self, region_name: str | None = None):
        """Initialize with optional region name."""
        self.region_name = region_name
        self._client = boto3.client("sagemaker", region_name=region_name)

    def list_endpoints(self) -> list[dict[str, Any]]:
        """List all SageMaker endpoints."""
        response = self._client.list_endpoints()
        return response.get("Endpoints", [])

    def describe_endpoint(self, endpoint_name: str) -> dict[str, Any]:
        """Get information about a SageMaker endpoint."""
        return self._client.describe_endpoint(EndpointName=endpoint_name)


class RealSageMakerRuntimeService(SageMakerRuntimeServiceInterface):
    """Real SageMaker runtime service implementation using boto3."""

    def __init__(self, region_name: str | None = None):
        """Initialize with optional region name."""
        self.region_name = region_name
        self._client = boto3.client("sagemaker-runtime", region_name=region_name)

    def invoke_endpoint(
        self, endpoint_name: str, content_type: str, body: bytes, **kwargs
    ) -> dict[str, Any]:
        """Invoke a SageMaker endpoint."""
        return self._client.invoke_endpoint(
            EndpointName=endpoint_name, ContentType=content_type, Body=body, **kwargs
        )


class RealComprehendMedicalService(ComprehendMedicalServiceInterface):
    """Real AWS Comprehend Medical service implementation using boto3."""

    def __init__(self, region_name: str | None = None):
        """Initialize with optional region name."""
        self.region_name = region_name
        self._client = boto3.client("comprehendmedical", region_name=region_name)

    def detect_entities(self, text: str) -> dict[str, Any]:
        """Detect medical entities in text."""
        return self._client.detect_entities_v2(Text=text)

    def detect_phi(self, text: str) -> dict[str, Any]:
        """Detect PHI (Protected Health Information) in text."""
        return self._client.detect_phi(Text=text)

    def infer_icd10_cm(self, text: str) -> dict[str, Any]:
        """Infer ICD-10-CM codes from medical text."""
        return self._client.infer_icd10_cm(Text=text)


class RealBedrockService(BedrockServiceInterface):
    """Real AWS Bedrock service implementation using boto3."""

    def __init__(self, region_name: str | None = None):
        """Initialize with optional region name."""
        self.region_name = region_name
        self._client = boto3.client("bedrock", region_name=region_name)

    def list_foundation_models(self) -> dict[str, Any]:
        """List available foundation models."""
        return self._client.list_foundation_models()

    def invoke_model(
        self, model_id: str, body: dict[str, Any], **kwargs
    ) -> dict[str, Any]:
        """Invoke a foundation model."""
        # Convert dict to JSON string if needed
        if isinstance(body, dict):
            body = json_module.dumps(body).encode("utf-8")

        return self._client.invoke_model(modelId=model_id, body=body, **kwargs)


class RealBedrockRuntimeService(BedrockRuntimeServiceInterface):
    """Real AWS Bedrock runtime service implementation using boto3."""

    def __init__(self, region_name: str | None = None):
        """Initialize with optional region name."""
        self.region_name = region_name
        self._client = boto3.client("bedrock-runtime", region_name=region_name)

    def invoke_model(
        self,
        model_id: str,
        body: str | dict[str, Any] | bytes,
        content_type: str | None = None,
        accept: str | None = None,
        **kwargs,
    ) -> dict[str, Any]:
        """Invoke a foundation model."""
        # Handle different body types
        if isinstance(body, dict):
            body = json_module.dumps(body).encode("utf-8")
        elif isinstance(body, str):
            body = body.encode("utf-8")

        params = {"modelId": model_id, "body": body}
        if content_type:
            params["contentType"] = content_type
        if accept:
            params["accept"] = accept

        return self._client.invoke_model(**params, **kwargs)

    def invoke_model_with_response_stream(
        self,
        model_id: str,
        body: str | dict[str, Any] | bytes,
        content_type: str | None = None,
        accept: str | None = None,
        **kwargs,
    ) -> dict[str, Any]:
        """Invoke a foundation model with streaming response."""
        # Handle different body types
        if isinstance(body, dict):
            body = json_module.dumps(body).encode("utf-8")
        elif isinstance(body, str):
            body = body.encode("utf-8")

        params = {"modelId": model_id, "body": body}
        if content_type:
            params["contentType"] = content_type
        if accept:
            params["accept"] = accept

        return self._client.invoke_model_with_response_stream(**params, **kwargs)


class RealAWSSessionService(AWSSessionServiceInterface):
    """Real AWS session service implementation using boto3."""

    def __init__(self, region_name: str | None = None):
        """Initialize with optional region name."""
        self.region_name = region_name
        self._session = boto3.session.Session(region_name=region_name)
        self._sts_client = self._session.client("sts")

    def get_caller_identity(self) -> dict[str, Any]:
        """Get the AWS identity information for the caller."""
        return self._sts_client.get_caller_identity()

    def get_available_regions(self, service_name: str) -> list[str]:
        """Get available regions for a specific AWS service."""
        return self._session.get_available_regions(service_name)

    def get_current_region_name(self) -> str:
        """Get the current AWS region name."""
        return (
            self._session.region_name or "us-east-1"
        )  # Default to us-east-1 if not set


class RealAWSServiceFactory(AWSServiceFactory):
    """Factory for creating real AWS service implementations."""

    def __init__(self, region_name: str | None = None):
        """Initialize with optional region name."""
        self.region_name = region_name

    def get_dynamodb_service(self) -> DynamoDBServiceInterface:
        """Get a DynamoDB service implementation."""
        return RealDynamoDBService(region_name=self.region_name)

    def get_s3_service(self) -> S3ServiceInterface:
        """Get an S3 service implementation."""
        return RealS3Service(region_name=self.region_name)

    def get_sagemaker_service(self) -> SageMakerServiceInterface:
        """Get a SageMaker service implementation."""
        return RealSageMakerService(region_name=self.region_name)

    def get_sagemaker_runtime_service(self) -> SageMakerRuntimeServiceInterface:
        """Get a SageMaker runtime service implementation."""
        return RealSageMakerRuntimeService(region_name=self.region_name)

    def get_comprehend_medical_service(self) -> ComprehendMedicalServiceInterface:
        """Get a Comprehend Medical service implementation."""
        return RealComprehendMedicalService(region_name=self.region_name)

    def get_bedrock_service(self) -> BedrockServiceInterface:
        """Get a Bedrock service implementation."""
        return RealBedrockService(region_name=self.region_name)

    def get_bedrock_runtime_service(self) -> BedrockRuntimeServiceInterface:
        """Get a Bedrock runtime service implementation."""
        return RealBedrockRuntimeService(region_name=self.region_name)

    def get_session_service(self) -> AWSSessionServiceInterface:
        """Get an AWS session service implementation."""
        return RealAWSSessionService(region_name=self.region_name)
