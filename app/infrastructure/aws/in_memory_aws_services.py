"""
In-memory AWS service implementations for testing.

This module provides in-memory implementations of the AWS service interfaces
that can be used in tests without requiring actual AWS connectivity.
"""

import json
import uuid
from datetime import datetime
from io import BytesIO
from typing import Any

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
from app.domain.utils.datetime_utils import UTC


class InMemoryDynamoDBService(DynamoDBServiceInterface):
    """In-memory DynamoDB service implementation for testing."""

    def __init__(self):
        """Initialize with empty tables storage."""
        self._tables: dict[str, list[dict[str, Any]]] = {}

    def scan_table(self, table_name: str) -> dict[str, list[dict[str, Any]]]:
        """Scan a DynamoDB table and return all items."""
        if table_name not in self._tables:
            self._tables[table_name] = []
        return {"Items": list(self._tables[table_name])}

    def put_item(self, *, TableName: str, Item: dict[str, Any]) -> dict[str, Any]:
        """Put an item into a DynamoDB table."""
        if TableName not in self._tables:
            self._tables[TableName] = []
        self._tables[TableName].append(Item)
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    def get_item(self, table_name: str, key: dict[str, Any]) -> dict[str, Any]:
        """Get an item from a DynamoDB table."""
        if table_name not in self._tables:
            return {"Item": None}

        # Find matching item by key
        for item in self._tables[table_name]:
            match = True
            for k, v in key.items():
                if k not in item or item[k] != v:
                    match = False
                    break
            if match:
                return {"Item": item}

        return {"Item": None}

    def query(
        self,
        table_name: str,
        key_condition_expression: str,
        expression_attribute_values: dict[str, Any],
    ) -> dict[str, Any]:
        """Query items from a DynamoDB table."""
        # This is a very simplified implementation for testing
        # In real applications, you'd need a proper expression parser
        if table_name not in self._tables:
            return {"Items": []}

        # Mock implementation - just return all items for now
        # In a real implementation, you would parse and apply the expression
        return {
            "Items": self._tables[table_name],
            "Count": len(self._tables[table_name]),
        }


class InMemoryS3Service(S3ServiceInterface):
    """In-memory S3 service implementation for testing."""

    def __init__(self):
        """Initialize with empty buckets storage."""
        self._buckets: dict[str, dict[str, bytes]] = {}

    def check_bucket_exists(self, bucket_name: str) -> bool:
        """Check if an S3 bucket exists."""
        return bucket_name in self._buckets

    def put_object(self, bucket_name: str, key: str, body: bytes) -> dict[str, Any]:
        """Upload an object to S3."""
        if bucket_name not in self._buckets:
            self._buckets[bucket_name] = {}
        self._buckets[bucket_name][key] = body
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    def get_object(self, bucket_name: str, key: str) -> dict[str, Any]:
        """Get an object from S3."""
        if bucket_name not in self._buckets or key not in self._buckets[bucket_name]:
            raise Exception(f"Key '{key}' not found in bucket '{bucket_name}'")

        body = self._buckets[bucket_name][key]
        return {
            "Body": BytesIO(body),
            "ContentLength": len(body),
            "ResponseMetadata": {"HTTPStatusCode": 200},
        }

    def list_objects(self, bucket_name: str, prefix: str | None = None) -> dict[str, Any]:
        """List objects in an S3 bucket with optional prefix."""
        if bucket_name not in self._buckets:
            return {"Contents": []}

        contents = []
        for key, body in self._buckets[bucket_name].items():
            if prefix is None or key.startswith(prefix):
                contents.append({"Key": key, "Size": len(body), "LastModified": datetime.now(UTC)})

        return {"Contents": contents}

    def download_file(self, bucket_name: str, key: str, filename: str) -> None:
        """Download a file from S3 to local filesystem."""
        if bucket_name not in self._buckets or key not in self._buckets[bucket_name]:
            raise Exception(f"Key '{key}' not found in bucket '{bucket_name}'")

        # In a test environment, we don't actually write to disk
        # But we'll record that this was called successfully
        pass


class InMemorySageMakerService(SageMakerServiceInterface):
    """In-memory SageMaker service implementation for testing."""

    def __init__(self):
        """Initialize with empty endpoints storage."""
        self._endpoints: dict[str, dict[str, Any]] = {}

    def list_endpoints(self) -> list[dict[str, Any]]:
        """List all SageMaker endpoints."""
        return [
            {"EndpointName": name, "EndpointStatus": info.get("status", "InService")}
            for name, info in self._endpoints.items()
        ]

    def describe_endpoint(self, endpoint_name: str) -> dict[str, Any]:
        """Get information about a SageMaker endpoint."""
        # If endpoint doesn't exist, create a default one to avoid errors in tests
        info = self._endpoints.setdefault(endpoint_name, {})
        return {"EndpointStatus": info.get("status", "InService")}


class BodyWrapper:
    """Wrapper for response body to mimic boto3 streaming body."""

    def __init__(self, value: Any):
        """Initialize with a value that will be returned by read()."""
        self.value = value

    def read(self, *_, **__) -> bytes:
        """Read and return the body content as bytes."""
        return json.dumps(self.value).encode()


class InMemorySageMakerRuntimeService(SageMakerRuntimeServiceInterface):
    """In-memory SageMaker runtime service implementation for testing."""

    def invoke_endpoint(
        self, endpoint_name: str, content_type: str, body: bytes, **kwargs
    ) -> dict[str, Any]:
        """Invoke a SageMaker endpoint with deterministic test responses."""
        # Create a predictable test response
        response_payload = {
            "risk_score": 0.42,
            "confidence": 0.9,
            "contributing_factors": [],
            "prediction_id": str(uuid.uuid4()),
            "timestamp": datetime.now(UTC).isoformat(),
        }

        return {
            "Body": BodyWrapper(value=response_payload),
            "ResponseMetadata": {"HTTPStatusCode": 200},
        }


class InMemoryComprehendMedicalService(ComprehendMedicalServiceInterface):
    """In-memory AWS Comprehend Medical service implementation for testing."""

    def detect_entities(self, text: str) -> dict[str, Any]:
        """Simulate detection of medical entities in text."""
        # Return simulated medical entities that would be found in psychiatric texts
        return {
            "Entities": [
                {
                    "Id": 0,
                    "Text": "depression",
                    "Category": "MEDICAL_CONDITION",
                    "Type": "DX_NAME",
                    "Score": 0.97,
                    "BeginOffset": text.find("depression") if "depression" in text else 0,
                    "EndOffset": text.find("depression") + 10 if "depression" in text else 10,
                },
                {
                    "Id": 1,
                    "Text": "anxiety",
                    "Category": "MEDICAL_CONDITION",
                    "Type": "DX_NAME",
                    "Score": 0.95,
                    "BeginOffset": text.find("anxiety") if "anxiety" in text else 0,
                    "EndOffset": text.find("anxiety") + 7 if "anxiety" in text else 7,
                },
            ],
            "UnmappedAttributes": [],
            "ResponseMetadata": {"HTTPStatusCode": 200},
        }

    def detect_phi(self, text: str) -> dict[str, Any]:
        """Simulate detection of PHI in text."""
        # Return simulated PHI entities with high sensitivity for testing
        return {
            "Entities": [
                {
                    "Id": 0,
                    "Text": "John Doe",
                    "Category": "PROTECTED_HEALTH_INFORMATION",
                    "Type": "NAME",
                    "Score": 0.99,
                    "BeginOffset": text.find("John") if "John" in text else 0,
                    "EndOffset": text.find("Doe") + 3 if "Doe" in text else 8,
                },
                {
                    "Id": 1,
                    "Text": "123-45-6789",
                    "Category": "PROTECTED_HEALTH_INFORMATION",
                    "Type": "ID",
                    "Score": 0.99,
                    "BeginOffset": text.find("123-45-6789") if "123-45-6789" in text else 0,
                    "EndOffset": text.find("123-45-6789") + 11 if "123-45-6789" in text else 11,
                },
            ],
            "ModelVersion": "ComprehendMedicalPHIModelV20190401",
            "ResponseMetadata": {"HTTPStatusCode": 200},
        }

    def infer_icd10_cm(self, text: str) -> dict[str, Any]:
        """Simulate inference of ICD-10-CM codes from text."""
        # Return simulated ICD-10 codes relevant to psychiatry
        return {
            "Entities": [
                {
                    "Id": 0,
                    "Text": "major depression",
                    "Category": "MEDICAL_CONDITION",
                    "Type": "DX_NAME",
                    "Score": 0.95,
                    "BeginOffset": text.find("depression") if "depression" in text else 0,
                    "EndOffset": text.find("depression") + 10 if "depression" in text else 10,
                    "ICD10CMConcepts": [
                        {
                            "Code": "F32.9",
                            "Description": "Major depressive disorder, single episode, unspecified",
                            "Score": 0.95,
                        },
                        {
                            "Code": "F33.9",
                            "Description": "Major depressive disorder, recurrent, unspecified",
                            "Score": 0.85,
                        },
                    ],
                    "Traits": [],
                }
            ],
            "ModelVersion": "ComprehendMedicalICD10CMModelV20220601",
            "ResponseMetadata": {"HTTPStatusCode": 200},
        }


class InMemoryBedrockService(BedrockServiceInterface):
    """In-memory AWS Bedrock service implementation for testing."""

    def list_foundation_models(self) -> dict[str, Any]:
        """Simulate listing available foundation models."""
        return {
            "modelSummaries": [
                {
                    "modelId": "anthropic.claude-v2",
                    "modelName": "Claude 2",
                    "providerName": "Anthropic",
                    "modelArn": "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-v2",
                    "responseStreamingSupported": True,
                },
                {
                    "modelId": "meta.llama2-70b-chat-v1",
                    "modelName": "Llama 2 Chat 70B",
                    "providerName": "Meta",
                    "modelArn": "arn:aws:bedrock:us-east-1::foundation-model/meta.llama2-70b-chat-v1",
                    "responseStreamingSupported": True,
                },
            ],
            "ResponseMetadata": {"HTTPStatusCode": 200},
        }

    def invoke_model(self, model_id: str, body: dict[str, Any], **kwargs) -> dict[str, Any]:
        """Simulate invoking a foundation model."""
        # Mock response for testing
        return {
            "body": BytesIO(
                json.dumps(
                    {
                        "completion": "This is a mock response from the in-memory Bedrock service for testing."
                    }
                ).encode()
            ),
            "contentType": "application/json",
            "ResponseMetadata": {"HTTPStatusCode": 200},
        }


class InMemoryBedrockRuntimeService(BedrockRuntimeServiceInterface):
    """In-memory AWS Bedrock runtime service implementation for testing."""

    def invoke_model(
        self,
        model_id: str,
        body: str | dict[str, Any] | bytes,
        content_type: str | None = None,
        accept: str | None = None,
        **kwargs,
    ) -> dict[str, Any]:
        """Simulate invoking a foundation model."""
        # Interpret the request based on model_id
        if "anthropic.claude" in model_id:
            response_content = {
                "completion": "This is a simulated response from Claude for psychiatric assessment."
            }
        elif "meta.llama" in model_id:
            response_content = {
                "generation": "This is a simulated response from Llama for psychiatric assessment."
            }
        else:
            response_content = {
                "output": "This is a generic simulated response for psychiatric assessment."
            }

        return {
            "body": BytesIO(json.dumps(response_content).encode()),
            "contentType": "application/json",
            "ResponseMetadata": {"HTTPStatusCode": 200},
        }

    def invoke_model_with_response_stream(
        self,
        model_id: str,
        body: str | dict[str, Any] | bytes,
        content_type: str | None = None,
        accept: str | None = None,
        **kwargs,
    ) -> dict[str, Any]:
        """Simulate invoking a foundation model with streaming response."""

        # Mock streaming response generator
        class MockStreamingBody:
            def __init__(self, chunks):
                self.chunks = chunks
                self.index = 0

            def get_chunk(self):
                if self.index >= len(self.chunks):
                    return None
                chunk = self.chunks[self.index]
                self.index += 1
                return {"chunk": {"bytes": json.dumps(chunk).encode()}}

        # Create streaming chunks based on model
        if "anthropic.claude" in model_id:
            chunks = [
                {"completion": "This "},
                {"completion": "is "},
                {"completion": "a "},
                {"completion": "simulated "},
                {"completion": "streaming "},
                {"completion": "response "},
                {"completion": "from "},
                {"completion": "Claude "},
                {"completion": "for "},
                {"completion": "psychiatric "},
                {"completion": "assessment."},
            ]
        else:
            chunks = [
                {"output": "This is a simulated streaming response for psychiatric assessment."}
            ]

        return {
            "body": MockStreamingBody(chunks),
            "contentType": "application/json",
            "ResponseMetadata": {"HTTPStatusCode": 200},
        }


class InMemoryAWSSessionService(AWSSessionServiceInterface):
    """In-memory AWS session service implementation for testing."""

    def __init__(self):
        """Initialize with mock region."""
        self._region_name = "us-east-1"  # Default test region

    def get_caller_identity(self) -> dict[str, Any]:
        """Simulate getting AWS identity information."""
        return {
            "UserId": "TESTUSER123",
            "Account": "123456789012",
            "Arn": "arn:aws:iam::123456789012:user/test-user",
        }

    def get_available_regions(self, service_name: str) -> list[str]:
        """Simulate getting available regions for a service."""
        return ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"]

    def get_current_region_name(self) -> str:
        """Get the current AWS region name."""
        return self._region_name


class InMemoryAWSServiceFactory(AWSServiceFactory):
    """Factory for creating in-memory AWS service implementations for testing."""

    def __init__(self):
        """Initialize shared service instances."""
        self._dynamodb_service = InMemoryDynamoDBService()
        self._s3_service = InMemoryS3Service()
        self._sagemaker_service = InMemorySageMakerService()
        self._sagemaker_runtime_service = InMemorySageMakerRuntimeService()
        self._comprehend_medical_service = InMemoryComprehendMedicalService()
        self._bedrock_service = InMemoryBedrockService()
        self._bedrock_runtime_service = InMemoryBedrockRuntimeService()
        self._session_service = InMemoryAWSSessionService()

    def get_dynamodb_service(self) -> DynamoDBServiceInterface:
        """Get an in-memory DynamoDB service implementation."""
        return self._dynamodb_service

    def get_s3_service(self) -> S3ServiceInterface:
        """Get an in-memory S3 service implementation."""
        return self._s3_service

    def get_sagemaker_service(self) -> SageMakerServiceInterface:
        """Get an in-memory SageMaker service implementation."""
        return self._sagemaker_service

    def get_sagemaker_runtime_service(self) -> SageMakerRuntimeServiceInterface:
        """Get an in-memory SageMaker runtime service implementation."""
        return self._sagemaker_runtime_service

    def get_comprehend_medical_service(self) -> ComprehendMedicalServiceInterface:
        """Get an in-memory Comprehend Medical service implementation."""
        return self._comprehend_medical_service

    def get_bedrock_service(self) -> BedrockServiceInterface:
        """Get an in-memory Bedrock service implementation."""
        return self._bedrock_service

    def get_bedrock_runtime_service(self) -> BedrockRuntimeServiceInterface:
        """Get an in-memory Bedrock runtime service implementation."""
        return self._bedrock_runtime_service

    def get_session_service(self) -> AWSSessionServiceInterface:
        """Get an in-memory AWS session service implementation."""
        return self._session_service
