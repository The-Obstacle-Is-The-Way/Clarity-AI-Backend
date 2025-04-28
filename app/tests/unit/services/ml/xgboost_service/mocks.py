"""
Consolidated mock implementations for AWS XGBoost service testing.

This module provides all mock implementations needed for proper testing of
the AWS XGBoost service with a clean separation of concerns and proper
interface adherence.
"""

import json
from typing import Dict, Any, List, Optional, Union
from datetime import datetime
import asyncio

from app.core.interfaces.aws_service_interface import (
    AWSServiceFactory,
    DynamoDBServiceInterface,
    S3ServiceInterface,
    SageMakerServiceInterface,
    SageMakerRuntimeServiceInterface,
    ComprehendMedicalServiceInterface,
    BedrockServiceInterface,
    BedrockRuntimeServiceInterface,
    AWSSessionServiceInterface
)


class MockDynamoDBService(DynamoDBServiceInterface):
    """Mock DynamoDB service for testing."""
    
    def __init__(self):
        """Initialize with empty tables."""
        self.tables = {}
    
    def scan_table(self, table_name: str) -> Dict[str, List[Dict[str, Any]]]:
        """Scan a DynamoDB table and return all items."""
        if table_name not in self.tables:
            self.tables[table_name] = []
        return {"Items": self.tables[table_name]}
    
    def put_item(self, table_name: str, item: Dict[str, Any]) -> Dict[str, Any]:
        """Add an item to a DynamoDB table."""
        if table_name not in self.tables:
            self.tables[table_name] = []
        self.tables[table_name].append(item)
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}
    
    def get_item(self, table_name: str, key: Dict[str, Any]) -> Dict[str, Any]:
        """Get an item from a DynamoDB table."""
        if table_name not in self.tables:
            return {"ResponseMetadata": {"HTTPStatusCode": 200}}
            
        for item in self.tables[table_name]:
            match = True
            for k, v in key.items():
                if k not in item or item[k] != v:
                    match = False
                    break
            if match:
                return {"Item": item, "ResponseMetadata": {"HTTPStatusCode": 200}}
                
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}
    
    def query(self, table_name: str, key_condition_expression: str, 
                  expression_attribute_values: Dict[str, Any]) -> Dict[str, Any]:
        """Query a DynamoDB table with a key condition expression."""
        if table_name not in self.tables:
            return {"Items": [], "Count": 0, "ResponseMetadata": {"HTTPStatusCode": 200}}
        
        # Simplified mock implementation - just return all items
        # In a real implementation, we would parse the condition expression
        return {
            "Items": self.tables[table_name],
            "Count": len(self.tables[table_name]), 
            "ResponseMetadata": {"HTTPStatusCode": 200}
        }
    
    def update_item(self, table_name: str, key: Dict[str, Any], 
                   update_expression: str, 
                   expression_attribute_values: Dict[str, Any]) -> Dict[str, Any]:
        """Update an item in a DynamoDB table."""
        if table_name not in self.tables:
            return {"ResponseMetadata": {"HTTPStatusCode": 200}}
            
        for i, item in enumerate(self.tables[table_name]):
            match = True
            for k, v in key.items():
                if k not in item or item[k] != v:
                    match = False
                    break
            if match:
                # Simplified implementation - just add/update values
                # In a real implementation, we would parse the update expression
                for k, v in expression_attribute_values.items():
                    # Remove the colon from the attribute name
                    attr_name = k[1:]
                    self.tables[table_name][i][attr_name] = v
                return {"ResponseMetadata": {"HTTPStatusCode": 200}}
                
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}


class MockS3Service(S3ServiceInterface):
    """Mock S3 service for testing."""
    
    def __init__(self, bucket_exists=True):
        """Initialize with empty objects dictionary."""
        self.bucket_exists = bucket_exists
        self.objects = {}
    
    def check_bucket_exists(self, bucket_name: str) -> bool:
        """Check if a bucket exists in S3."""
        return self.bucket_exists
    
    def put_object(self, bucket_name: str, key: str, body: bytes) -> Dict[str, Any]:
        """Put an object in S3."""
        if bucket_name not in self.objects:
            self.objects[bucket_name] = {}
        self.objects[bucket_name][key] = body
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}
    
    def get_object(self, bucket_name: str, key: str) -> Dict[str, Any]:
        """Get an object from S3."""
        if (bucket_name not in self.objects or 
            key not in self.objects[bucket_name]):
            raise Exception("NoSuchKey")
            
        return {
            "Body": MockS3ObjectBody(self.objects[bucket_name][key]),
            "ResponseMetadata": {"HTTPStatusCode": 200}
        }
    
    def list_objects(self, bucket_name: str, prefix: Optional[str] = None) -> Dict[str, Any]:
        """List objects in an S3 bucket with optional prefix."""
        if bucket_name not in self.objects:
            return {"Contents": [], "ResponseMetadata": {"HTTPStatusCode": 200}}
            
        contents = []
        for key in self.objects[bucket_name]:
            if prefix is None or key.startswith(prefix):
                contents.append({
                    "Key": key,
                    "LastModified": datetime.now(),
                    "Size": len(self.objects[bucket_name][key]),
                    "ETag": "mock-etag"
                })
                
        return {"Contents": contents, "ResponseMetadata": {"HTTPStatusCode": 200}}
    
    def download_file(self, bucket_name: str, key: str, filename: str) -> None:
        """Download a file from S3 to local filesystem."""
        if (bucket_name not in self.objects or 
            key not in self.objects[bucket_name]):
            raise Exception("NoSuchKey")
            
        # In a real implementation, this would write to the filesystem
        # For testing, we'll just return without doing anything
        pass


class MockS3ObjectBody:
    """Mock S3 object body for testing."""
    
    def __init__(self, content: bytes):
        """Initialize with content bytes."""
        self.content = content
    
    def read(self) -> bytes:
        """Read the content bytes."""
        return self.content


class MockSageMakerService(SageMakerServiceInterface):
    """Mock SageMaker service for testing."""
    
    def __init__(self, endpoints=None):
        """Initialize with default or provided endpoints list."""
        self.endpoints = endpoints or []
        # Setup default endpoints for testing
        if not self.endpoints:
            self.endpoints = [
                {
                    "EndpointName": "test-prefix-risk-relapse-endpoint",
                    "EndpointStatus": "InService",
                    "CreationTime": datetime.now(),
                    "LastModifiedTime": datetime.now(),
                    "EndpointArn": "arn:aws:sagemaker:us-east-1:123456789012:endpoint/test-prefix-risk-relapse-endpoint"
                },
                {
                    "EndpointName": "test-prefix-risk-suicide-endpoint",
                    "EndpointStatus": "InService",
                    "CreationTime": datetime.now(),
                    "LastModifiedTime": datetime.now(),
                    "EndpointArn": "arn:aws:sagemaker:us-east-1:123456789012:endpoint/test-prefix-risk-suicide-endpoint"
                },
                {
                    "EndpointName": "test-prefix-feature-importance-endpoint",
                    "EndpointStatus": "InService",
                    "CreationTime": datetime.now(),
                    "LastModifiedTime": datetime.now(),
                    "EndpointArn": "arn:aws:sagemaker:us-east-1:123456789012:endpoint/test-prefix-feature-importance-endpoint"
                }
            ]
    
    def list_endpoints(self) -> Dict[str, List[Dict[str, Any]]]:
        """List all SageMaker endpoints."""
        return {"Endpoints": self.endpoints}
    
    def describe_endpoint(self, endpoint_name: str) -> Dict[str, Any]:
        """Describe a specific SageMaker endpoint."""
        for endpoint in self.endpoints:
            if endpoint["EndpointName"] == endpoint_name:
                return endpoint
                
        raise Exception(f"ResourceNotFound: Endpoint {endpoint_name} does not exist")


class MockSageMakerRuntimeService(SageMakerRuntimeServiceInterface):
    """Mock SageMaker runtime service for testing."""
    
    def __init__(self, response_payload=None):
        """Initialize with default or provided response payload."""
        self.response_payload = response_payload or {
            "prediction": {
                "score": 0.85,
                "risk_level": "high"
            },
            "prediction_id": "pred-123",
            "timestamp": datetime.now().isoformat()
        }
        self.exception_to_raise = None
    
    async def invoke_endpoint(self, EndpointName: str, ContentType: str, 
                      Body: bytes, Accept: Optional[str] = None) -> Dict[str, Any]:
        """Async mock invoke endpoint implementation."""
        # If we're configured to raise an exception, do so
        if self.exception_to_raise:
            raise self.exception_to_raise
            
        # Parse the request payload for testing
        try:
            request_payload = json.loads(Body.decode('utf-8'))
        except Exception:
            request_payload = {"error": "Failed to parse request payload"}
        
        # Create a properly structured response body that matches AWS SageMaker response format
        response_body = MockResponseBody(self.response_payload)
            
        # Return a properly structured async-compatible response that exactly matches AWS structure
        return {
            "Body": response_body,
            "ContentType": "application/json", 
            "ResponseMetadata": {"HTTPStatusCode": 200, "RequestId": f"req-{uuid.uuid4()}"},
            "StatusCode": 200
        }


class MockResponseBody:
    """Mock response body for testing."""
    
    def __init__(self, content: Any):
        """Initialize with content."""
        self.content = content
    
    async def read(self) -> bytes:
        """Async read the content as JSON bytes."""
        # Simulate slight network delay for realism
        await asyncio.sleep(0.001)
        return json.dumps(self.content).encode("utf-8")


class MockComprehendMedicalService(ComprehendMedicalServiceInterface):
    """Mock Comprehend Medical service for testing."""
    
    def detect_entities(self, text: str) -> Dict[str, Any]:
        """Detect medical entities in text."""
        entities = []
        # Add PHI detection if text contains typical PHI patterns
        if any(term in text.lower() for term in ["john", "doe", "ssn", "address"]):
            entities.append({
                "Category": "PROTECTED_HEALTH_INFORMATION",
                "Type": "NAME",
                "Text": "John Doe",
                "Score": 0.99,
                "BeginOffset": 0,
                "EndOffset": 8
            })
            
        return {"Entities": entities}
    
    def detect_phi(self, text: str) -> Dict[str, Any]:
        """Detect PHI in text."""
        entities = []
        # Add PHI detection if text contains typical PHI patterns
        if any(term in text.lower() for term in ["john", "doe", "ssn", "address"]):
            entities.append({
                "Type": "NAME",
                "Text": "John Doe",
                "Score": 0.99,
                "BeginOffset": 0,
                "EndOffset": 8
            })
            
        return {"Entities": entities}
    
    def infer_icd10_cm(self, text: str) -> Dict[str, Any]:
        """Infer ICD-10-CM codes from medical text."""
        return {
            "Entities": [{
                "Category": "MEDICAL_CONDITION",
                "Text": "depression",
                "Score": 0.97,
                "BeginOffset": 0,
                "EndOffset": 10,
                "ICD10CMConcepts": [{
                    "Code": "F32.9",
                    "Description": "Major depressive disorder, single episode, unspecified",
                    "Score": 0.95
                }]
            }]
        }


class MockBedrockService(BedrockServiceInterface):
    """Mock Bedrock service for testing."""
    
    def list_foundation_models(self) -> Dict[str, Any]:
        """List available foundation models."""
        return {
            "modelSummaries": [{
                "modelId": "anthropic.claude-v2",
                "modelName": "Claude 2",
                "providerName": "Anthropic"
            }]
        }
    
    def invoke_model(self, model_id: str, body: Dict[str, Any], **kwargs) -> Dict[str, Any]:
        """Invoke a foundation model."""
        return {
            "body": json.dumps({
                "generated_text": "Mock LLM response for testing purposes."
            }).encode("utf-8"),
            "contentType": "application/json"
        }


class MockBedrockRuntimeService(BedrockRuntimeServiceInterface):
    """Mock Bedrock Runtime service for testing."""
    
    def invoke_model(self, model_id: str, body: Union[str, Dict[str, Any], bytes],
                   content_type: Optional[str] = None, 
                   accept: Optional[str] = None, **kwargs) -> Dict[str, Any]:
        """Invoke a foundation model."""
        return {
            "body": MockResponseBody({
                "completion": "Mock LLM response for testing purposes."
            }),
            "contentType": "application/json"
        }
    
    def invoke_model_with_response_stream(self, model_id: str, 
                                        body: Union[str, Dict[str, Any], bytes],
                                        content_type: Optional[str] = None, 
                                        accept: Optional[str] = None, **kwargs) -> Dict[str, Any]:
        """Invoke a foundation model with streaming response."""
        return {
            "stream": MockStreamIterator([
                {"chunk": {"bytes": json.dumps({"completion": "Mock"}).encode("utf-8")}},
                {"chunk": {"bytes": json.dumps({"completion": " LLM"}).encode("utf-8")}},
                {"chunk": {"bytes": json.dumps({"completion": " response"}).encode("utf-8")}}
            ])
        }


class MockStreamIterator:
    """Mock stream iterator for testing streaming responses."""
    
    def __init__(self, chunks):
        """Initialize with chunks."""
        self.chunks = chunks
        self.index = 0
    
    def __iter__(self):
        """Return self as iterator."""
        return self
    
    def __next__(self):
        """Return next chunk or raise StopIteration."""
        if self.index < len(self.chunks):
            chunk = self.chunks[self.index]
            self.index += 1
            return chunk
        raise StopIteration


class MockAWSSessionService(AWSSessionServiceInterface):
    """Mock AWS Session service for testing."""
    
    def get_caller_identity(self) -> Dict[str, str]:
        """Get the AWS identity information for the caller."""
        return {
            "UserId": "AIDAXXXXXXXXXXXXXXXX",
            "Account": "123456789012",
            "Arn": "arn:aws:iam::123456789012:user/test-user"
        }
    
    def get_available_regions(self, service_name: str) -> List[str]:
        """Get available regions for a specific AWS service."""
        return ["us-east-1", "us-west-2", "eu-west-1"]
    
    def get_current_region_name(self) -> str:
        """Get the current AWS region name."""
        return "us-east-1"


class MockAWSServiceFactory(AWSServiceFactory):
    """Mock AWS service factory for testing."""
    
    def __init__(
            self,
            dynamodb_service=None,
            s3_service=None,
            sagemaker_service=None,
            sagemaker_runtime_service=None,
            comprehend_medical_service=None,
            bedrock_service=None,
            bedrock_runtime_service=None,
            session_service=None,
            # Feature flags for testing initialization validation
            raise_on_missing_region=True,
            raise_on_missing_endpoint=True,
            validate_resources=True
        ):
        """Initialize with optional service implementations."""
        self.dynamodb_service = dynamodb_service or MockDynamoDBService()
        self.s3_service = s3_service or MockS3Service()
        self.sagemaker_service = sagemaker_service or MockSageMakerService()
        self.sagemaker_runtime_service = sagemaker_runtime_service or MockSageMakerRuntimeService()
        self.comprehend_medical_service = comprehend_medical_service or MockComprehendMedicalService()
        self.bedrock_service = bedrock_service or MockBedrockService()
        self.bedrock_runtime_service = bedrock_runtime_service or MockBedrockRuntimeService()
        self.session_service = session_service or MockAWSSessionService()
        
        # Testing flags
        self.raise_on_missing_region = raise_on_missing_region
        self.raise_on_missing_endpoint = raise_on_missing_endpoint
        self.validate_resources = validate_resources
    
    def get_dynamodb_service(self) -> DynamoDBServiceInterface:
        """Get the DynamoDB service implementation."""
        return self.dynamodb_service
    
    def get_s3_service(self) -> S3ServiceInterface:
        """Get the S3 service implementation."""
        return self.s3_service
    
    def get_sagemaker_service(self) -> SageMakerServiceInterface:
        """Get the SageMaker service implementation."""
        return self.sagemaker_service
    
    def get_sagemaker_runtime_service(self) -> SageMakerRuntimeServiceInterface:
        """Get the SageMaker runtime service implementation."""
        return self.sagemaker_runtime_service
    
    def get_comprehend_medical_service(self) -> ComprehendMedicalServiceInterface:
        """Get the Comprehend Medical service implementation."""
        return self.comprehend_medical_service
    
    def get_bedrock_service(self) -> BedrockServiceInterface:
        """Get the Bedrock service implementation."""
        return self.bedrock_service
    
    def get_bedrock_runtime_service(self) -> BedrockRuntimeServiceInterface:
        """Get the Bedrock runtime service implementation."""
        return self.bedrock_runtime_service
    
    def get_session_service(self) -> AWSSessionServiceInterface:
        """Get the AWS session service implementation."""
        return self.session_service


class AsyncMock:
    """Helper class to run async fixture in sync context."""
    
    def __init__(self, coroutine):
        """Initialize with coroutine."""
        self.coroutine = coroutine
    
    def __call__(self, *args, **kwargs):
        """Run the coroutine synchronously."""
        return asyncio.run(self.coroutine(*args, **kwargs))
