"""
AWS SageMaker integration module.

This module provides infrastructure-level abstractions for interacting with
AWS SageMaker services following clean architecture principles.
"""
import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

import boto3
from botocore.exceptions import ClientError

from app.core.domain.prediction_result import PredictionResult
from app.core.services.ml.xgboost.exceptions import (
    ModelInvocationError,
    ModelTimeoutError,
    PredictionError,
    SerializationError,
    ServiceConnectionError,
)


logger = logging.getLogger(__name__)


class SageMakerEndpoint:
    """
    Infrastructure adapter for SageMaker endpoints.
    
    Following clean architecture principles, this class serves as an adapter
    in the infrastructure layer that encapsulates the details of SageMaker 
    endpoint invocation, allowing the application core to remain decoupled
    from AWS implementation details.
    """
    
    def __init__(
        self,
        endpoint_name: str,
        client: Optional[Any] = None,
        content_type: str = "application/json",
        accept_type: str = "application/json",
        region_name: Optional[str] = None,
    ):
        """
        Initialize a SageMaker endpoint adapter.
        
        Args:
            endpoint_name: Name of the SageMaker endpoint
            client: Boto3 SageMaker runtime client (optional, created if not provided)
            content_type: Content type for requests (default: application/json)
            accept_type: Accept type for responses (default: application/json)
            region_name: AWS region name (optional, uses boto3 default if not provided)
        """
        self.endpoint_name = endpoint_name
        self.content_type = content_type
        self.accept_type = accept_type
        self._client = client or boto3.client("sagemaker-runtime", region_name=region_name)
        
    def invoke(self, input_data: Union[Dict[str, Any], List[Any], str, bytes]) -> Dict[str, Any]:
        """
        Invoke the SageMaker endpoint with input data.
        
        Args:
            input_data: Input data for the model (dict, list, string, or bytes)
            
        Returns:
            Dictionary containing the model response
            
        Raises:
            SerializationError: If data serialization fails
            ServiceConnectionError: If there's a connection issue with AWS
            ModelInvocationError: If the model invocation fails
            ModelTimeoutError: If the model invocation times out
            PredictionError: If there's an error in the prediction
        """
        try:
            # Serialize input data if necessary
            body = self._serialize_input(input_data)
            
            # Invoke the endpoint
            response = self._client.invoke_endpoint(
                EndpointName=self.endpoint_name,
                ContentType=self.content_type,
                Accept=self.accept_type,
                Body=body
            )
            
            # Parse and return the response
            return self._parse_response(response)
            
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            
            if error_code == "ModelError":
                raise ModelInvocationError(
                    f"Model error during invocation of endpoint {self.endpoint_name}",
                    endpoint_name=self.endpoint_name,
                    cause=str(e)
                )
            elif error_code == "ServiceUnavailable":
                raise ServiceConnectionError(
                    f"SageMaker service unavailable for endpoint {self.endpoint_name}",
                    service_name="SageMaker",
                    cause=str(e)
                )
            elif error_code == "ValidationError":
                raise ModelInvocationError(
                    f"Invalid input for endpoint {self.endpoint_name}",
                    endpoint_name=self.endpoint_name,
                    cause=str(e)
                )
            elif error_code == "RequestTimeout":
                raise ModelTimeoutError(
                    f"Request timeout for endpoint {self.endpoint_name}",
                    endpoint_name=self.endpoint_name,
                    cause=str(e)
                )
            else:
                raise ServiceConnectionError(
                    f"AWS service error for endpoint {self.endpoint_name}: {error_code}",
                    service_name="SageMaker",
                    cause=str(e)
                )
                
        except Exception as e:
            raise PredictionError(
                f"Unexpected error during prediction with endpoint {self.endpoint_name}",
                cause=str(e)
            )
            
    def _serialize_input(self, input_data: Union[Dict[str, Any], List[Any], str, bytes]) -> bytes:
        """
        Serialize input data to the appropriate format.
        
        Args:
            input_data: Input data to serialize
            
        Returns:
            Serialized data as bytes
            
        Raises:
            SerializationError: If serialization fails
        """
        try:
            if isinstance(input_data, bytes):
                return input_data
            elif isinstance(input_data, str):
                return input_data.encode("utf-8")
            elif isinstance(input_data, (dict, list)):
                return json.dumps(input_data).encode("utf-8")
            else:
                raise SerializationError(
                    f"Unsupported input data type: {type(input_data).__name__}",
                    data_type=type(input_data).__name__,
                    format_type=self.content_type
                )
        except (TypeError, ValueError) as e:
            raise SerializationError(
                f"Failed to serialize input data: {str(e)}",
                data_type=type(input_data).__name__,
                format_type=self.content_type,
                cause=str(e)
            )
            
    def _parse_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse the SageMaker endpoint response.
        
        Args:
            response: Raw response from SageMaker
            
        Returns:
            Parsed response as a dictionary
            
        Raises:
            SerializationError: If response parsing fails
        """
        try:
            if "Body" not in response:
                raise SerializationError(
                    "Missing Body in SageMaker response",
                    data_type="response",
                    format_type=response.get("ContentType", "unknown")
                )
                
            # Get the response body as a stream
            body = response["Body"].read().decode("utf-8")
            
            # Parse the JSON response
            if not body:
                return {}
                
            return json.loads(body)
            
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise SerializationError(
                f"Failed to parse response: {str(e)}",
                data_type="response",
                format_type=response.get("ContentType", "unknown"),
                cause=str(e)
            )


class SageMakerFactory:
    """
    Factory for creating SageMaker-related clients and resources.
    
    This class follows the Factory design pattern, providing a way to create
    various AWS client objects while keeping the creation logic in one place.
    """
    
    def __init__(
        self,
        region_name: Optional[str] = None,
        aws_access_key_id: Optional[str] = None,
        aws_secret_access_key: Optional[str] = None,
        aws_session_token: Optional[str] = None,
    ):
        """
        Initialize a new SageMaker factory.
        
        Args:
            region_name: AWS region name (optional)
            aws_access_key_id: AWS access key ID (optional)
            aws_secret_access_key: AWS secret access key (optional)
            aws_session_token: AWS session token (optional)
        """
        self.region_name = region_name
        self.aws_access_key_id = aws_access_key_id
        self.aws_secret_access_key = aws_secret_access_key
        self.aws_session_token = aws_session_token
        
    def create_sagemaker_runtime_client(self) -> Any:
        """
        Create a SageMaker runtime client.
        
        Returns:
            Boto3 SageMaker runtime client
        """
        return boto3.client(
            "sagemaker-runtime",
            region_name=self.region_name,
            aws_access_key_id=self.aws_access_key_id,
            aws_secret_access_key=self.aws_secret_access_key,
            aws_session_token=self.aws_session_token,
        )
        
    def create_sagemaker_client(self) -> Any:
        """
        Create a SageMaker client.
        
        Returns:
            Boto3 SageMaker client
        """
        return boto3.client(
            "sagemaker",
            region_name=self.region_name,
            aws_access_key_id=self.aws_access_key_id,
            aws_secret_access_key=self.aws_secret_access_key,
            aws_session_token=self.aws_session_token,
        )
        
    def create_endpoint(self, endpoint_name: str) -> SageMakerEndpoint:
        """
        Create a SageMaker endpoint adapter.
        
        Args:
            endpoint_name: Name of the SageMaker endpoint
            
        Returns:
            SageMakerEndpoint adapter
        """
        return SageMakerEndpoint(
            endpoint_name=endpoint_name,
            client=self.create_sagemaker_runtime_client(),
            region_name=self.region_name,
        )
